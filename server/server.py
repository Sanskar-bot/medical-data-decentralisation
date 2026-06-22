#!/usr/bin/env python3
"""
server.py

Decentralised medical-data server (development).

Storage layer migrated from JSON files to PostgreSQL.
All 25 security fixes (C1-C4, H1-H7, M1-M8, L1-L6) are preserved.
"""

# -----------------------
# Standard / 3rd-party imports
# -----------------------
import os
import json
import uuid
import base64
import time
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()  # load .env before any os.environ.get calls

from flask import Flask, request, jsonify, g
from cryptography.fernet import Fernet

# -----------------------
# Server base directories (paths used by handlers)
# -----------------------
SERVER_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# PATIENTS_DIR: still used for encrypted_data.json file uploads & migration bridge
PATIENTS_DIR = os.path.join(SERVER_BASE_DIR, "Patients")
os.makedirs(PATIENTS_DIR, exist_ok=True)

# DOCTORS_DIR: kept for any PEM file fallback
DOCTORS_DIR = os.path.join(SERVER_BASE_DIR, "Doctors")
os.makedirs(DOCTORS_DIR, exist_ok=True)

# Legacy user folder (kept for compatibility)
USER_FOLDER = os.path.join(SERVER_BASE_DIR, "users")
os.makedirs(USER_FOLDER, exist_ok=True)

DATA_DIR = PATIENTS_DIR

UPLOADS_DIR = os.path.join(SERVER_BASE_DIR, "uploads")
os.makedirs(os.path.join(UPLOADS_DIR, "reports"),  exist_ok=True)
os.makedirs(os.path.join(UPLOADS_DIR, "images"),   exist_ok=True)
os.makedirs(os.path.join(UPLOADS_DIR, "profiles"), exist_ok=True)

NOTE_IMAGES_DIR = os.path.join(SERVER_BASE_DIR, "note_images")
os.makedirs(NOTE_IMAGES_DIR, exist_ok=True)

# -----------------------
# Simple server-side cipher (Fernet) — used only if you need server-side symmetric encryption
# -----------------------
KEY_FILE = os.path.join(SERVER_BASE_DIR, "server_key.key")
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()
fernet = Fernet(key)

# -----------------------
# Flask app
# -----------------------
app = Flask(__name__)

# [H6] Global upload size limit: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# -----------------------
# [C1] API-key authentication
# -----------------------
import secrets as _secrets

_API_KEY_FILE = os.path.join(SERVER_BASE_DIR, "api_key.txt")
_FLASK_ENV = os.environ.get("FLASK_ENV", "production")

_SERVER_API_KEY = os.environ.get("SERVER_API_KEY", "")
if not _SERVER_API_KEY:
    if os.path.exists(_API_KEY_FILE):
        if _FLASK_ENV != "development":
            raise RuntimeError(
                "api_key.txt must not exist in production. "
                "Set SERVER_API_KEY env var instead."
            )
        with open(_API_KEY_FILE, "r") as _f:
            _SERVER_API_KEY = _f.read().strip()
        print("[WARN] Reading API key from api_key.txt (dev mode). "
              "Set SERVER_API_KEY env var in production.")
    else:
        _SERVER_API_KEY = _secrets.token_hex(32)
        with open(_API_KEY_FILE, "w") as _f:
            _f.write(_SERVER_API_KEY)
        print("\n[AUTH] NEW API key saved to " + _API_KEY_FILE)
        print("[AUTH] Share this key with authorised clients: " + _SERVER_API_KEY + "\n")


def _require_api_key():
    """Return a 401 response if the request has no valid API key, else None."""
    if request.headers.get("X-API-Key", "") != _SERVER_API_KEY:
        return jsonify({"error": "unauthorized",
                        "hint": "Add header  X-API-Key: <your key>"}), 401
    return None

# -----------------------
# Utility helpers (kept for non-DB file ops)
# -----------------------
def load_json(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Corrupted JSON detected at {file_path}. Reinitializing.")
            return {}
    else:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump({}, f)
        return {}

def save_json(file_path, data):
    """[M4] Save JSON atomically: write to .tmp, fsync, then os.replace()."""
    tmp = file_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, file_path)
    except Exception as e:
        print(f"[] Failed to save {file_path}: {e}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _save_json(path, obj):
    """Small wrapper used to write JSON with stable options."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)

# -----------------------
# DB init
# -----------------------
from db import init_db, db_cursor
try:
    init_db()
    print("[DB] PostgreSQL connected ✓")
except RuntimeError as _db_err:
    print(f"[DB] WARNING: {_db_err}")
    print("[DB] Server will start but DB operations will fail until DATABASE_URL is set.")

# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Users
# ════════════════════════════════════════════════════════════════════════════
import threading
import hashlib
import re
from functools import wraps
from collections import defaultdict

_users_db_lock = threading.Lock()


def _db_get_user_by_email(email: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        return dict(row) if row else None


def _db_get_user_by_username(username: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM users WHERE lower(username) = lower(%s)", (username,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def _db_get_all_users() -> dict:
    """Return {email: user_dict} — used by EMR admin endpoints."""
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()
        return {r["email"]: dict(r) for r in rows}


def _db_upsert_user(email: str, user_data: dict) -> str:
    """Insert or update a user. Returns user id."""
    created_at = user_data.get("created_at")
    if isinstance(created_at, str) and created_at:
        try:
            created_at = datetime.fromisoformat(created_at)
        except ValueError:
            created_at = datetime.now(timezone.utc)
    elif not created_at:
        created_at = datetime.now(timezone.utc)

    last_login = user_data.get("last_login")
    if isinstance(last_login, str) and last_login:
        try:
            last_login = datetime.fromisoformat(last_login)
        except ValueError:
            last_login = None
    elif not last_login:
        last_login = None

    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO users (
                id, email, username, name, phone, role,
                password_hash, public_key, encrypted_private_key,
                profile_code, doctor_code, profile_photo_url,
                locked, failed_attempts, created_at, last_login
            ) VALUES (
                %(id)s, %(email)s, %(username)s, %(name)s,
                %(phone)s, %(role)s, %(password_hash)s,
                %(public_key)s, %(encrypted_private_key)s,
                %(profile_code)s, %(doctor_code)s,
                %(profile_photo_url)s, %(locked)s,
                %(failed_attempts)s, %(created_at)s, %(last_login)s
            )
            ON CONFLICT (email) DO UPDATE SET
                username              = EXCLUDED.username,
                name                  = EXCLUDED.name,
                phone                 = EXCLUDED.phone,
                role                  = EXCLUDED.role,
                password_hash         = EXCLUDED.password_hash,
                public_key            = EXCLUDED.public_key,
                encrypted_private_key = EXCLUDED.encrypted_private_key,
                profile_code          = EXCLUDED.profile_code,
                doctor_code           = EXCLUDED.doctor_code,
                profile_photo_url     = EXCLUDED.profile_photo_url,
                locked                = EXCLUDED.locked,
                failed_attempts       = EXCLUDED.failed_attempts,
                last_login            = EXCLUDED.last_login
            RETURNING id
        """, {
            "id": user_data.get("id", str(uuid.uuid4())),
            "email": email,
            "username": user_data.get("username", ""),
            "name": user_data.get("name", ""),
            "phone": user_data.get("phone", ""),
            "role": user_data.get("role", "patient"),
            "password_hash": user_data.get("password_hash", ""),
            "public_key": user_data.get("public_key", ""),
            "encrypted_private_key": user_data.get("encrypted_private_key", ""),
            "profile_code": user_data.get("profile_code", ""),
            "doctor_code": user_data.get("doctor_code", ""),
            "profile_photo_url": user_data.get("profile_photo_url", ""),
            "locked": user_data.get("locked", False),
            "failed_attempts": user_data.get("failed_attempts", 0),
            "created_at": created_at,
            "last_login": last_login,
        })
        return cur.fetchone()["id"]


def _db_update_user_field(email: str, field: str, value):
    """Update a single whitelisted field on a user row."""
    ALLOWED_FIELDS = {
        "password_hash", "locked", "failed_attempts",
        "last_login", "profile_photo_url", "public_key",
        "encrypted_private_key", "role", "doctor_code", "profile_code",
        "username", "name", "phone",
    }
    if field not in ALLOWED_FIELDS:
        raise ValueError(f"Field '{field}' not in update whitelist")
    with db_cursor() as cur:
        cur.execute(
            f"UPDATE users SET {field} = %s WHERE email = %s",
            (value, email)
        )


def _db_save_users_bulk(users: dict):
    """Bulk upsert a {email: user_dict} dict — used by admin_change_role."""
    for email, u in users.items():
        _db_upsert_user(email, u)


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Login history
# ════════════════════════════════════════════════════════════════════════════

_login_hist_lock = threading.Lock()


def _append_login_history(entry: dict):
    """Thread-safe append to login_history table."""
    ts = entry.get("ts")
    if isinstance(ts, str) and ts:
        try:
            ts = datetime.fromisoformat(ts)
        except ValueError:
            ts = datetime.now(timezone.utc)
    elif not ts:
        ts = datetime.now(timezone.utc)

    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO login_history (email, ts, ip)
            VALUES (%s, %s, %s)
        """, (entry.get("email"), ts, entry.get("ip")))


# ════════════════════════════════════════════════════════════════════════════
# [H4] DB-backed Rate Limiter
# ════════════════════════════════════════════════════════════════════════════

_rate_lock = threading.Lock()


def _rate_check_and_record(ip: str, endpoint: str, max_calls: int, window: int) -> bool:
    """
    Returns True if request is allowed, False if rate limited.
    Records the hit atomically. window is in seconds.
    """
    with _rate_lock:
        with db_cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) AS cnt FROM rate_limits
                WHERE ip = %s
                  AND endpoint = %s
                  AND hit_at > now() - (%s || ' seconds')::interval
            """, (ip, endpoint, str(window)))
            count = cur.fetchone()["cnt"]
            if count >= max_calls:
                return False
            cur.execute("""
                INSERT INTO rate_limits (ip, endpoint, hit_at)
                VALUES (%s, %s, now())
            """, (ip, endpoint))
            return True


def rate_limited(max_calls=10, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*a, **kw):
            ip = request.remote_addr or "unknown"
            endpoint = request.endpoint or f.__name__
            if not _rate_check_and_record(ip, endpoint, max_calls, window):
                return jsonify({
                    "error": "rate_limited",
                    "retry_after": window
                }), 429
            return f(*a, **kw)
        return wrapper
    return decorator


# ════════════════════════════════════════════════════════════════════════════
# Audit log
# ════════════════════════════════════════════════════════════════════════════

def audit(action, actor="", target="", detail=""):
    try:
        ip = request.remote_addr if request else ""
    except RuntimeError:
        ip = ""
    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (action, actor, target, detail, ip)
                VALUES (%s, %s, %s, %s, %s)
            """, (action, actor, target, detail, ip))
    except Exception as _ae:
        print(f"[Audit] DB write failed: {_ae}")


# ════════════════════════════════════════════════════════════════════════════
# [H5] DB-backed OTP store
# ════════════════════════════════════════════════════════════════════════════

_otp_lock = threading.Lock()

import secrets as _secrets_otp, string


def _gen_otp():
    return "".join(_secrets_otp.choice(string.digits) for _ in range(6))


def _otp_get(email: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT otp,
                   EXTRACT(EPOCH FROM expires_at)::FLOAT AS expires,
                   attempts
            FROM otp_store
            WHERE email = %s AND expires_at > now()
        """, (email,))
        row = cur.fetchone()
        if not row:
            return None
        return {"otp": row["otp"], "expires": float(row["expires"]), "attempts": row["attempts"]}


def _otp_set(email: str, otp: str, expires: float, attempts: int = 0):
    exp_dt = datetime.fromtimestamp(expires, tz=timezone.utc)
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO otp_store (email, otp, expires_at, attempts)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (email) DO UPDATE SET
                otp        = EXCLUDED.otp,
                expires_at = EXCLUDED.expires_at,
                attempts   = EXCLUDED.attempts
        """, (email, otp, exp_dt, attempts))


def _otp_update_attempts(email: str, attempts: int):
    with db_cursor() as cur:
        cur.execute("UPDATE otp_store SET attempts = %s WHERE email = %s", (attempts, email))


def _otp_delete(email: str):
    with db_cursor() as cur:
        cur.execute("DELETE FROM otp_store WHERE email = %s", (email,))


# ════════════════════════════════════════════════════════════════════════════
# [C3] JWT secret
# ════════════════════════════════════════════════════════════════════════════
import hmac as _hmac, base64 as _b64
import uuid as _uuid_mod

_JWT_SECRET_FILE = os.path.join(SERVER_BASE_DIR, "jwt_secret.txt")


def _get_jwt_secret() -> str:
    """[C3] Return the JWT signing secret."""
    secret = os.environ.get("JWT_SECRET", "")
    if secret:
        return secret
    if os.path.exists(_JWT_SECRET_FILE):
        return open(_JWT_SECRET_FILE).read().strip()
    new_secret = _secrets.token_hex(64)
    with open(_JWT_SECRET_FILE, "w") as _jf:
        _jf.write(new_secret)
    print("[WARN] JWT_SECRET env var not set. Auto-generated jwt_secret.txt (dev mode only).")
    return new_secret


if not os.environ.get("JWT_SECRET"):
    print("[WARN] JWT_SECRET env var is not set. Using auto-generated jwt_secret.txt (dev mode).")

# ════════════════════════════════════════════════════════════════════════════
# [H3] DB-backed token blocklist
# ════════════════════════════════════════════════════════════════════════════

_blocklist_lock = threading.Lock()


def _load_blocklist() -> set:
    """Load non-expired JTIs from DB into memory on startup."""
    try:
        with db_cursor(commit=False) as cur:
            cur.execute("SELECT jti FROM token_blocklist WHERE expires_at > now()")
            return {row["jti"] for row in cur.fetchall()}
    except Exception:
        return set()


def _blocklist_add(jti: str, exp: float):
    """Add a JTI to the blocklist (in-memory + DB)."""
    _token_blocklist.add(jti)
    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO token_blocklist (jti, expires_at)
                VALUES (%s, %s)
                ON CONFLICT (jti) DO NOTHING
            """, (jti, exp_dt))
    except Exception as _be:
        print(f"[Blocklist] DB write failed: {_be}")


# Load blocklist on startup (after init_db)
_token_blocklist: set = _load_blocklist()


def _jwt_encode(payload: dict) -> str:
    if "jti" not in payload:
        payload["jti"] = str(_uuid_mod.uuid4())
    secret = _get_jwt_secret()
    header = _b64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body   = _b64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig_raw = _hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    sig     = _b64.urlsafe_b64encode(sig_raw).rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


def _jwt_decode(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        secret = _get_jwt_secret()
        expected_sig = _b64.urlsafe_b64encode(
            _hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not _hmac.compare_digest(sig, expected_sig):
            return None
        pad  = 4 - len(body) % 4
        data = json.loads(_b64.urlsafe_b64decode(body + "=" * pad))
        if data.get("exp", 0) < time.time():
            return None
        # [H3] Check token blocklist — fast in-memory path
        jti = data.get("jti")
        if jti:
            if _token_blocklist:
                if jti in _token_blocklist:
                    return None
            else:
                # In-memory set empty (restart recovery) — reload from DB
                recovered = _load_blocklist()
                _token_blocklist.update(recovered)
                if jti in _token_blocklist:
                    return None
        return data
    except Exception:
        return None


def _require_jwt(roles=None):
    """Decorator — validates JWT and optionally checks role."""
    def decorator(f):
        @wraps(f)
        def wrapper(*a, **kw):
            auth = request.headers.get("Authorization", "")
            token = auth.replace("Bearer ", "").strip() if auth.startswith("Bearer ") else ""
            if not token:
                token = request.cookies.get("access_token", "")
            payload = _jwt_decode(token)
            if not payload:
                return jsonify({"error": "invalid_or_expired_token"}), 401
            if roles and payload.get("role") not in roles:
                return jsonify({"error": "forbidden", "required_roles": roles}), 403
            request.jwt_payload = payload
            return f(*a, **kw)
        return wrapper
    return decorator


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Patients
# ════════════════════════════════════════════════════════════════════════════

def _db_get_patient(profile_code: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM patients WHERE profile_code = %s", (profile_code,))
        row = cur.fetchone()
        return dict(row) if row else None


def _db_upsert_patient(profile_code: str, data: dict):
    enc_rec = data.get("encrypted_record", {})
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO patients (profile_code, encrypted_record, patient_public_pem, signature)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (profile_code) DO UPDATE SET
                encrypted_record   = EXCLUDED.encrypted_record,
                patient_public_pem = EXCLUDED.patient_public_pem,
                signature          = EXCLUDED.signature
        """, (
            profile_code,
            json.dumps(enc_rec) if isinstance(enc_rec, dict) else enc_rec,
            data.get("patient_public_pem"),
            data.get("signature"),
        ))


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Doctors
# ════════════════════════════════════════════════════════════════════════════

def _db_get_doctor(doctor_code: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM doctors WHERE doctor_code = %s", (doctor_code,))
        row = cur.fetchone()
        return dict(row) if row else None


def _db_upsert_doctor(doctor_code: str, data: dict):
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO doctors (doctor_code, doctor_id, public_pem, encrypted_profile)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (doctor_code) DO UPDATE SET
                public_pem        = EXCLUDED.public_pem,
                encrypted_profile = EXCLUDED.encrypted_profile
        """, (
            doctor_code,
            data.get("doctor_id", str(uuid.uuid4())),
            data.get("public_pem", data.get("public_key", "")),
            data.get("encrypted_profile"),
        ))


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Wrapped keys
# ════════════════════════════════════════════════════════════════════════════

def _db_get_wrapped_key(profile_code: str, doctor_code: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT * FROM wrapped_keys
            WHERE profile_code = %s
              AND doctor_code = %s
              AND (temp_key_expires_at IS NULL OR temp_key_expires_at > now())
        """, (profile_code, doctor_code))
        row = cur.fetchone()
        return dict(row) if row else None


def _db_upsert_wrapped_key(profile_code: str, doctor_code: str, data: dict):
    enc_kdata = data.get("encrypted_kdata_with_temp")
    temp_exp  = data.get("temp_key_expires_at")
    if isinstance(temp_exp, str) and temp_exp:
        try:
            temp_exp = datetime.fromisoformat(temp_exp)
        except ValueError:
            temp_exp = None
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO wrapped_keys
                (profile_code, doctor_code, wrapped_key, encrypted_kdata, temp_key_expires_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (profile_code, doctor_code) DO UPDATE SET
                wrapped_key         = EXCLUDED.wrapped_key,
                encrypted_kdata     = EXCLUDED.encrypted_kdata,
                temp_key_expires_at = EXCLUDED.temp_key_expires_at,
                uploaded_at         = now()
        """, (
            profile_code,
            doctor_code,
            data.get("wrapped_key"),
            json.dumps(enc_kdata) if isinstance(enc_kdata, dict) else enc_kdata,
            temp_exp,
        ))


def _db_get_all_wrapped_keys(profile_code: str) -> dict:
    """Returns dict keyed by doctor_code (non-expired only)."""
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT * FROM wrapped_keys
            WHERE profile_code = %s
              AND (temp_key_expires_at IS NULL OR temp_key_expires_at > now())
        """, (profile_code,))
        rows = cur.fetchall()
        return {r["doctor_code"]: dict(r) for r in rows}


def _doctor_has_active_access(patient_code: str, doctor_code: str) -> bool:
    """Return True iff the doctor has a non-expired wrapped key for this patient."""
    return _db_get_wrapped_key(patient_code, doctor_code) is not None


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Access requests
# ════════════════════════════════════════════════════════════════════════════

def _db_get_access_requests(profile_code: str = None,
                             doctor_code: str = None,
                             status: str = None) -> list:
    conditions = []
    params = []
    if profile_code:
        conditions.append("profile_code = %s")
        params.append(profile_code)
    if doctor_code:
        conditions.append("doctor_code = %s")
        params.append(doctor_code)
    if status:
        conditions.append("status = %s")
        params.append(status)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with db_cursor(commit=False) as cur:
        cur.execute(
            f"SELECT * FROM access_requests {where} ORDER BY created_at DESC",
            params
        )
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            # Serialize timestamps for JSON
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_get_one_access_request(request_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM access_requests WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


def _db_create_access_request(entry: dict) -> str:
    req_id = entry.get("request_id", str(uuid.uuid4()))
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO access_requests
                (request_id, profile_code, doctor_code,
                 doctor_public_pem, encrypted_doctor_profile, status)
            VALUES (%s, %s, %s, %s, %s, 'pending')
            RETURNING request_id
        """, (
            req_id,
            entry["profile_code"],
            entry["doctor_code"],
            entry.get("doctor_public_pem"),
            entry.get("encrypted_doctor_profile_b64"),
        ))
        return str(cur.fetchone()["request_id"])


def _db_update_access_request(request_id: str, updates: dict):
    ALLOWED = {
        "status", "approved_at", "denied_at", "cancelled_at", "expired_at",
        "wrapped_key", "encrypted_kdata", "temp_key_expires_at",
    }
    set_parts = []
    params = []
    for field, value in updates.items():
        if field not in ALLOWED:
            continue
        set_parts.append(f"{field} = %s")
        params.append(value)
    if not set_parts:
        return
    params.append(request_id)
    with db_cursor() as cur:
        cur.execute(
            f"UPDATE access_requests SET {', '.join(set_parts)} WHERE request_id = %s",
            params
        )


def _db_pending_request_exists(profile_code: str, doctor_code: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT request_id FROM access_requests
            WHERE profile_code = %s AND doctor_code = %s AND status = 'pending'
            LIMIT 1
        """, (profile_code, doctor_code))
        row = cur.fetchone()
        return dict(row) if row else None


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Doctor notes
# ════════════════════════════════════════════════════════════════════════════

def _db_add_note(note: dict) -> str:
    note_id = note.get("note_id", str(uuid.uuid4()))
    visit_date = note.get("visit_date") or None
    if visit_date == "":
        visit_date = None
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO doctor_notes
                (note_id, patient_code, doctor_code, doctor_name,
                 doctor_specialization, doctor_hospital, note_type,
                 note_text, visit_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING note_id
        """, (
            note_id,
            note["patient_code"],
            note["doctor_code"],
            note.get("doctor_name", ""),
            note.get("doctor_specialization", ""),
            note.get("doctor_hospital", ""),
            note.get("note_type", "General"),
            note["note_text"],
            visit_date,
        ))
        return str(cur.fetchone()["note_id"])


def _db_get_notes(patient_code: str, doctor_code: str = None) -> list:
    with db_cursor(commit=False) as cur:
        if doctor_code:
            cur.execute("""
                SELECT * FROM doctor_notes
                WHERE patient_code = %s AND doctor_code = %s
                ORDER BY created_at DESC
            """, (patient_code, doctor_code))
        else:
            cur.execute("""
                SELECT * FROM doctor_notes
                WHERE patient_code = %s
                ORDER BY created_at DESC
            """, (patient_code,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
                elif hasattr(v, 'isoformat'):  # date objects
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_get_note(note_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM doctor_notes WHERE note_id = %s", (note_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
            elif hasattr(v, 'isoformat'):
                d[k] = v.isoformat()
        return d


def _db_delete_note(note_id: str, doctor_code: str) -> bool:
    with db_cursor() as cur:
        cur.execute("""
            DELETE FROM doctor_notes
            WHERE note_id = %s AND doctor_code = %s
        """, (note_id, doctor_code))
        return cur.rowcount > 0


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Records & Images
# ════════════════════════════════════════════════════════════════════════════

def _db_add_record(record: dict) -> str:
    enc_blob = record.get("encrypted_report_blob", {})
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO records
                (id, patient_id, doctor_id, doctor_email,
                 encrypted_report_blob, encrypted_aes_key, file_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            record.get("id", str(uuid.uuid4())),
            record["patient_id"],
            record["doctor_id"],
            record.get("doctor_email", ""),
            json.dumps(enc_blob) if isinstance(enc_blob, dict) else enc_blob,
            record.get("encrypted_aes_key", ""),
            record.get("file_hash", ""),
        ))
        return str(cur.fetchone()["id"])


def _db_get_records_for_patient(patient_id: str) -> list:
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT id, patient_id, doctor_id, doctor_email,
                   encrypted_aes_key, file_hash, created_at
            FROM records WHERE patient_id = %s
            ORDER BY created_at DESC
        """, (patient_id,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_get_record(record_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM records WHERE id = %s", (record_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


def _db_add_image(img_record: dict) -> str:
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO images
                (id, record_id, encrypted_image_path, encrypted_aes_key,
                 file_hash, server_hash, hash_verified, doctor_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            img_record.get("id", str(uuid.uuid4())),
            img_record["record_id"],
            img_record["encrypted_image_path"],
            img_record.get("encrypted_aes_key", ""),
            img_record.get("file_hash", ""),
            img_record.get("server_hash", ""),
            img_record.get("hash_verified"),
            img_record.get("doctor_id", ""),
        ))
        return str(cur.fetchone()["id"])


def _db_get_images_for_record(record_id: str) -> list:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM images WHERE record_id = %s", (record_id,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_get_image(image_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM images WHERE id = %s", (image_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Access DB (JWT-based)
# ════════════════════════════════════════════════════════════════════════════

def _db_access_get_pending(doctor_id: str, patient_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT * FROM access_db
            WHERE doctor_id = %s AND patient_id = %s AND status = 'pending'
        """, (doctor_id, patient_id))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


def _db_access_for_patient(patient_id: str) -> list:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM access_db WHERE patient_id = %s ORDER BY created_at DESC",
                    (patient_id,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_access_for_doctor(doctor_id: str, status: str = "approved") -> list:
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT * FROM access_db
            WHERE doctor_id = %s AND status = %s
            ORDER BY created_at DESC
        """, (doctor_id, status))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_access_insert(entry: dict) -> dict:
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO access_db (id, doctor_id, doctor_email, patient_id, status)
            VALUES (%s, %s, %s, %s, 'pending')
            RETURNING *
        """, (entry["id"], entry["doctor_id"], entry.get("doctor_email", ""), entry["patient_id"]))
        row = cur.fetchone()
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


def _db_access_respond(req_id: str, patient_id: str, status: str, responded_at: str) -> dict | None:
    with db_cursor() as cur:
        cur.execute("""
            UPDATE access_db SET status = %s, responded_at = %s
            WHERE id = %s AND patient_id = %s
            RETURNING *
        """, (status, responded_at, req_id, patient_id))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


# ════════════════════════════════════════════════════════════════════════════
# DB HELPERS — Appointments
# ════════════════════════════════════════════════════════════════════════════

def _db_appt_insert(entry: dict) -> dict:
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO appointments
                (id, patient_id, patient_username, patient_name,
                 doctor_username, date, time, notes, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
            RETURNING *
        """, (
            entry["id"],
            entry["patient_id"],
            entry.get("patient_username", ""),
            entry.get("patient_name", ""),
            entry["doctor_username"],
            entry["date"],
            entry["time"],
            entry.get("notes", ""),
        ))
        row = cur.fetchone()
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


def _db_appts_for_patient(patient_id: str) -> list:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM appointments WHERE patient_id = %s ORDER BY created_at DESC",
                    (patient_id,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_appts_for_doctor(doctor_username: str) -> list:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM appointments WHERE doctor_username = %s ORDER BY created_at DESC",
                    (doctor_username,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        return result


def _db_appt_respond(req_id: str, doctor_username: str, status: str,
                     date: str = None, time_val: str = None) -> dict | None:
    with db_cursor() as cur:
        if status == "rescheduled" and date and time_val:
            cur.execute("""
                UPDATE appointments
                SET status = %s, date = %s, time = %s, updated_at = now()
                WHERE id = %s AND doctor_username = %s
                RETURNING *
            """, (status, date, time_val, req_id, doctor_username))
        else:
            cur.execute("""
                UPDATE appointments
                SET status = %s, updated_at = now()
                WHERE id = %s AND doctor_username = %s
                RETURNING *
            """, (status, req_id, doctor_username))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


# ════════════════════════════════════════════════════════════════════════════
# [H1] Helper: check if the caller may access a patient's data
# ════════════════════════════════════════════════════════════════════════════

def _caller_may_access_patient(profile_code: str) -> bool:
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip() if auth.startswith("Bearer ") else ""
    if not token:
        token = request.cookies.get("access_token", "")
    if not token:
        return False
    payload = _jwt_decode(token)
    if not payload:
        return False
    role = payload.get("role", "")
    uid  = payload.get("uid", "")
    if role == "patient":
        return uid == profile_code
    if role == "doctor":
        return _doctor_has_active_access(profile_code, uid)
    return False


# ════════════════════════════════════════════════════════════════════════════
# [H6] Image magic-byte validation
# ════════════════════════════════════════════════════════════════════════════

_IMAGE_MAGIC = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG":      "png",
    b"GIF8":         "gif",
    b"RIFF":         "webp",
}


def _validate_image_magic(file_obj) -> bool:
    header = file_obj.read(12)
    file_obj.seek(0)
    for magic in _IMAGE_MAGIC:
        if header[:len(magic)] == magic:
            return True
    return False


@app.errorhandler(413)
def _handle_413(e):
    """[H6] Return JSON error for request entity too large."""
    return jsonify({"error": "file_too_large", "limit_mb": 10}), 413


# ════════════════════════════════════════════════════════════════════════════
# PATIENT REGISTRATION
# ════════════════════════════════════════════════════════════════════════════

import re as re  # fix #28

def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_\-]", "_", name)


@app.route("/register_user", methods=["POST"])
def register_user():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "details": str(e)}), 400

    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "empty_or_nonjson_payload"}), 400

    profile = payload.get("profile_code")
    enc = payload.get("encrypted_record")
    if not profile or not isinstance(profile, str):
        return jsonify({"error": "missing_profile_code"}), 400
    if not enc or not isinstance(enc, dict) or "nonce" not in enc or "ciphertext" not in enc:
        return jsonify({"error": "missing_encrypted_record_or_invalid_format",
                        "encrypted_record": enc}), 400

    safe_profile = "".join([c for c in profile if c.isalnum() or c in ("-", "_")])

    obj = {
        "profile_code": profile,
        "encrypted_record": enc,
        "signature": payload.get("signature"),
        "patient_public_pem": payload.get("patient_public_pem"),
        "uploaded_at": str(datetime.utcnow())
    }

    try:
        _db_upsert_patient(safe_profile, obj)
    except Exception as e:
        return jsonify({"error": "write_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "profile": profile}), 200


# ════════════════════════════════════════════════════════════════════════════
# DOCTOR REGISTRATION
# ════════════════════════════════════════════════════════════════════════════

@app.route("/register_doctor", methods=["POST"])
def register_doctor():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    try:
        data = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "details": str(e)}), 400

    doctor_id       = data.get("doctor_id")
    doctor_code     = data.get("doctor_code")
    public_pem      = data.get("public_pem")
    encrypted_profile = data.get("encrypted_profile")

    if not doctor_id or not doctor_code or not public_pem:
        return jsonify({"error": "missing_required_fields",
                        "required": ["doctor_id", "doctor_code", "public_pem"]}), 400

    try:
        _db_upsert_doctor(doctor_code, {
            "doctor_id": doctor_id,
            "public_pem": public_pem,
            "encrypted_profile": encrypted_profile,
        })
    except Exception as e:
        return jsonify({"error": "write_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "doctor_code": doctor_code}), 200


# ════════════════════════════════════════════════════════════════════════════
# UPLOAD RECORD (legacy helper)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/upload_record", methods=["POST"])
def upload_record():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    data = request.get_json(force=True)
    print("\n[POST] /upload_record →", data)

    pid = data.get("patient_id")
    cid = data.get("cid")

    if not pid or not cid:
        return jsonify({"error": "Missing patient_id or CID"}), 400

    # Legacy: try to find patient and attach CID note
    return jsonify({"message": "Record uploaded"}), 200  # [MIGRATED TO DB] legacy CID store


# ════════════════════════════════════════════════════════════════════════════
# FETCH PATIENT DATA
# ════════════════════════════════════════════════════════════════════════════

@app.route("/get_patient_data/<profile_code>", methods=["GET"])
def get_patient_data(profile_code):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    # fix #3: path-traversal sanitisation
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", profile_code)
    if not safe_code:
        return jsonify({"error": "invalid_profile_code"}), 400
    profile_code = safe_code

    # [H1] IDOR check
    if not _caller_may_access_patient(profile_code):
        return jsonify({"error": "forbidden",
                        "detail": "No access to this patient's data."}), 403

    try:
        patient_data = _db_get_patient(profile_code)

        # migration bridge — check files if not in DB
        if not patient_data:
            enc_file_path  = os.path.join(PATIENTS_DIR, profile_code, "encrypted_data.json")
            meta_file_path = os.path.join(PATIENTS_DIR, f"{profile_code}.json")
            if os.path.exists(enc_file_path):
                with open(enc_file_path, "r", encoding="utf-8") as f:
                    encrypted_json = json.load(f)
                _db_upsert_patient(profile_code, encrypted_json)
                patient_data = _db_get_patient(profile_code)
            elif os.path.exists(meta_file_path):
                with open(meta_file_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                _db_upsert_patient(profile_code, meta)
                patient_data = _db_get_patient(profile_code)

        if not patient_data:
            return jsonify({"error": "Patient not found"}), 404

        enc_record = patient_data.get("encrypted_record")
        if isinstance(enc_record, str):
            enc_record = json.loads(enc_record)

        if not enc_record or "nonce" not in enc_record or "ciphertext" not in enc_record:
            return jsonify({"error": "Malformed encrypted record"}), 500

        print(f"\n[🔍 SERVER] Returning encrypted data for {profile_code}")

        return jsonify({
            "encrypted_record": enc_record,
            "signature": patient_data.get("signature"),
            "patient_public_pem": patient_data.get("patient_public_pem"),
        }), 200

    except Exception as e:
        print(f"[X] Error in get_patient_data: {e}")
        return jsonify({"error": str(e)}), 500


# ════════════════════════════════════════════════════════════════════════════
# GET PATIENT PUBLIC KEY
# ════════════════════════════════════════════════════════════════════════════

@app.route("/get_patient_public/<profile_code>", methods=["GET"])
def get_patient_public(profile_code):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", profile_code)
    if not safe_code:
        return jsonify({"error": "invalid_profile_code"}), 400
    profile_code = safe_code

    try:
        patient_data = _db_get_patient(profile_code)

        # migration bridge
        if not patient_data:
            meta_file_path = os.path.join(PATIENTS_DIR, f"{profile_code}.json")
            if os.path.exists(meta_file_path):
                with open(meta_file_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                _db_upsert_patient(profile_code, meta)
                patient_data = _db_get_patient(profile_code)

        if not patient_data:
            return jsonify({"error": "patient_not_found"}), 404

        patient_pub = patient_data.get("patient_public_pem")
        if patient_pub:
            return jsonify({"patient_public_pem": patient_pub}), 200

        return jsonify({"error": "patient_public_pem_not_found"}), 404

    except Exception as e:
        return jsonify({"error": "server_error", "details": str(e)}), 500


# ════════════════════════════════════════════════════════════════════════════
# REQUEST ACCESS SIMPLE
# ════════════════════════════════════════════════════════════════════════════

@app.route("/request_access_simple/<profile_code>", methods=["POST"])
def request_access_simple(profile_code):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "details": str(e)}), 400

    required = ["doctor_code", "doctor_public_pem", "encrypted_doctor_profile_b64"]
    missing = [k for k in required if k not in payload]
    if missing:
        return jsonify({"error": "missing_fields", "required": required,
                        "missing": missing}), 400

    doctor_code     = payload["doctor_code"]
    doctor_pub      = payload["doctor_public_pem"]
    enc_profile_b64 = payload["encrypted_doctor_profile_b64"]

    if not isinstance(doctor_code, str) or not doctor_code:
        return jsonify({"error": "invalid_doctor_code"}), 400
    if not isinstance(enc_profile_b64, str) or len(enc_profile_b64) < 16:
        return jsonify({"error": "invalid_encrypted_profile"}), 400

    # ensure patient exists (DB first, then file migration bridge)
    patient_data = _db_get_patient(profile_code)
    if not patient_data:
        meta_file = os.path.join(PATIENTS_DIR, f"{profile_code}.json")
        if os.path.exists(meta_file):
            with open(meta_file) as f:
                meta = json.load(f)
            _db_upsert_patient(profile_code, meta)
        else:
            return jsonify({"error": "patient_not_found"}), 404

    # Prevent duplicate pending requests
    duplicate = _db_pending_request_exists(profile_code, doctor_code)
    if duplicate:
        return jsonify({"status": "duplicate_pending",
                        "request_id": duplicate["request_id"]}), 200

    entry = {
        "request_id": str(uuid.uuid4()),
        "profile_code": profile_code,
        "doctor_code": doctor_code,
        "doctor_public_pem": doctor_pub,
        "encrypted_doctor_profile_b64": enc_profile_b64,
    }

    try:
        req_id = _db_create_access_request(entry)
    except Exception as e:
        return jsonify({"error": "write_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "request_id": req_id}), 201


# ════════════════════════════════════════════════════════════════════════════
# ACTIVE REQUESTS ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/active_requests", methods=["GET"])
def get_all_active_requests():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    arr = _db_get_access_requests()
    return jsonify(arr), 200


@app.route("/request_status/<request_id>", methods=["GET"])
def get_request_status(request_id):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    found = _db_get_one_access_request(request_id)
    if not found:
        return jsonify({"error": "not_found"}), 404
    return jsonify(found), 200


@app.route("/wrapped_key/<profile_code>", methods=["GET"])
def get_wrapped_key_for_profile(profile_code):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", profile_code)
    if not safe_code:
        return jsonify({"error": "invalid_profile_code"}), 400
    profile_code = safe_code

    # [H1] IDOR check
    if not _caller_may_access_patient(profile_code):
        return jsonify({"error": "forbidden",
                        "detail": "No access to this patient's wrapped keys."}), 403

    try:
        keys_dict = _db_get_all_wrapped_keys(profile_code)
        # Serialize any datetime objects in the values
        out = {}
        for dk, js in keys_dict.items():
            entry = {}
            for k, v in js.items():
                if isinstance(v, datetime):
                    entry[k] = v.isoformat()
                else:
                    entry[k] = v
            out[dk] = entry
        return jsonify({"wrapped_keys": out}), 200
    except Exception as e:
        return jsonify({"error": "server_error", "details": str(e)}), 500


@app.route("/approve_request", methods=["POST"])
def approve_request():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "details": str(e)}), 400

    req_id       = payload.get("request_id")
    doctor_code  = payload.get("doctor_code")
    patient_code = payload.get("patient_code")

    if not req_id or not doctor_code or not patient_code:
        return jsonify({"error": "missing_fields",
                        "required": ["request_id", "doctor_code", "patient_code"]}), 400

    wrapped_key        = payload.get("wrapped_key")
    enc_record         = payload.get("encrypted_record")
    enc_kdata_with_temp = payload.get("encrypted_kdata_with_temp")
    temp_key_expires_at = payload.get("temp_key_expires_at")

    # Verify request exists and matches
    found = _db_get_one_access_request(req_id)
    if not found or found.get("profile_code") != patient_code or found.get("doctor_code") != doctor_code:
        return jsonify({"error": "request_not_found"}), 404

    # Persist wrapped key to DB
    if wrapped_key:
        try:
            _db_upsert_wrapped_key(patient_code, doctor_code, {
                "wrapped_key": wrapped_key,
                "encrypted_kdata_with_temp": enc_kdata_with_temp,
                "temp_key_expires_at": temp_key_expires_at,
            })
        except Exception as e:
            return jsonify({"error": "write_wrapped_key_failed", "details": str(e)}), 500

    # Update request status
    updates = {
        "status": "approved",
        "approved_at": datetime.now(timezone.utc),
    }
    if wrapped_key:
        updates["wrapped_key"] = wrapped_key
    if enc_kdata_with_temp:
        updates["encrypted_kdata"] = json.dumps(enc_kdata_with_temp) \
            if isinstance(enc_kdata_with_temp, dict) else enc_kdata_with_temp
    if temp_key_expires_at:
        try:
            updates["temp_key_expires_at"] = datetime.fromisoformat(temp_key_expires_at)
        except ValueError:
            pass

    try:
        _db_update_access_request(req_id, updates)
    except Exception as e:
        return jsonify({"error": "update_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "request_id": req_id}), 200


@app.route("/update_request_status", methods=["POST"])
def update_request_status():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "details": str(e)}), 400

    req_id = payload.get("request_id")
    status = payload.get("status")
    if not req_id or not status:
        return jsonify({"error": "missing_fields",
                        "required": ["request_id", "status"]}), 400

    # [H7] Whitelist
    ALLOWED_STATUSES = {"denied", "expired", "cancelled"}
    if status not in ALLOWED_STATUSES:
        return jsonify({
            "error": "invalid_status",
            "detail": "'approved' must use /approve_request. Only denied/expired/cancelled allowed here.",
            "allowed": list(ALLOWED_STATUSES)
        }), 400

    found = _db_get_one_access_request(req_id)
    if not found:
        return jsonify({"error": "request_not_found"}), 404

    updates = {
        "status": status,
        f"{status}_at": datetime.now(timezone.utc),
    }
    try:
        _db_update_access_request(req_id, updates)
    except Exception as e:
        return jsonify({"error": "update_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "request_id": req_id, "new_status": status}), 200


# ════════════════════════════════════════════════════════════════════════════
# Periodic cleanup (runs every hour)
# ════════════════════════════════════════════════════════════════════════════
import threading as _threading


def _cleanup_old_requests():
    try:
        with db_cursor() as cur:
            # resolved access requests older than 48h
            cur.execute("""
                DELETE FROM access_requests
                WHERE status IN ('approved','denied')
                  AND COALESCE(approved_at, denied_at) < now() - interval '48 hours'
            """)
            # stale pending older than 7 days
            cur.execute("""
                DELETE FROM access_requests
                WHERE status = 'pending'
                  AND created_at < now() - interval '7 days'
            """)
            # expired tokens
            cur.execute("DELETE FROM token_blocklist WHERE expires_at <= now()")
            # old rate limit records
            cur.execute("DELETE FROM rate_limits WHERE hit_at < now() - interval '10 minutes'")
    except Exception as ex:
        print(f"[Cleanup] DB cleanup error: {ex}")
    finally:
        _threading.Timer(3600, _cleanup_old_requests).start()


def _schedule_cleanup():
    t = _threading.Timer(3600, _cleanup_old_requests)
    t.daemon = True
    t.start()


# ════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/auth/otp/send", methods=["POST"])
@rate_limited(max_calls=5, window=300)
def auth_otp_send():
    """Send (simulated) OTP to email."""
    body  = request.get_json(force=True) or {}
    email = (body.get("email", "") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "invalid_email"}), 400
    otp = _gen_otp()
    exp = time.time() + 300  # 5 minutes
    with _otp_lock:
        _otp_set(email, otp, exp, attempts=0)
    # [L3] Only log OTP in development environment
    if os.environ.get("FLASK_ENV") == "development":
        print(f"[DEV OTP] {email} → {otp}")
    audit("otp_sent", actor=email)
    return jsonify({"message": "OTP sent", "expires_in": 300})


@app.route("/auth/otp/verify", methods=["POST"])
@rate_limited(max_calls=10, window=60)
def auth_otp_verify():
    body  = request.get_json(force=True) or {}
    email = (body.get("email", "") or "").strip().lower()
    otp   = (body.get("otp", "") or "").strip()
    with _otp_lock:
        rec = _otp_get(email)
        if not rec:
            return jsonify({"error": "no_otp_found"}), 400
        if rec["attempts"] >= 5:
            _otp_delete(email)
            return jsonify({"error": "too_many_attempts"}), 429
        if time.time() > rec["expires"]:
            _otp_delete(email)
            return jsonify({"error": "otp_expired"}), 400
        if rec["otp"] != otp:
            _otp_update_attempts(email, rec["attempts"] + 1)
            return jsonify({"error": "wrong_otp",
                            "attempts_left": 5 - rec["attempts"] - 1}), 400
        _otp_delete(email)
    audit("otp_verified", actor=email)
    vtoken = _jwt_encode({"sub": email, "purpose": "otp_verified", "exp": time.time() + 600})
    return jsonify({"verified": True, "verification_token": vtoken})


@app.route("/auth/register", methods=["POST"])
@rate_limited(max_calls=5, window=300)
def auth_register():
    body   = request.get_json(force=True) or {}
    vtoken = body.get("verification_token", "")
    payload = _jwt_decode(vtoken)
    if not payload or payload.get("purpose") != "otp_verified":
        return jsonify({"error": "email_not_verified"}), 403

    email    = payload["sub"]
    name     = (body.get("name", "") or "").strip()
    username = (body.get("username", "") or "").strip().lower()
    role     = body.get("role", "patient")
    pw_hash  = body.get("password_hash", "")
    pub_key  = body.get("public_key", "")
    enc_priv = body.get("encrypted_private_key", "")
    phone    = body.get("phone", "")

    if not name or not pw_hash or not pub_key or not username:
        return jsonify({"error": "missing_fields"}), 400
    if role not in ("patient", "doctor", "admin"):
        return jsonify({"error": "invalid_role"}), 400

    with _users_db_lock:
        existing = _db_get_user_by_email(email)
        if existing:
            return jsonify({"error": "email_already_registered"}), 409

        existing_un = _db_get_user_by_username(username)
        if existing_un and existing_un["email"] != email:
            return jsonify({"error": "username_taken"}), 409

        uid = str(uuid.uuid4())
        _db_upsert_user(email, {
            "id": uid, "name": name, "email": email, "username": username,
            "phone": phone, "role": role, "password_hash": pw_hash,
            "public_key": pub_key, "encrypted_private_key": enc_priv,
            "profile_photo_url": "", "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": "", "locked": False, "failed_attempts": 0,
        })

    audit("register", actor=email, detail=role)
    return jsonify({"message": "registered", "user_id": uid, "role": role})


@app.route("/internal/register_user_db", methods=["POST"])
def internal_register_user_db():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    body     = request.get_json(force=True) or {}
    email    = (body.get("email", "") or "").strip().lower()
    username = (body.get("username", "") or "").strip().lower()
    name     = (body.get("name", "") or "").strip()
    pw_hash  = body.get("password_hash", "")
    role     = body.get("role", "patient")
    pub_key  = body.get("public_key", "")
    enc_priv = body.get("encrypted_private_key", "")
    if not email or not name or not pw_hash or not username:
        return jsonify({"error": "missing_fields"}), 400

    profile_code = body.get("profile_code", "")
    doctor_code  = body.get("doctor_code", "")

    with _users_db_lock:
        existing_un = _db_get_user_by_username(username)
        if existing_un and existing_un["email"] != email:
            return jsonify({"error": "username_taken",
                            "message": "Username is already taken"}), 409

        existing = _db_get_user_by_email(email)
        if existing:
            # Update existing
            updates = {
                "role": role, "username": username,
                "password_hash": pw_hash,
            }
            if pub_key:
                updates["public_key"] = pub_key
            if profile_code:
                updates["profile_code"] = profile_code
            if doctor_code:
                updates["doctor_code"] = doctor_code
            for field, value in updates.items():
                _db_update_user_field(email, field, value)
            audit("register_via_legacy", actor=email, detail=role)
            return jsonify({"message": "updated", "user_id": existing["id"]}), 200

        uid = str(uuid.uuid4())
        _db_upsert_user(email, {
            "id": uid, "name": name, "email": email, "username": username,
            "phone": "", "role": role, "password_hash": pw_hash,
            "public_key": pub_key, "encrypted_private_key": enc_priv,
            "profile_code": profile_code, "doctor_code": doctor_code,
            "profile_photo_url": "", "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": "", "locked": False, "failed_attempts": 0,
        })
    audit("register_via_legacy", actor=email, detail=role)
    return jsonify({"message": "created", "user_id": uid})


@app.route("/auth/login", methods=["POST"])
@rate_limited(max_calls=10, window=60)
def auth_login():
    body       = request.get_json(force=True) or {}
    identifier = (body.get("email", "") or "").strip().lower()
    raw_pw     = body.get("password", "")

    with _users_db_lock:
        user  = _db_get_user_by_email(identifier)
        email = identifier
        if not user:
            user_by_un = _db_get_user_by_username(identifier)
            if user_by_un:
                user  = user_by_un
                email = user_by_un["email"]

        if not user:
            return jsonify({"error": "invalid_credentials"}), 401
        if user.get("locked"):
            return jsonify({"error": "account_locked"}), 403

        from werkzeug.security import check_password_hash as _wz_check

        stored  = user.get("password_hash", "")
        auth_ok = False

        if stored.startswith("pbkdf2:sha256:") or stored.startswith("scrypt:"):
            if raw_pw:
                auth_ok = _wz_check(stored, raw_pw)
        else:
            sha_hash = hashlib.sha256(raw_pw.encode()).hexdigest() if raw_pw else ""
            legacy_match = (stored == sha_hash) if sha_hash else False
            if legacy_match:
                return jsonify({
                    "error": "password_reset_required",
                    "reason": "legacy_hash",
                    "detail": "Your password uses an outdated hash. Use /auth/upgrade_password to reset."
                }), 403
            auth_ok = False

        if not auth_ok:
            new_attempts = user.get("failed_attempts", 0) + 1
            _db_update_user_field(email, "failed_attempts", new_attempts)
            if new_attempts >= 5:
                _db_update_user_field(email, "locked", True)
                audit("account_locked", actor=email)
            return jsonify({"error": "invalid_credentials"}), 401

        last_login_ts = datetime.now(timezone.utc).isoformat()
        _db_update_user_field(email, "failed_attempts", 0)
        _db_update_user_field(email, "last_login", datetime.now(timezone.utc))

    # Re-fetch to get updated user data
    user = _db_get_user_by_email(email)
    _append_login_history({"email": email, "ts": last_login_ts, "ip": request.remote_addr})

    jwt_uid = (user.get("profile_code") or user.get("doctor_code") or user["id"])
    access_token  = _jwt_encode({"sub": email, "uid": jwt_uid, "role": user["role"],
                                  "exp": time.time() + 3600})
    refresh_token = _jwt_encode({"sub": email, "uid": jwt_uid, "role": user["role"],
                                  "purpose": "refresh", "exp": time.time() + 604800})

    audit("login", actor=email)
    resp = jsonify({
        "message": "ok", "role": user["role"],
        "name": user["name"], "user_id": user["id"],
        "username": user.get("username", ""),
        "profile_code": user.get("profile_code", ""),
        "doctor_code": user.get("doctor_code", "") or user.get("profile_code", "")
                       if user["role"] == "doctor" else "",
        "access_token": access_token, "refresh_token": refresh_token,
        "public_key": user["public_key"],
        "encrypted_private_key": user["encrypted_private_key"],
    })
    resp.set_cookie("access_token", access_token, httponly=True, samesite="Strict", max_age=3600)
    resp.set_cookie("refresh_token", refresh_token, httponly=True, samesite="Strict", max_age=604800)
    return resp


@app.route("/auth/upgrade_password", methods=["POST"])
@rate_limited(max_calls=5, window=300)
def auth_upgrade_password():
    """[H2] Migrate a legacy SHA-256 account to werkzeug pbkdf2:sha256."""
    body     = request.get_json(force=True) or {}
    email    = (body.get("email", "") or "").strip().lower()
    old_hash = (body.get("old_password_hash", "") or "").strip()
    new_pw   = body.get("new_password", "")

    if not email or not old_hash or not new_pw:
        return jsonify({"error": "missing_fields",
                        "required": ["email", "old_password_hash", "new_password"]}), 400

    from werkzeug.security import generate_password_hash as _wz_gen

    with _users_db_lock:
        user = _db_get_user_by_email(email)
        if not user:
            user_by_un = _db_get_user_by_username(email)
            if user_by_un:
                user  = user_by_un
                email = user_by_un["email"]
        if not user:
            return jsonify({"error": "invalid_credentials"}), 401
        if user.get("locked"):
            return jsonify({"error": "account_locked"}), 403

        stored = user.get("password_hash", "")
        if stored.startswith("pbkdf2:sha256:") or stored.startswith("scrypt:"):
            return jsonify({"error": "not_legacy",
                            "detail": "Account already uses a modern hash."}), 400
        if stored != old_hash:
            return jsonify({"error": "invalid_credentials"}), 401

        new_hash = _wz_gen(new_pw, method="pbkdf2:sha256", salt_length=16)
        _db_update_user_field(email, "password_hash", new_hash)
        _db_update_user_field(email, "failed_attempts", 0)
        _db_update_user_field(email, "last_login", datetime.now(timezone.utc))

    user = _db_get_user_by_email(email)
    audit("password_upgraded", actor=email)
    jwt_uid = (user.get("profile_code") or user.get("doctor_code") or user["id"])
    access_token  = _jwt_encode({"sub": email, "uid": jwt_uid, "role": user["role"],
                                  "exp": time.time() + 3600})
    refresh_token = _jwt_encode({"sub": email, "uid": jwt_uid, "role": user["role"],
                                  "purpose": "refresh", "exp": time.time() + 604800})
    resp = jsonify({"message": "password_upgraded",
                    "access_token": access_token, "refresh_token": refresh_token})
    resp.set_cookie("access_token", access_token, httponly=True, samesite="Strict", max_age=3600)
    resp.set_cookie("refresh_token", refresh_token, httponly=True, samesite="Strict", max_age=604800)
    return resp


@app.route("/api/resolve_username/<username>", methods=["GET"])
def resolve_username(username):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    u = _db_get_user_by_username(username)
    if not u:
        return jsonify({"error": "user_not_found"}), 404
    return jsonify({
        "username": u.get("username"),
        "profile_code": u.get("profile_code", ""),
        "doctor_code": u.get("doctor_code", ""),
        "role": u.get("role", "patient"),
        "name": u.get("name", ""),
    }), 200


@app.route("/auth/logout", methods=["POST"])
@_require_jwt()
def auth_logout():
    jti = request.jwt_payload.get("jti", "")
    exp = request.jwt_payload.get("exp", 0)
    if jti:
        with _blocklist_lock:
            _blocklist_add(jti, exp)
    resp = jsonify({"message": "logged_out"})
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    audit("logout", actor=request.jwt_payload.get("sub", ""))
    return resp


@app.route("/auth/refresh", methods=["POST"])
def auth_refresh():
    token   = request.cookies.get("refresh_token", "") or \
              (request.get_json(force=True) or {}).get("refresh_token", "")
    payload = _jwt_decode(token)
    if not payload or payload.get("purpose") != "refresh":
        return jsonify({"error": "invalid_refresh_token"}), 401

    # [M8] Invalidate the old refresh token (single-use enforcement)
    old_jti = payload.get("jti", "")
    old_exp = payload.get("exp", 0)
    if old_jti:
        with _blocklist_lock:
            _blocklist_add(old_jti, old_exp)

    new_access = _jwt_encode({"sub": payload["sub"], "uid": payload["uid"],
                               "role": payload["role"], "exp": time.time() + 900})
    new_refresh = _jwt_encode({"sub": payload["sub"], "uid": payload["uid"],
                                "role": payload["role"], "purpose": "refresh",
                                "exp": time.time() + 604800})

    resp = jsonify({"access_token": new_access})
    resp.set_cookie("access_token", new_access, httponly=True, samesite="Strict", max_age=900)
    resp.set_cookie("refresh_token", new_refresh, httponly=True, samesite="Strict", max_age=604800)
    return resp


@app.route("/auth/me", methods=["GET"])
@_require_jwt()
def auth_me():
    p    = request.jwt_payload
    user = _db_get_user_by_email(p["sub"]) or {}
    return jsonify({
        "id":               user.get("id"),
        "name":             user.get("name"),
        "email":            p["sub"],
        "role":             user.get("role"),
        "phone":            user.get("phone", ""),
        "profile_photo_url": user.get("profile_photo_url", ""),
        "created_at":       str(user.get("created_at", "")),
        "last_login":       str(user.get("last_login", "")),
    })


@app.route("/auth/login_history", methods=["GET"])
@_require_jwt()
def auth_login_history():
    p = request.jwt_payload
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT email, ts, ip FROM login_history
            WHERE email = %s
            ORDER BY ts DESC LIMIT 50
        """, (p["sub"],))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("ts"), datetime):
                d["ts"] = d["ts"].isoformat()
            result.append(d)
        return jsonify(result)


# ════════════════════════════════════════════════════════════════════════════
# VISIT REPORT ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/reports/upload", methods=["POST"])
@_require_jwt(roles=["doctor"])
@rate_limited(max_calls=20, window=60)
def upload_report():
    body       = request.get_json(force=True) or {}
    doctor_jwt = request.jwt_payload
    patient_id = body.get("patient_id", "")
    enc_blob   = body.get("encrypted_report_blob", {})
    enc_key    = body.get("encrypted_aes_key", "")
    file_hash  = body.get("file_hash", "")

    if not patient_id or not enc_blob or not enc_key:
        return jsonify({"error": "missing_fields"}), 400

    record_id = str(uuid.uuid4())
    try:
        _db_add_record({
            "id": record_id,
            "patient_id": patient_id,
            "doctor_id": doctor_jwt["uid"],
            "doctor_email": doctor_jwt["sub"],
            "encrypted_report_blob": enc_blob,
            "encrypted_aes_key": enc_key,
            "file_hash": file_hash,
        })
    except Exception as e:
        return jsonify({"error": "db_write_failed", "details": str(e)}), 500

    audit("report_upload", actor=doctor_jwt["sub"], target=patient_id)
    return jsonify({"message": "report_uploaded", "record_id": record_id}), 201


@app.route("/reports/patient/<patient_id>", methods=["GET"])
@_require_jwt()
def get_patient_reports(patient_id):
    p = request.jwt_payload
    if p["role"] == "patient" and p["uid"] != patient_id:
        return jsonify({"error": "forbidden"}), 403
    records = _db_get_records_for_patient(patient_id)
    return jsonify(records)


@app.route("/reports/<record_id>", methods=["GET"])
@_require_jwt()
def get_report(record_id):
    p   = request.jwt_payload
    rec = _db_get_record(record_id)
    if not rec:
        return jsonify({"error": "not_found"}), 404
    if p["role"] == "patient" and p["uid"] != rec["patient_id"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(rec)


# ════════════════════════════════════════════════════════════════════════════
# IMAGE ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/images/upload", methods=["POST"])
@_require_jwt(roles=["doctor"])
@rate_limited(max_calls=10, window=60)
def upload_image():
    from flask import send_from_directory
    doctor_jwt = request.jwt_payload
    record_id  = request.form.get("record_id", "")
    file_hash  = request.form.get("file_hash", "")
    enc_key    = request.form.get("encrypted_aes_key", "")
    img_file   = request.files.get("image")

    if not record_id or not img_file or not enc_key:
        return jsonify({"error": "missing_fields"}), 400

    # [H6] Size check
    img_file.seek(0, 2)
    file_size = img_file.tell()
    img_file.seek(0)
    if file_size > 5 * 1024 * 1024:
        return jsonify({"error": "file_too_large", "limit_mb": 5}), 413

    # [H6] Magic-byte validation
    if not _validate_image_magic(img_file):
        return jsonify({"error": "invalid_file_type",
                        "allowed": ["jpg", "png", "gif", "webp"]}), 400

    img_id    = str(uuid.uuid4())
    filename  = f"{img_id}.enc"
    save_path = os.path.join(UPLOADS_DIR, "images", filename)
    img_file.save(save_path)

    actual_hash = hashlib.sha256(open(save_path, "rb").read()).hexdigest()

    try:
        _db_add_image({
            "id": img_id,
            "record_id": record_id,
            "encrypted_image_path": f"images/{filename}",
            "encrypted_aes_key": enc_key,
            "file_hash": file_hash,
            "server_hash": actual_hash,
            "hash_verified": actual_hash == file_hash if file_hash else None,
            "doctor_id": doctor_jwt["uid"],
        })
    except Exception as e:
        return jsonify({"error": "db_write_failed", "details": str(e)}), 500

    audit("image_upload", actor=doctor_jwt["sub"], target=record_id)
    return jsonify({"message": "image_uploaded", "image_id": img_id,
                    "hash_verified": actual_hash == file_hash if file_hash else None}), 201


@app.route("/images/record/<record_id>", methods=["GET"])
@_require_jwt()
def get_images_for_record(record_id):
    return jsonify(_db_get_images_for_record(record_id))


@app.route("/images/download/<image_id>", methods=["GET"])
@_require_jwt()
def download_image(image_id):
    from flask import send_file
    img = _db_get_image(image_id)
    if not img:
        return jsonify({"error": "not_found"}), 404
    path = os.path.join(UPLOADS_DIR, img["encrypted_image_path"])
    if not os.path.exists(path):
        return jsonify({"error": "file_missing"}), 404
    audit("image_download", actor=request.jwt_payload["sub"], target=image_id)
    return send_file(path, as_attachment=True,
                     download_name=f"encrypted_{image_id}.enc")


# ════════════════════════════════════════════════════════════════════════════
# PROFILE PHOTO
# ════════════════════════════════════════════════════════════════════════════

@app.route("/profile/photo", methods=["POST"])
@_require_jwt()
@rate_limited(max_calls=5, window=60)
def upload_profile_photo():
    from flask import send_file
    p        = request.jwt_payload
    img_file = request.files.get("photo")
    if not img_file:
        return jsonify({"error": "no_file"}), 400
    ext = img_file.filename.rsplit(".", 1)[-1].lower() if "." in img_file.filename else "jpg"
    if ext not in ("jpg", "jpeg", "png", "webp"):
        return jsonify({"error": "invalid_type"}), 400

    # [H6] Magic-byte validation
    if not _validate_image_magic(img_file):
        return jsonify({"error": "invalid_file_type",
                        "allowed": ["jpg", "jpeg", "png", "webp"]}), 400

    filename  = f"{p['uid']}_profile.{ext}"
    save_path = os.path.join(UPLOADS_DIR, "profiles", filename)
    img_file.save(save_path)
    url = f"/profile/photo/{p['uid']}"

    with _users_db_lock:
        _db_update_user_field(p["sub"], "profile_photo_url", url)

    return jsonify({"url": url})


@app.route("/profile/photo/<uid>", methods=["GET"])
def get_profile_photo(uid):
    from flask import send_file
    # [L4] Require API key for profile photo access
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    for ext in ("jpg", "jpeg", "png", "webp"):
        path = os.path.join(UPLOADS_DIR, "profiles", f"{uid}_profile.{ext}")
        if os.path.exists(path):
            return send_file(path)
    return jsonify({"error": "not_found"}), 404


# ════════════════════════════════════════════════════════════════════════════
# ACCESS MANAGEMENT (JWT-aware)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/access/request", methods=["POST"])
@_require_jwt(roles=["doctor"])
def jwt_request_access():
    body       = request.get_json(force=True) or {}
    patient_id = body.get("patient_id", "")
    doctor_jwt = request.jwt_payload
    if not patient_id:
        return jsonify({"error": "missing patient_id"}), 400

    existing = _db_access_get_pending(doctor_jwt["uid"], patient_id)
    if existing:
        return jsonify({"message": "already_pending", "id": existing["id"]}), 200

    entry = {
        "id": str(uuid.uuid4()),
        "doctor_id": doctor_jwt["uid"],
        "doctor_email": doctor_jwt["sub"],
        "patient_id": patient_id,
    }
    result = _db_access_insert(entry)
    audit("access_request", actor=doctor_jwt["sub"], target=patient_id)
    return jsonify(result), 201


@app.route("/access/patient_requests", methods=["GET"])
@_require_jwt(roles=["patient"])
def patient_access_requests():
    p = request.jwt_payload
    return jsonify(_db_access_for_patient(p["uid"]))


@app.route("/access/respond", methods=["POST"])
@_require_jwt(roles=["patient"])
def respond_access():
    body    = request.get_json(force=True) or {}
    req_id  = body.get("request_id", "")
    action  = body.get("action", "")
    patient = request.jwt_payload
    if action not in ("approve", "revoke", "deny"):
        return jsonify({"error": "invalid_action"}), 400
    status       = "approved" if action == "approve" else action
    responded_at = datetime.now(timezone.utc).isoformat()
    rec = _db_access_respond(req_id, patient["uid"], status, responded_at)
    if not rec:
        return jsonify({"error": "not_found"}), 404
    audit(f"access_{action}", actor=patient["sub"], target=rec.get("doctor_email", ""))
    return jsonify(rec)


@app.route("/access/doctor_patients", methods=["GET"])
@_require_jwt(roles=["doctor"])
def doctor_patients():
    p = request.jwt_payload
    return jsonify(_db_access_for_doctor(p["uid"], status="approved"))


# ════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ════════════════════════════════════════════════════════════════════════════

@app.route("/audit/log", methods=["GET"])
@_require_jwt()
def get_audit_log():
    p = request.jwt_payload
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT ts, action, actor, target, detail, ip
            FROM audit_log
            WHERE actor = %s OR target = %s
            ORDER BY ts DESC LIMIT 200
        """, (p["sub"], p["sub"]))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("ts"), datetime):
                d["ts"] = d["ts"].isoformat()
            result.append(d)
        return jsonify(result)


# ════════════════════════════════════════════════════════════════════════════
# USER SEARCH
# ════════════════════════════════════════════════════════════════════════════

@app.route("/users/search", methods=["GET"])
@_require_jwt(roles=["doctor"])
def user_search():
    q    = (request.args.get("q", "") or "").strip().lower()
    role = request.args.get("role", "patient")
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT id, name, email FROM users
            WHERE role = %s
              AND (lower(email) LIKE %s OR lower(name) LIKE %s)
            LIMIT 20
        """, (role, f"%{q}%", f"%{q}%"))
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS MIDDLEWARE
# ════════════════════════════════════════════════════════════════════════════

import secrets as _csp_secrets

_ALLOWED_ORIGINS = {"http://127.0.0.1:5001", "http://127.0.0.1:5002", "http://127.0.0.1:5003"}


@app.before_request
def _set_csp_nonce():
    g.csp_nonce = _csp_secrets.token_hex(16)


@app.context_processor
def _inject_csp_nonce():
    return {"csp_nonce": getattr(g, "csp_nonce", "")}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"]  = "nosniff"
    resp.headers["X-Frame-Options"]         = "DENY"
    resp.headers["X-XSS-Protection"]        = "1; mode=block"
    # [M1] Only set HSTS when behind a TLS proxy
    if os.environ.get("BEHIND_TLS_PROXY"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # fix #6: dynamic single-origin CORS
    origin = request.headers.get("Origin", "")
    if origin in _ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Vary"]                         = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,X-API-Key,Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    # [M7] CSP with per-request nonce
    nonce = getattr(g, "csp_nonce", "")
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: blob:; "
        f"connect-src 'self' http://127.0.0.1:5000; "
        f"frame-ancestors 'none';"
    )
    resp.headers["Content-Security-Policy"] = csp
    return resp


print("[UPGRADE] New auth/report/image/access endpoints loaded ✓")

# ════════════════════════════════════════════════════════════════════════════
# EMR MODULE — Blueprint registration
# ════════════════════════════════════════════════════════════════════════════
from emr.routes import emr_bp

# Inject server helpers so the blueprint can use them without circular imports
app.config["EMR_require_jwt"]  = _require_jwt
app.config["EMR_audit"]        = audit
app.config["EMR_rate_limited"] = rate_limited
# Updated to use DB-backed helpers
app.config["EMR_load_users"]   = _db_get_all_users
app.config["EMR_save_users"]   = _db_save_users_bulk

app.register_blueprint(emr_bp)
print("[EMR] EMR module loaded ✓")

# ════════════════════════════════════════════════════════════════════════════
# APPOINTMENTS & QR / BARCODE ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/patient/appointment-request", methods=["POST"])
@_require_jwt(roles=["patient"])
def request_appointment():
    body            = request.get_json(force=True) or {}
    patient         = request.jwt_payload
    doctor_username = body.get("doctor_username", "").strip()
    date            = body.get("date", "").strip()
    time_val        = body.get("time", "").strip()
    notes           = body.get("notes", "").strip()

    if not doctor_username or not date or not time_val:
        return jsonify({"error": "missing_fields"}), 400

    req_id = str(uuid.uuid4())
    entry = {
        "id": req_id,
        "patient_id": patient["uid"],
        "doctor_username": doctor_username,
        "date": date,
        "time": time_val,
        "notes": notes,
    }

    # Resolve patient username/name
    user = _db_get_user_by_email(patient["sub"])
    if user:
        entry["patient_username"] = user.get("username", patient["sub"])
        entry["patient_name"]     = user.get("name", "")
    else:
        entry["patient_username"] = patient["sub"]
        entry["patient_name"]     = ""

    try:
        result = _db_appt_insert(entry)
    except Exception as e:
        return jsonify({"error": "db_write_failed", "details": str(e)}), 500

    audit("appointment_requested", actor=patient["sub"], target=doctor_username)
    return jsonify({"message": "requested", "appointment": result}), 201


@app.route("/api/patient/appointment-requests", methods=["GET"])
@_require_jwt(roles=["patient"])
def get_patient_appointments():
    patient = request.jwt_payload
    appts   = _db_appts_for_patient(patient["uid"])
    return jsonify({"appointments": appts}), 200


@app.route("/api/doctor/appointment-requests", methods=["GET"])
@_require_jwt(roles=["doctor"])
def get_doctor_appointments():
    doc = request.jwt_payload
    user = _db_get_user_by_email(doc["sub"])
    doc_username = user.get("username", "") if user else ""
    appts = _db_appts_for_doctor(doc_username) if doc_username else []
    return jsonify({"appointments": appts}), 200


@app.route("/api/doctor/appointment-requests/<req_id>/respond", methods=["POST"])
@_require_jwt(roles=["doctor"])
def respond_appointment(req_id):
    body   = request.get_json(force=True) or {}
    status = body.get("status")
    if status not in ("accepted", "rejected", "rescheduled", "completed"):
        return jsonify({"error": "invalid_status"}), 400

    doc  = request.jwt_payload
    user = _db_get_user_by_email(doc["sub"])
    doc_username = user.get("username", "") if user else ""
    if not doc_username:
        return jsonify({"error": "doctor_not_found"}), 404

    result = _db_appt_respond(
        req_id, doc_username, status,
        date=body.get("date"), time_val=body.get("time")
    )
    if not result:
        return jsonify({"error": "not_found"}), 404

    audit(f"appointment_{status}", actor=doc["sub"])
    return jsonify({"message": "updated"}), 200


import io
import qrcode
import barcode
from barcode.writer import ImageWriter
from flask import send_file


@app.route("/api/patient/qr", methods=["GET"])
@_require_jwt(roles=["patient"])
def patient_qr():
    patient = request.jwt_payload
    user    = _db_get_user_by_email(patient["sub"])
    patient_id = patient["sub"]
    if user:
        patient_id = user.get("profile_code") or user.get("username", patient["sub"])
    qr = qrcode.make(patient_id)
    img_io = io.BytesIO()
    qr.save(img_io, "PNG")
    img_io.seek(0)
    return send_file(img_io, mimetype="image/png")


@app.route("/api/doctor/qr", methods=["GET"])
@_require_jwt(roles=["doctor"])
def doctor_qr():
    doc  = request.jwt_payload
    user = _db_get_user_by_email(doc["sub"])
    username = user.get("username", doc["sub"]) if user else doc["sub"]
    url = f"http://127.0.0.1:5001/doctor/public/{username}"
    qr  = qrcode.make(url)
    img_io = io.BytesIO()
    qr.save(img_io, "PNG")
    img_io.seek(0)
    return send_file(img_io, mimetype="image/png")


@app.route("/api/patient/barcode", methods=["GET"])
@_require_jwt(roles=["patient"])
def patient_barcode():
    patient = request.jwt_payload
    user    = _db_get_user_by_email(patient["sub"])
    patient_id = patient["sub"]
    if user:
        patient_id = user.get("profile_code") or user.get("username", patient["sub"])
    CODE = barcode.get_barcode_class("code128")
    bc   = CODE(patient_id, writer=ImageWriter())
    img_io = io.BytesIO()
    bc.write(img_io)
    img_io.seek(0)
    return send_file(img_io, mimetype="image/png")


# ════════════════════════════════════════════════════════════════════════════
# DOCTOR NOTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/note_images/<filename>", methods=["GET"])
def serve_note_image(filename):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    # [L5] Ownership check: parse note_id from filename (format: note_<uuid>.<ext>)
    note_id_from_file = None
    base = filename.rsplit(".", 1)[0] if "." in filename else filename
    if base.startswith("note_"):
        note_id_from_file = base[5:]

    if note_id_from_file:
        note = _db_get_note(note_id_from_file)
        if note:
            auth_hdr = request.headers.get("Authorization", "")
            token = auth_hdr.replace("Bearer ", "").strip() if auth_hdr.startswith("Bearer ") else ""
            if not token:
                token = request.cookies.get("access_token", "")
            if token:
                jwt_payload = _jwt_decode(token)
                if jwt_payload:
                    caller_uid = jwt_payload.get("uid", "")
                    if (caller_uid != note.get("patient_code") and
                            caller_uid != note.get("doctor_code")):
                        return jsonify({"error": "forbidden"}), 403
                else:
                    return jsonify({"error": "invalid_or_expired_token"}), 401

    img_path = os.path.join(NOTE_IMAGES_DIR, filename)
    if not os.path.exists(img_path):
        return jsonify({"error": "image_not_found"}), 404
    ext  = filename.rsplit(".", 1)[-1].lower()
    mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "gif": "image/gif", "webp": "image/webp"}.get(ext, "application/octet-stream")
    from flask import send_file as _sf
    return _sf(img_path, mimetype=mime)


@app.route("/doctor_notes/add", methods=["POST", "OPTIONS"])
@_require_jwt(roles=["doctor"])
def doctor_notes_add():
    """[C4] Add a doctor note. Requires a valid doctor JWT."""
    if request.method == "OPTIONS":
        return jsonify({}), 200

    # [C4] Derive doctor identity from JWT, not from body
    doctor_code = request.jwt_payload["uid"]

    body         = request.get_json(force=True) or {}
    patient_code = (body.get("patient_code")  or "").strip()
    doctor_name  = (body.get("doctor_name")   or "").strip()
    doctor_spec  = (body.get("doctor_specialization") or "").strip()
    doctor_hosp  = (body.get("doctor_hospital") or "").strip()
    note_type    = (body.get("note_type")     or "General").strip()
    note_text    = (body.get("note_text") or body.get("note") or "").strip()
    visit_date   = (body.get("visit_date")    or "").strip()

    if not patient_code or not note_text:
        return jsonify({"error": "missing_fields",
                        "required": ["patient_code", "note_text"]}), 400

    # Ensure patient profile exists (DB + migration bridge)
    patient_exists = _db_get_patient(patient_code) is not None
    if not patient_exists:
        # Check wrapped keys in DB (implies patient was registered and doctor was granted access)
        wk = _db_get_wrapped_key(patient_code, doctor_code)
        if not wk:
            # Fall back to file system for migration bridge
            pat_flat   = os.path.join(PATIENTS_DIR, f"{patient_code}.json")
            pat_folder = os.path.join(PATIENTS_DIR, patient_code, "encrypted_data.json")
            pat_wkdir  = os.path.join(PATIENTS_DIR, patient_code, "wrapped_keys")
            if not (os.path.exists(pat_flat) or os.path.exists(pat_folder)
                    or os.path.isdir(pat_wkdir)):
                return jsonify({"error": "patient_not_found",
                                "detail": f"No patient record found for code '{patient_code}'."}), 404

    # Access gate — doctor must have active approval
    if not _doctor_has_active_access(patient_code, doctor_code):
        return jsonify({
            "error": "access_denied",
            "detail": ("Doctor does not have active approved access for this patient. "
                       "Patient must approve access first, or the 24-hour window has expired.")
        }), 403

    note_id = str(uuid.uuid4())
    note = {
        "note_id":               note_id,
        "patient_code":          patient_code,
        "doctor_code":           doctor_code,
        "doctor_name":           doctor_name,
        "doctor_specialization": doctor_spec,
        "doctor_hospital":       doctor_hosp,
        "note_type":             note_type,
        "note_text":             note_text,
        "visit_date":            visit_date,
    }

    try:
        _db_add_note(note)
    except Exception as e:
        return jsonify({"error": "db_write_failed", "details": str(e)}), 500

    audit("doctor_note_added",
          actor=f"{doctor_name} ({doctor_code})",
          target=patient_code,
          detail=f"type={note_type}, note_id={note_id}")

    return jsonify({"message": "note_added", "note_id": note_id}), 201


@app.route("/doctor_notes/patient/<patient_code>", methods=["GET"])
def doctor_notes_for_patient(patient_code):
    """
    Returns all notes for this patient.
    [M6] JWT-based ownership check.
    """
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    # fix #3: path-traversal sanitisation
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", patient_code)
    if not safe_code:
        return jsonify({"error": "invalid_patient_code"}), 400
    patient_code = safe_code

    # [M6] JWT ownership check
    auth_hdr = request.headers.get("Authorization", "")
    token = auth_hdr.replace("Bearer ", "").strip() if auth_hdr.startswith("Bearer ") else ""
    if not token:
        token = request.cookies.get("access_token", "")
    if token:
        jwt_payload = _jwt_decode(token)
        if jwt_payload:
            role = jwt_payload.get("role", "")
            uid  = jwt_payload.get("uid", "")
            if role == "patient" and uid != patient_code:
                return jsonify({"error": "forbidden"}), 403
            if role == "doctor" and not _doctor_has_active_access(patient_code, uid):
                return jsonify({"error": "forbidden",
                                "detail": "No active access for this patient."}), 403
        else:
            return jsonify({"error": "invalid_or_expired_token"}), 401

    doc_filter = (request.args.get("doctor_code") or "").strip()
    notes = _db_get_notes(patient_code, doctor_code=doc_filter if doc_filter else None)
    return jsonify(notes), 200


@app.route("/doctor_notes/<note_id>", methods=["DELETE", "OPTIONS"])
@_require_jwt(roles=["doctor"])
def doctor_notes_delete(note_id):
    """[C4] Doctor deletes their own note."""
    if request.method == "OPTIONS":
        return jsonify({}), 200

    # [C4] Derive doctor identity from JWT
    doctor_code = request.jwt_payload["uid"]

    note = _db_get_note(note_id)
    if not note:
        return jsonify({"error": "note_not_found"}), 404
    if note["doctor_code"] != doctor_code:
        return jsonify({"error": "forbidden — you can only delete your own notes"}), 403

    deleted = _db_delete_note(note_id, doctor_code)
    if not deleted:
        return jsonify({"error": "delete_failed"}), 500

    audit("doctor_note_deleted",
          actor=f"{note.get('doctor_name', '?')} ({doctor_code})",
          target=note["patient_code"],
          detail=f"note_id={note_id}")

    return jsonify({"message": "deleted", "note_id": note_id}), 200


# ── Start cleanup scheduler ──────────────────────────────────────────────────
_schedule_cleanup()

# ── Entry point — MUST be last so every route above is registered ────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)