#!/usr/bin/env python3
"""
landing.py — MedVault Unified Landing Page (port 5003)

Serves:
  GET  /              → Landing page (Login / Sign Up)
  POST /login         → Authenticate via backend, set Flask session
  POST /register/patient → Register patient, set session
  POST /register/doctor  → Register doctor, set session
  GET  /dashboard     → Protected role-based dashboard
  GET  /logout        → Clear session, redirect to /
"""
import os, sys, json, secrets, string, hashlib
from base64 import b64encode, b64decode
import requests as http

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from flask import (Flask, render_template, request, session,
                   redirect, url_for, jsonify, flash)

from common.crypto_utils import (
    generate_rsa_keypair, rsa_serialize_private, rsa_serialize_public,
    generate_aes_key, aesgcm_encrypt, rsa_sign,
    derive_kek_from_password, wrap_key_with_kek,
)
from common.secure_key_store import SecureKeyStore

# ── App setup ─────────────────────────────────────────────────────────────────
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
STATIC_DIR   = os.path.join(os.path.dirname(__file__), "static")
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

# Shared secret key: same file used by patient_portal and doctor_portal
# so session cookies are accepted across all three apps.
_SK_FILE = os.path.join(ROOT, "server", "flask_secret.key")
if os.path.exists(_SK_FILE):
    app.secret_key = open(_SK_FILE, "rb").read()
else:
    app.secret_key = secrets.token_bytes(32)
    with open(_SK_FILE, "wb") as f:
        f.write(app.secret_key)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") != "development",  # fix #14
    PERMANENT_SESSION_LIFETIME=3600 * 8,   # 8-hour session
)

# ── Template context: inject `now` for dashboard greeting ─────────────────────
from datetime import datetime as _datetime
@app.context_processor
def _inject_now():
    return {'now': _datetime.now()}

# ── Constants ─────────────────────────────────────────────────────────────────
BACKEND     = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")
USERS_DIR   = os.path.join(ROOT, "client", "Users")
DOCTORS_DIR = os.path.join(ROOT, "doctor", "Doctors")
os.makedirs(USERS_DIR,   exist_ok=True)
os.makedirs(DOCTORS_DIR, exist_ok=True)

# ── Helpers ───────────────────────────────────────────────────────────────────
def _api_key():
    kf = os.path.join(ROOT, "server", "api_key.txt")
    return open(kf).read().strip() if os.path.exists(kf) else ""

def _headers():
    return {"X-API-Key": _api_key(), "Content-Type": "application/json"}

def _user_json_path(profile_code):
    return os.path.join(USERS_DIR, profile_code, "user_data.json")

def _require_session():
    """Redirect to landing if not logged in."""
    if not session.get("logged_in"):
        return redirect(url_for("landing"))
    return None


# ──────────────────────────────────────────────────────────────────────────────
#   ROUTES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def landing():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/dashboard")
def dashboard():
    guard = _require_session()
    if guard:
        return guard
    role        = session.get("role", "patient")
    doctor_code = session.get("doctor_code", "")
    spec        = session.get("specialization", "")
    hosp        = session.get("hospital", "")
    # If spec/hospital not yet in session (old session before our change),
    # load them live from doctor_data.json without requiring re-login.
    if role == "doctor" and doctor_code and not (spec or hosp):
        try:
            for d_folder in os.listdir(DOCTORS_DIR):
                meta_path = os.path.join(DOCTORS_DIR, d_folder, "doctor_data.json")
                if os.path.exists(meta_path):
                    m = json.load(open(meta_path, encoding="utf-8"))
                    if m.get("doctor_code") == doctor_code:
                        spec = m.get("specialization", "")
                        hosp = m.get("hospital", "")
                        session["specialization"] = spec
                        session["hospital"]        = hosp
                        break
        except Exception:
            pass
    return render_template(
        "dashboard.html",
        role=role,
        name=session.get("name", "User"),
        email=session.get("email", ""),
        username=session.get("username", ""),
        profile_code=session.get("profile_code", ""),
        doctor_code=doctor_code,
        specialization=spec,
        hospital=hosp,
        uid=session.get("profile_code", "") if role == "patient" else doctor_code,
        jwt_token=session.get("jwt_token", ""),
    )


# ── ADDITIONAL PAGE ROUTES ───────────────────────────────────────────────────
def _page_context():
    """Common context dict for all authenticated page renders."""
    role        = session.get("role", "patient")
    doctor_code = session.get("doctor_code", "")
    return dict(
        role=role,
        name=session.get("name", "User"),
        email=session.get("email", ""),
        username=session.get("username", ""),
        profile_code=session.get("profile_code", "") if role == "patient" else "",
        doctor_code=doctor_code,
        specialization=session.get("specialization", ""),
        hospital=session.get("hospital", ""),
        jwt_token=session.get("jwt_token", ""),
    )

@app.route("/health-record")
def health_record():
    guard = _require_session()
    if guard: return guard
    return render_template("health_record.html", **_page_context())

@app.route("/access-requests")
def access_requests():
    guard = _require_session()
    if guard: return guard
    return render_template("access_requests.html", **_page_context())

@app.route("/appointments")
def appointments():
    guard = _require_session()
    if guard: return guard
    return render_template("appointments.html", **_page_context())

@app.route("/notes")
def notes_page():
    guard = _require_session()
    if guard: return guard
    return render_template("doctor_notes.html", **_page_context())

@app.route("/audit")
def audit_log():
    guard = _require_session()
    if guard: return guard
    return render_template("audit_log.html", **_page_context())

@app.route("/profile")
def profile():
    guard = _require_session()
    if guard: return guard
    return render_template("profile.html", **_page_context())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ── LOGIN ─────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    try:
        d = request.get_json(force=True) or {}
        # Accept either email or username in the same field
        identifier = (d.get("email") or d.get("username") or "").strip().lower()
        password   = d.get("password") or ""

        if not identifier or not password:
            return jsonify({"error": "Username/email and password are required"}), 400

        sha_hash = hashlib.sha256(password.encode()).hexdigest()

        # Send raw password to backend — server handles both SHA-256 and werkzeug
        try:
            r = http.post(
                f"{BACKEND}/auth/login",
                json={"email": identifier, "password": password,
                      "password_hash": sha_hash},
                headers=_headers(),
                timeout=10,
            )
            data = r.json()
        except Exception as e:
            return jsonify({"error": f"Cannot reach backend: {e}"}), 502

        # ── Legacy hash detected: surface as upgrade_required ─────────
        if r.status_code == 403 and data.get("error") == "password_reset_required":
            return jsonify({
                "upgrade_required": True,
                "identifier": identifier,
                "old_hash": sha_hash,
                "message": "Your account uses an outdated password format. Set a new password to continue.",
            }), 403

        if not r.ok:
            err = data.get("error", "Invalid credentials")
            human = {
                "invalid_credentials": "Incorrect email/username or password.",
                "account_locked": "Account locked after too many failed attempts. Contact support.",
            }.get(err, err)
            return jsonify({"error": human}), r.status_code

        # Populate Flask session
        session.clear()
        role  = data.get("role", "patient")
        pcode = data.get("profile_code", "")
        dcode = data.get("doctor_code", "") or (pcode if role == "doctor" else "")
        session["logged_in"]    = True
        session["role"]         = role
        session["name"]         = data.get("name", "")
        session["email"]        = data.get("email", identifier)
        session["username"]     = data.get("username", "")
        session["user_id"]      = data.get("user_id", "")
        session["profile_code"] = pcode if role == "patient" else ""
        session["doctor_code"]  = dcode if role == "doctor" else ""
        session["jwt_token"]    = data.get("access_token", "")
        if role == "doctor" and dcode:
            try:
                for d_folder in os.listdir(DOCTORS_DIR):
                    meta_path = os.path.join(DOCTORS_DIR, d_folder, "doctor_data.json")
                    if os.path.exists(meta_path):
                        m = json.load(open(meta_path, encoding="utf-8"))
                        if m.get("doctor_code") == dcode:
                            session["specialization"] = m.get("specialization", "")
                            session["hospital"]        = m.get("hospital", "")
                            break
            except Exception:
                pass
        session.permanent = True

        return jsonify({"message": "ok", "redirect": "/dashboard",
                        "role": session["role"]})
    except Exception as e:
        app.logger.exception("Login error")
        return jsonify({"error": str(e)}), 500


# ── Password upgrade proxy (legacy SHA-256 → werkzeug pbkdf2) ─────────────────
@app.route("/login/upgrade", methods=["POST"])
def login_upgrade():
    """Transparently upgrades a legacy-hash account to werkzeug pbkdf2 and logs in."""
    try:
        d          = request.get_json(force=True) or {}
        identifier = (d.get("identifier") or "").strip().lower()
        old_hash   = (d.get("old_hash") or "").strip()
        new_pw     = d.get("new_password") or ""

        if not identifier or not old_hash or not new_pw:
            return jsonify({"error": "Missing fields."}), 400
        if len(new_pw) < 8:
            return jsonify({"error": "Password must be at least 8 characters."}), 400

        try:
            r = http.post(
                f"{BACKEND}/auth/upgrade_password",
                json={"email": identifier, "old_password_hash": old_hash,
                      "new_password": new_pw},
                headers=_headers(), timeout=10,
            )
            data = r.json()
        except Exception as e:
            return jsonify({"error": f"Cannot reach backend: {e}"}), 502

        if not r.ok:
            err = data.get("error", "Upgrade failed.")
            human = {
                "invalid_credentials": "The original password didn't match. Try again.",
                "account_locked": "Account locked. Contact support.",
                "not_legacy": "Account already upgraded — just sign in normally.",
            }.get(err, err)
            return jsonify({"error": human}), r.status_code

        # Upgrade succeeded — now log the user in by re-using the new token from the response
        # Immediately call login with the new password to populate session
        sha2 = hashlib.sha256(new_pw.encode()).hexdigest()
        r2 = http.post(
            f"{BACKEND}/auth/login",
            json={"email": identifier, "password": new_pw, "password_hash": sha2},
            headers=_headers(), timeout=10,
        )
        data2 = r2.json()
        if not r2.ok:
            return jsonify({"error": "Upgrade succeeded but auto-login failed. Please sign in."}), 200

        session.clear()
        role  = data2.get("role", "patient")
        pcode = data2.get("profile_code", "")
        dcode = data2.get("doctor_code", "") or (pcode if role == "doctor" else "")
        session["logged_in"]    = True
        session["role"]         = role
        session["name"]         = data2.get("name", "")
        session["email"]        = data2.get("email", identifier)
        session["username"]     = data2.get("username", "")
        session["user_id"]      = data2.get("user_id", "")
        session["profile_code"] = pcode if role == "patient" else ""
        session["doctor_code"]  = dcode if role == "doctor" else ""
        session["jwt_token"]    = data2.get("access_token", "")
        session.permanent       = True
        return jsonify({"message": "upgraded", "redirect": "/dashboard"})
    except Exception as e:
        app.logger.exception("login_upgrade error")
        return jsonify({"error": str(e)}), 500




# ── REGISTER PATIENT ──────────────────────────────────────────────────────────
@app.route("/register/patient", methods=["POST"])
def register_patient():
    try:
        d        = request.get_json(force=True) or {}
        name     = (d.get("name") or "").strip()
        email    = (d.get("email") or "").strip().lower()
        username = (d.get("username") or "").strip().lower()
        age      = (d.get("age") or "").strip()
        notes    = d.get("notes", "")
        password = d.get("password") or ""

        if not name:     return jsonify({"error": "Name is required"}), 400
        if not email:    return jsonify({"error": "Email is required"}), 400
        if not username: return jsonify({"error": "Username is required"}), 400
        import re
        if not re.match(r"^[a-z0-9_\.]+$", username):
            return jsonify({"error": "Username can only contain lowercase letters, numbers, dot, or underscore"}), 400
        if not password: return jsonify({"error": "Password is required"}), 400
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400

        # ── Generate RSA keypair + encrypt record ─────────────────────────────
        priv, pub  = generate_rsa_keypair()
        K_data     = generate_aes_key()
        record     = {"name": name, "age": age, "email": email, "notes": notes}
        plain      = json.dumps(record, ensure_ascii=False).encode()
        enc        = aesgcm_encrypt(K_data, plain)   # returns {nonce:str, ciphertext:str}
        sig        = rsa_sign(priv, (enc["nonce"] + "|" + enc["ciphertext"]).encode())
        kek, salt  = derive_kek_from_password(password)
        wrapped_k  = wrap_key_with_kek(kek, K_data)   # returns str (base64)
        priv_pem   = rsa_serialize_private(priv)        # bytes
        pub_pem    = rsa_serialize_public(pub)           # bytes

        # Unique profile code — MUST be alphanumeric only (Windows CredWrite rejects '+', '/', etc.)
        _CHARS = string.ascii_uppercase + string.digits
        profile_code = ''.join(secrets.choice(_CHARS) for _ in range(10))
        pdir = os.path.join(USERS_DIR, profile_code)
        os.makedirs(pdir, exist_ok=True)

        # Local user data — all values are JSON-serializable (strings/dicts)
        local = {
            "profile_code":       profile_code,
            "patient_details":    record,
            "patient_public_pem": pub_pem.decode("utf-8"),
            "encrypted_record":   enc,
            "signature":          sig,
            "key_protection": {
                "wrapped_k": wrapped_k,              # str (base64)
                "salt_b64":  b64encode(salt).decode("utf-8"),
            },
            "password_hash": hashlib.sha256(password.encode()).hexdigest(),
            "jwt_token": "",
        }
        with open(_user_json_path(profile_code), "w", encoding="utf-8") as f:
            json.dump(local, f, indent=2, ensure_ascii=False)

        # Store private key in Windows Credential Manager (DPAPI-backed)
        SecureKeyStore.store_private_key(f"patient__{profile_code}", priv_pem)

        with open(os.path.join(pdir, "patient_public.pem"), "wb") as f:
            f.write(pub_pem)

        # ── Register on backend (best-effort — don't crash if backend is slow) ─
        try:
            http.post(
                f"{BACKEND}/register_user",
                json={"profile_code": profile_code, "encrypted_record": enc,
                      "signature": sig, "patient_public_pem": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
        except Exception as e:
            app.logger.warning("backend /register_user failed: %s", e)

        # ── Create users_db entry (enables /auth/login after logout) ────────────
        try:
            resp = http.post(
                f"{BACKEND}/internal/register_user_db",
                json={"email": email, "username": username, "name": name, "role": "patient",
                      "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                      "profile_code": profile_code,
                      "public_key": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
            if resp.status_code == 409:
                return jsonify({"error": resp.json().get("error", "Username or email is already taken. Try a different username.")}), 409
        except Exception as e:
            app.logger.warning("backend /internal/register_user_db failed: %s", e)

        # ── Set session ────────────────────────────────────────────────────────
        session.clear()
        session["logged_in"]    = True
        session["role"]         = "patient"
        session["name"]         = name
        session["email"]        = email
        session["username"]     = username
        session["profile_code"] = profile_code
        session["doctor_code"]  = ""
        session.permanent       = True

        # ── Fetch JWT immediately so EMR endpoints work right away ────────────
        try:
            _lr = http.post(
                f"{BACKEND}/auth/login",
                json={"email": email, "password": password,
                      "password_hash": hashlib.sha256(password.encode()).hexdigest()},
                headers=_headers(), timeout=10,
            )
            if _lr.ok:
                session["jwt_token"] = _lr.json().get("access_token", "")
            else:
                session["jwt_token"] = ""
        except Exception:
            session["jwt_token"] = ""

        return jsonify({
            "message":      "ok",
            "profile_code": profile_code,
            "redirect":     "/dashboard",
        })

    except Exception as e:
        app.logger.exception("Patient registration error")
        return jsonify({"error": f"Registration failed: {e}"}), 500


# ── REGISTER DOCTOR ───────────────────────────────────────────────────────────
@app.route("/register/doctor", methods=["POST"])
def register_doctor():
    try:
        import uuid as _uuid

        d        = request.get_json(force=True) or {}
        name     = (d.get("name") or "").strip()
        email    = (d.get("email") or "").strip().lower()
        username = (d.get("username") or "").strip().lower()
        spec     = (d.get("specialization") or "").strip()
        hosp     = (d.get("hospital") or "").strip()
        password = d.get("password") or ""

        if not name:     return jsonify({"error": "Name is required"}), 400
        if not email:    return jsonify({"error": "Email is required"}), 400
        if not username: return jsonify({"error": "Username is required"}), 400
        import re
        if not re.match(r"^[a-z0-9_\.]+$", username):
            return jsonify({"error": "Username can only contain lowercase letters, numbers, dot, or underscore"}), 400
        if not password: return jsonify({"error": "Password is required"}), 400
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400

        # ── Generate RSA keypair ──────────────────────────────────────────────
        priv, pub   = generate_rsa_keypair()
        doctor_id   = str(_uuid.uuid4())
        # doctor_code from UUID is already hex (alphanumeric), safe for CredWrite
        doctor_code = doctor_id.replace('-', '')[:10].upper()

        priv_pem = rsa_serialize_private(priv)   # bytes
        pub_pem  = rsa_serialize_public(pub)      # bytes

        # KEK-wrap the private key for local storage (same as doctor_portal)
        kek, salt = derive_kek_from_password(password)
        wrapped   = wrap_key_with_kek(kek, priv_pem)   # str (base64)

        folder = os.path.join(DOCTORS_DIR, doctor_id)
        os.makedirs(folder, exist_ok=True)

        # Store wrapped private key in Windows Credential Manager
        SecureKeyStore.store_private_key(
            f"doctor__{doctor_code}", wrapped.encode("utf-8")
        )
        with open(os.path.join(folder, "key_protection.json"), "w") as f:
            json.dump({"salt_b64": b64encode(salt).decode("utf-8")}, f, indent=2)
        with open(os.path.join(folder, "doctor_public.pem"), "wb") as f:
            f.write(pub_pem)

        meta = {
            "doctor_id":       doctor_id,
            "doctor_code":     doctor_code,
            "name":            name,
            "specialization":  spec,
            "hospital":        hosp,
            "email":           email,
        }
        with open(os.path.join(folder, "doctor_data.json"), "w") as f:
            json.dump(meta, f, indent=2)

        # ── Register on backend (best-effort) ─────────────────────────────────
        try:
            http.post(
                f"{BACKEND}/register_doctor",
                json={"doctor_id": doctor_id, "doctor_code": doctor_code,
                      "public_pem": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
        except Exception as e:
            app.logger.warning("backend /register_doctor failed: %s", e)

        # ── Create users_db entry (enables /auth/login after logout) ────────────
        try:
            resp = http.post(
                f"{BACKEND}/internal/register_user_db",
                json={"email": email, "username": username, "name": name, "role": "doctor",
                      "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                      "profile_code": doctor_code,
                      "doctor_code": doctor_code,
                      "public_key": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
            if resp.status_code == 409:
                return jsonify({"error": resp.json().get("error", "Username or email is already taken. Try a different username.")}), 409
        except Exception as e:
            app.logger.warning("backend register_user_db failed: %s", e)

        # ── Set session ────────────────────────────────────────────────────────
        session.clear()
        session["logged_in"]      = True
        session["role"]           = "doctor"
        session["name"]           = name
        session["email"]          = email
        session["username"]       = username
        session["profile_code"]   = ""
        session["doctor_code"]    = doctor_code
        session["specialization"] = spec
        session["hospital"]       = hosp
        session.permanent         = True

        # ── Fetch JWT immediately so EMR endpoints work right away ────────────
        try:
            _lr = http.post(
                f"{BACKEND}/auth/login",
                json={"email": email, "password": password,
                      "password_hash": hashlib.sha256(password.encode()).hexdigest()},
                headers=_headers(), timeout=10,
            )
            if _lr.ok:
                session["jwt_token"] = _lr.json().get("access_token", "")
            else:
                session["jwt_token"] = ""
        except Exception:
            session["jwt_token"] = ""

        return jsonify({
            "message":     "ok",
            "doctor_code": doctor_code,
            "redirect":    "/dashboard",
        })

    except Exception as e:
        app.logger.exception("Doctor registration error")
        return jsonify({"error": f"Registration failed: {e}"}), 500


# ════════════════════════════════════════════════════════════════════════════
#   PATIENT API ROUTES  (called by dashboard.html via fetch)
# ════════════════════════════════════════════════════════════════════════════

def _patient_session_check():
    if not session.get("logged_in") or session.get("role") != "patient":
        return jsonify({"error": "unauthenticated"}), 401
    return None

# ── Load decrypted patient record ─────────────────────────────────────────────
@app.route("/patient/record", methods=["POST"])
def patient_record():
    err = _patient_session_check()
    if err: return err
    try:
        from common.crypto_utils import (
            derive_kek_from_password, unwrap_key_with_kek, aesgcm_decrypt
        )
        d = request.get_json(force=True) or {}
        pw = d.get("password", "")
        profile_code = session.get("profile_code", "")
        upath = _user_json_path(profile_code)
        if not os.path.exists(upath):
            return jsonify({"error": "Profile file not found on this device"}), 404
        local = json.load(open(upath, encoding="utf-8"))
        kp    = local.get("key_protection", {})
        if not kp or "salt_b64" not in kp or "wrapped_k" not in kp:
            return jsonify({"error": "Key protection data not found. "
                           "Please re-register your account."}), 500
        try:
            salt  = b64decode(kp["salt_b64"])
            kek, _= derive_kek_from_password(pw, salt=salt)
            unwrap_key_with_kek(kek, kp["wrapped_k"])   # validates password
        except Exception as ex:
            app.logger.warning("Record unlock failed for %s: %s", profile_code, type(ex).__name__)
            return jsonify({"error": "Wrong password — please enter the same "
                           "password you used during registration."}), 401
        return jsonify({"record": local.get("patient_details", {}),
                        "profile_code": profile_code})
    except Exception as e:
        app.logger.exception("patient_record error")
        return jsonify({"error": str(e)}), 500

# ── Access requests list ──────────────────────────────────────────────────────
@app.route("/patient/requests")
def patient_requests():
    err = _patient_session_check()
    if err: return err
    try:
        profile_code = session.get("profile_code", "")
        r = http.get(f"{BACKEND}/active_requests", headers=_headers(), timeout=8)
        all_reqs = r.json() if r.ok else []
        # Backend stores patient code as 'profile_code' in active_requests.json
        mine = [x for x in all_reqs
                if isinstance(x, dict) and x.get("profile_code") == profile_code]
        # Normalize fields for frontend (doctor_code, request_id, status, requested_at)
        normalized = []
        for x in mine:
            normalized.append({
                "id":           x.get("request_id", x.get("id", "")),
                "request_id":   x.get("request_id", x.get("id", "")),
                "doctor_code":  x.get("doctor_code", ""),
                "doctor_name":  x.get("doctor_name", x.get("doctor_code", "Doctor")),
                "status":       x.get("status", "pending"),
                "requested_at": x.get("timestamp", x.get("requested_at", "")),
            })
        return jsonify({"requests": normalized})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Approve access request ────────────────────────────────────────────────────
@app.route("/patient/approve", methods=["POST"])
def patient_approve():
    err = _patient_session_check()
    if err: return err
    try:
        from common.crypto_utils import (
            derive_kek_from_password, unwrap_key_with_kek,
            aesgcm_decrypt, aesgcm_encrypt,
            rsa_load_private, rsa_load_public, rsa_wrap_key,
        )
        d = request.get_json(force=True) or {}
        pw          = d.get("password", "")
        request_id  = d.get("request_id", "")
        doc_code    = d.get("doctor_code", "")
        profile_code= session.get("profile_code", "")

        upath = _user_json_path(profile_code)
        if not os.path.exists(upath):
            return jsonify({"error": "Profile not found on this device"}), 404

        local = json.load(open(upath, encoding="utf-8"))
        kp    = local.get("key_protection", {})

        # Unlock patient private key
        try:
            salt  = b64decode(kp["salt_b64"])
            kek,_ = derive_kek_from_password(pw, salt=salt)
            K_data = unwrap_key_with_kek(kek, kp["wrapped_k"])
        except Exception:
            return jsonify({"error": "Wrong password"}), 401

        priv_pem = SecureKeyStore.load_private_key(f"patient__{profile_code}")
        priv     = rsa_load_private(priv_pem)

        # Get doctor's public key from the active request entry
        # (doctor_public_pem is stored in active_requests.json at request time)
        req_r = http.get(f"{BACKEND}/request_status/{request_id}", headers=_headers(), timeout=8)
        if not req_r.ok:
            return jsonify({"error": "Access request not found"}), 404
        req_entry   = req_r.json()
        doc_pub_pem = req_entry.get("doctor_public_pem", "")
        if not doc_pub_pem:
            return jsonify({"error": "Doctor public key not found in request"}), 404
        doc_pub = rsa_load_public(doc_pub_pem.encode())

        # Generate temp key T, encrypt K_data with T, wrap T with doctor's public key
        from os import urandom
        T = urandom(32)
        enc_kdata = aesgcm_encrypt(T, K_data)
        wrapped_T = rsa_wrap_key(doc_pub, T)

        resp = http.post(
            f"{BACKEND}/approve_request",
            json={"request_id": request_id, "patient_code": profile_code,
                  "doctor_code": doc_code, "wrapped_key": wrapped_T,
                  "encrypted_kdata_with_temp": enc_kdata},
            headers=_headers(), timeout=10,
        )
        try:
            rdata = resp.json()
        except Exception:
            rdata = {"status": "ok" if resp.ok else "error", "code": resp.status_code}
        return jsonify(rdata), resp.status_code
    except Exception as e:
        app.logger.exception("patient_approve error")
        return jsonify({"error": str(e)}), 500

# ── Deny access request ───────────────────────────────────────────────────────
@app.route("/patient/deny", methods=["POST"])
def patient_deny():
    err = _patient_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        resp = http.post(f"{BACKEND}/deny_access",
                         json={"request_id": d.get("request_id",""),
                               "patient_code": session.get("profile_code",""),
                               "doctor_code": d.get("doctor_code","")},
                         headers=_headers(), timeout=8)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Doctor notes (pull → save locally → delete from server) ──────────────────
@app.route("/patient/notes")
def patient_notes():
    err = _patient_session_check()
    if err: return err
    try:
        profile_code = session.get("profile_code", "")

        # Paths on the "patient's device"
        user_folder  = os.path.join(USERS_DIR, profile_code)
        notes_file   = os.path.join(user_folder, "notes.json")
        images_dir   = os.path.join(user_folder, "images")
        os.makedirs(images_dir, exist_ok=True)

        # 1. Load already-synced local notes
        local_notes = []
        if os.path.exists(notes_file):
            try:
                local_notes = json.load(open(notes_file, encoding="utf-8"))
                if not isinstance(local_notes, list):
                    local_notes = []
            except Exception:
                local_notes = []

        local_ids = {n.get("id") for n in local_notes}

        # 2. Fetch new notes from server (temporary relay)
        try:
            r = http.get(f"{BACKEND}/doctor_notes/patient/{profile_code}",
                         headers=_headers(), timeout=8)
            server_notes = r.json().get("notes", []) if r.ok else []
        except Exception:
            server_notes = []

        # 3. Pull each new note onto the patient's device
        newly_pulled = []
        for note in server_notes:
            note_id = note.get("id", "")
            if note_id in local_ids:
                # Already saved locally — still delete the server copy
                try:
                    http.delete(f"{BACKEND}/doctor_notes/{note_id}",
                                headers=_headers(), timeout=6)
                except Exception:
                    pass
                continue

            # Download image to local device if present
            img_filename = note.get("image_filename", "")
            if img_filename:
                try:
                    ri = http.get(f"{BACKEND}/note_images/{img_filename}",
                                  headers=_headers(), timeout=15)
                    if ri.ok:
                        local_img_path = os.path.join(images_dir, img_filename)
                        with open(local_img_path, "wb") as f:
                            f.write(ri.content)
                    else:
                        img_filename = ""   # image unavailable
                except Exception:
                    img_filename = ""

            # Save note locally (with local image reference)
            local_note = {**note, "image_filename": img_filename}
            local_notes.append(local_note)
            local_ids.add(note_id)
            newly_pulled.append(note_id)

            # 4. Delete this note from the server (data now lives on patient's device)
            try:
                http.delete(f"{BACKEND}/doctor_notes/{note_id}",
                            headers=_headers(), timeout=6)
                app.logger.info("Pulled note %s to local device, deleted from server.", note_id)
            except Exception as e:
                app.logger.warning("Could not delete note %s from server: %s", note_id, e)

        # 5. Persist updated local notes file
        if newly_pulled:
            with open(notes_file, "w", encoding="utf-8") as f:
                json.dump(local_notes, f, indent=2)

        # Sort newest first
        local_notes.sort(key=lambda n: n.get("created_at", ""), reverse=True)
        return jsonify({"notes": local_notes})

    except Exception as e:
        app.logger.exception("patient_notes error")
        return jsonify({"error": str(e)}), 502


# ── Serve patient-local note images from their own device ─────────────────────
@app.route("/patient/note_image/<filename>")
def patient_local_note_image(filename):
    # Allow both patients (own notes) and doctors (reading patient notes with access)
    if not session.get("logged_in"):
        return "Unauthorized", 401
    # For patients use their own profile_code; for doctors, derive from URL context
    role = session.get("role", "")
    profile_code = session.get("profile_code", "") if role == "patient" else None
    # If doctor: search all patient folders for this image file
    if role == "doctor":
        for user_folder in os.listdir(USERS_DIR):
            candidate = os.path.join(USERS_DIR, user_folder, "images", filename)
            if os.path.exists(candidate):
                ext  = filename.rsplit(".", 1)[-1].lower()
                mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
                        "gif": "image/gif", "webp": "image/webp"}.get(ext, "application/octet-stream")
                from flask import send_file
                return send_file(candidate, mimetype=mime)
        # Fallback: try fetching from server
        try:
            r = http.get(f"{BACKEND}/note_images/{filename}", headers=_headers(), timeout=10)
            if r.ok:
                from flask import Response
                return Response(r.content, content_type=r.headers.get("Content-Type", "image/jpeg"))
        except Exception:
            pass
        return "Not found", 404
    img_path = os.path.join(USERS_DIR, profile_code, "images", filename)
    if not os.path.exists(img_path):
        # Fallback: try fetching from server (image not yet synced)
        try:
            r = http.get(f"{BACKEND}/note_images/{filename}",
                         headers=_headers(), timeout=10)
            if r.ok:
                from flask import Response
                return Response(r.content,
                                content_type=r.headers.get("Content-Type", "image/jpeg"))
        except Exception:
            pass
        return "Not found", 404
    ext  = filename.rsplit(".", 1)[-1].lower()
    mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "gif": "image/gif", "webp": "image/webp"}.get(ext, "application/octet-stream")
    from flask import send_file
    return send_file(img_path, mimetype=mime)


# ── Login history ─────────────────────────────────────────────────────────────
@app.route("/patient/history")
def patient_history():
    err = _patient_session_check()
    if err: return err
    try:
        email = session.get("email", "")
        jwt   = session.get("jwt_token", "")
        hdrs  = {**_headers()}
        if jwt:
            hdrs["Authorization"] = f"Bearer {jwt}"
        r = http.get(f"{BACKEND}/auth/login_history", headers=hdrs, timeout=8)
        if r.ok:
            hist = r.json()
            if isinstance(hist, dict):
                hist = hist.get("history", [])
            mine = [h for h in hist if h.get("email") == email]
            return jsonify({"history": mine[-20:]})
        # Fallback: read login_history.json directly if JWT expired
        hist_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "server", "login_history.json"
        )
        if os.path.exists(hist_file):
            hist = json.load(open(hist_file, encoding="utf-8"))
            mine = [h for h in hist if h.get("email") == email]
            return jsonify({"history": mine[-20:]})
        return jsonify({"history": []})
    except Exception as e:
        return jsonify({"error": str(e), "history": []}), 200


# ── Full audit log proxy ───────────────────────────────────────────────────────
@app.route("/portal/audit-log")
def portal_audit_log():
    """Proxy to the server's audit/log endpoint, filtering to the current user."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    jwt = session.get("jwt_token", "")
    if not jwt:
        return jsonify({"events": [], "note": "no_jwt"}), 200
    try:
        hdrs = {**_headers(), "Authorization": f"Bearer {jwt}"}
        r = http.get(f"{BACKEND}/audit/log", headers=hdrs, timeout=8)
        if r.ok:
            data = r.json()
            events = data if isinstance(data, list) else data.get("events", data.get("log", []))
            return jsonify({"events": events})
        return jsonify({"events": [], "backend_error": r.status_code}), 200
    except Exception as e:
        return jsonify({"events": [], "error": str(e)}), 200




# ── Patient: list all registered doctors ─────────────────────────────────────
@app.route("/patient/doctors", methods=["GET"])
def patient_list_doctors():
    """Return all registered doctors with name, specialization, hospital, username.
    No authentication required — this is a public directory listing."""
    doctors = []

    # ── Build a map: doctor_code → {username, email, name} from users_db ──
    users_db = {}
    try:
        users_db_path = os.path.join(ROOT, "server", "users_db.json")
        users_db = json.load(open(users_db_path, encoding="utf-8"))
    except Exception:
        pass

    code_to_user = {}
    for _email, _u in users_db.items():
        if isinstance(_u, dict) and _u.get("role") == "doctor":
            dc = _u.get("doctor_code") or _u.get("profile_code", "")
            if dc:
                code_to_user[dc] = {
                    "username": _u.get("username", ""),
                    "email":    _email,
                    "name":     _u.get("name", ""),
                }

    # ── Read specialization & hospital from doctor_data.json files ─────────
    seen_codes = set()
    for folder in os.listdir(DOCTORS_DIR):
        meta_path = os.path.join(DOCTORS_DIR, folder, "doctor_data.json")
        if not os.path.exists(meta_path):
            continue
        try:
            m = json.load(open(meta_path, encoding="utf-8"))
        except Exception:
            continue

        dc   = m.get("doctor_code", "")
        if not dc or dc in seen_codes:
            continue
        seen_codes.add(dc)

        user_info = code_to_user.get(dc, {})
        doctors.append({
            "doctor_code":    dc,
            "name":           user_info.get("name") or m.get("name", ""),
            "username":       user_info.get("username") or "",
            "email":          user_info.get("email", ""),
            "specialization": m.get("specialization", ""),
            "hospital":       m.get("hospital", ""),
        })

    # ── Also include doctors in users_db that have no doctor_data.json ─────
    for dc, info in code_to_user.items():
        if dc not in seen_codes:
            doctors.append({
                "doctor_code":    dc,
                "name":           info.get("name", ""),
                "username":       info.get("username", ""),
                "email":          info.get("email", ""),
                "specialization": "",
                "hospital":       "",
            })

    # Sort by name
    doctors.sort(key=lambda d: d["name"].lower())
    return jsonify({"doctors": doctors}), 200


# ════════════════════════════════════════════════════════════════════════════
#   DOCTOR API ROUTES  (called by dashboard.html via fetch)
# ════════════════════════════════════════════════════════════════════════════

DOCTOR_PORTAL = "http://127.0.0.1:5002"

def _doctor_session_check():
    if not session.get("logged_in") or session.get("role") != "doctor":
        return jsonify({"error": "unauthenticated"}), 401
    return None

def _resolve_patient_code(username_or_code: str) -> str:
    """Resolve a patient username to their profile_code.
    Tries in order:
      1. Local users_db.json (fastest)
      2. Server /api/resolve_username/<username> (PostgreSQL)
      3. Scan client/Users/* user_data.json folders
    Falls back to returning the raw value so raw profile_codes still work.
    """
    if not username_or_code:
        return username_or_code
    raw = username_or_code.strip()

    # ── 1. Local users_db.json ─────────────────────────────────────
    users_db_path = os.path.join(ROOT, "server", "users_db.json")
    try:
        users = json.load(open(users_db_path, encoding="utf-8"))
        for entry in users.values():
            uname = entry.get("username", "") or entry.get("email", "")
            if uname.lower() == raw.lower() and entry.get("role") == "patient":
                pc = entry.get("profile_code", "")
                if pc:
                    return pc
    except Exception as e:
        app.logger.debug("_resolve_patient_code users_db: %s", e)

    # ── 2. PostgreSQL via /api/resolve_username/<username> ─────────
    try:
        r = http.get(f"{BACKEND}/api/resolve_username/{raw}",
                     headers=_headers(), timeout=5)
        if r.ok:
            data = r.json()
            pc = data.get("profile_code") or data.get("patient_code") or ""
            if pc:
                return pc
    except Exception as e:
        app.logger.debug("_resolve_patient_code backend: %s", e)

    # ── 3. Scan local client/Users folders ────────────────────────
    try:
        for folder in os.listdir(USERS_DIR):
            ud_path = os.path.join(USERS_DIR, folder, "user_data.json")
            if not os.path.exists(ud_path):
                continue
            ud = json.load(open(ud_path, encoding="utf-8"))
            uname = ud.get("username", "") or ud.get("email", "")
            if uname.lower() == raw.lower():
                pc = ud.get("profile_code", folder)
                if pc:
                    return pc
    except Exception as e:
        app.logger.debug("_resolve_patient_code scan: %s", e)

    # Fallback: treat as raw profile_code
    return raw

def _fwd_headers():
    """Build headers that carry the Flask session cookie to doctor_portal."""
    h = {"Content-Type": "application/json", "X-API-Key": _api_key()}
    return h


# ── Load doctor profile (verify password + get profile details) ────────────
@app.route("/doctor/load_profile", methods=["POST"])
def doctor_load_profile():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        doc_code = session.get("doctor_code", "")
        pw = d.get("password", "")
        try:
            r = http.post(
                f"{DOCTOR_PORTAL}/api/load_profile",
                json={"doctor_code": doc_code, "password": pw},
                cookies={"session": request.cookies.get("session", "")},
                headers=_fwd_headers(), timeout=10,
            )
            return jsonify(r.json()), r.status_code
        except (http.exceptions.ConnectionError, http.exceptions.Timeout):
            # Fallback: return doctor info from session cache
            return jsonify({
                "name":           session.get("name", ""),
                "doctor_code":    doc_code,
                "specialization": session.get("specialization", ""),
                "hospital":       session.get("hospital", ""),
                "email":          session.get("email", ""),
                "_portal_fallback": True,
            }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Request patient access ─────────────────────────────────────────────────
@app.route("/doctor/request_access", methods=["POST"])
def doctor_request_access():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        # Resolve username → profile_code before forwarding
        pat_code = _resolve_patient_code(d.get("patient_code", ""))
        if not pat_code:
            return jsonify({"error": "Patient username is required"}), 400
        try:
            r = http.post(
                f"{DOCTOR_PORTAL}/api/request_access",
                json={
                    "doctor_code": session.get("doctor_code", ""),
                    "patient_code": pat_code,
                    "password": d.get("password", ""),
                },
                cookies={"session": request.cookies.get("session", "")},
                headers=_fwd_headers(), timeout=10,
            )
            return jsonify(r.json()), r.status_code
        except (http.exceptions.ConnectionError, http.exceptions.Timeout):
            # Fallback: call backend request-access endpoint directly
            hdrs = {**_headers()}
            jwt = session.get("jwt_token", "")
            if jwt: hdrs["Authorization"] = f"Bearer {jwt}"
            rb = http.post(f"{BACKEND}/request_access",
                json={"doctor_code": session.get("doctor_code", ""),
                      "patient_code": pat_code},
                headers=hdrs, timeout=10)
            return jsonify(rb.json()), rb.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Fetch & decrypt patient record ─────────────────────────────────────────
@app.route("/doctor/fetch_record", methods=["POST"])
def doctor_fetch_record():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        # Resolve username → profile_code before forwarding
        pat_code = _resolve_patient_code(d.get("patient_code", ""))
        if not pat_code:
            return jsonify({"error": "Patient username is required"}), 400
        try:
            r = http.post(
                f"{DOCTOR_PORTAL}/api/fetch_record",
                json={
                    "doctor_code": session.get("doctor_code", ""),
                    "patient_code": pat_code,
                    "password": d.get("password", ""),
                },
                cookies={"session": request.cookies.get("session", "")},
                headers=_fwd_headers(), timeout=10,
            )
            return jsonify(r.json()), r.status_code
        except (http.exceptions.ConnectionError, http.exceptions.Timeout):
            return jsonify({"error": "Doctor Portal (port 5002) is not running. Please start it with: python portals/doctor_portal.py"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Shared helper: read EMR files directly (no JWT needed) ─────────────────
EMR_DATA_DIR = os.path.join(ROOT, "server", "emr_data")

def _read_emr_file(filename):
    """Read a JSON list from the EMR data directory. Returns [] on any error."""
    try:
        path = os.path.join(EMR_DATA_DIR, filename)
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _read_emr_profile(pat_code):
    """Return the patient's self-saved EMR profile dict, or {} if not found."""
    try:
        path = os.path.join(EMR_DATA_DIR, "emr_profiles.json")
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        return profiles.get(pat_code, {}) if isinstance(profiles, dict) else {}
    except Exception:
        return {}

def _fetch_timeline_for(pat_code):
    """Return notes, prescriptions and lab_reports for pat_code, each sorted newest-first."""
    # ── Doctor notes via backend API (uses API-key auth, not JWT) ──────────
    notes = []
    try:
        rn = http.get(f"{BACKEND}/doctor_notes/patient/{pat_code}",
                      headers=_headers(), timeout=8)
        if rn.ok:
            nd = rn.json()
            notes = nd.get("notes", nd) if isinstance(nd, dict) else nd
            if not isinstance(notes, list):
                notes = []
            for n in notes:
                if "note_id" not in n and "id" in n:
                    n["note_id"] = n["id"]
    except Exception:
        pass
    notes.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # ── Prescriptions — read JSON directly (no JWT needed) ─────────────────
    all_rx = _read_emr_file("emr_prescriptions.json")
    prescriptions = [r for r in all_rx if r.get("patient_id") == pat_code]
    prescriptions.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # ── Lab reports — read JSON directly ───────────────────────────────────
    all_labs = _read_emr_file("emr_lab_reports.json")
    lab_reports = [r for r in all_labs if r.get("patient_id") == pat_code]
    lab_reports.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return notes, prescriptions, lab_reports


# ── Doctor: patient medical timeline ───────────────────────────────────────
@app.route("/doctor/patient_timeline/<username>", methods=["GET"])
def doctor_patient_timeline(username):
    """All clinical notes + prescriptions + lab reports for a patient (doctor view)."""
    err = _doctor_session_check()
    if err: return err

    pat_code = _resolve_patient_code(username)
    if not pat_code:
        return jsonify({"error": "Patient not found"}), 404

    notes, prescriptions, lab_reports = _fetch_timeline_for(pat_code)
    emr_profile = _read_emr_profile(pat_code)
    return jsonify({
        "patient_code": pat_code,
        "emr_profile":  emr_profile,
        "notes": notes,
        "prescriptions": prescriptions,
        "lab_reports": lab_reports,
    }), 200


# ── Patient: own medical timeline ───────────────────────────────────────────
@app.route("/patient/timeline", methods=["GET"])
def patient_timeline_rich():
    """Return the logged-in patient's own notes + prescriptions + lab reports."""
    if not session.get("logged_in") or session.get("role") != "patient":
        return jsonify({"error": "unauthenticated"}), 401

    pat_code = session.get("profile_code", "")
    if not pat_code:
        return jsonify({"error": "No profile code in session"}), 400

    notes, prescriptions, lab_reports = _fetch_timeline_for(pat_code)
    emr_profile = _read_emr_profile(pat_code)
    return jsonify({
        "patient_code": pat_code,
        "emr_profile":  emr_profile,
        "notes": notes,
        "prescriptions": prescriptions,
        "lab_reports": lab_reports,
    }), 200


# ── Add clinical note ──────────────────────────────────────────────────────
@app.route("/doctor/add_note", methods=["POST"])
def doctor_add_note():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}

        # Resolve patient username → profile_code
        pat_code = _resolve_patient_code(d.get("patient_code", "").strip())
        if not pat_code:
            return jsonify({"error": "Patient username is required"}), 400

        doc_code = session.get("doctor_code", "")
        if not doc_code:
            return jsonify({"error": "Doctor code missing from session. Please log out and log in again."}), 401

        # Build note payload using session-cached doctor metadata
        # (avoids the fragile proxy → doctor_portal → password-verify chain)
        note_payload = {
            "patient_code":          pat_code,
            "doctor_code":           doc_code,
            "doctor_name":           session.get("name", ""),
            "doctor_specialization": session.get("specialization", ""),
            "doctor_hospital":       session.get("hospital", ""),
            "note_type":             d.get("note_type", "General"),
            "note_text":             d.get("note_text", ""),
            "visit_date":            d.get("visit_date", ""),
        }

        # POST directly to backend — no password re-verification needed
        # (user is already authenticated via Flask session)
        rb = http.post(
            f"{BACKEND}/doctor_notes/add",
            json=note_payload,
            headers=_headers(),
            timeout=30,
        )
        try:
            resp_data = rb.json()
        except Exception:
            resp_data = {
                "error": f"Backend error (HTTP {rb.status_code}). "
                         f"Ensure you have active approved access for patient '{pat_code}'."
            }
        return jsonify(resp_data), rb.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── List doctor notes for a patient ────────────────────────────────────────
@app.route("/doctor/notes/<patient_code>")
def doctor_notes_list(patient_code):
    err = _doctor_session_check()
    if err: return err
    try:
        doc_code = session.get("doctor_code", "")
        r = http.get(
            f"{DOCTOR_PORTAL}/api/doctor_notes/{patient_code}?doctor_code={doc_code}",
            cookies={"session": request.cookies.get("session", "")},
            headers=_fwd_headers(), timeout=10,
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Delete a note ──────────────────────────────────────────────────────────
@app.route("/doctor/delete_note/<note_id>", methods=["DELETE"])
def doctor_delete_note(note_id):
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        d["doctor_code"] = session.get("doctor_code", "")
        r = http.delete(
            f"{DOCTOR_PORTAL}/api/delete_note/{note_id}",
            json=d,
            cookies={"session": request.cookies.get("session", "")},
            headers=_fwd_headers(), timeout=10,
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Universal note image proxy (any logged-in user) ───────────────────────
@app.route("/note_images/<filename>")
def note_image_proxy(filename):
    if not session.get("logged_in"):
        return "Unauthorized", 401
    try:
        r = http.get(
            f"{BACKEND}/note_images/{filename}",
            headers=_headers(), timeout=10, stream=True,
        )
        if not r.ok:
            return "Not found", 404
        from flask import Response
        return Response(r.content, content_type=r.headers.get("Content-Type", "image/jpeg"))
    except Exception as e:
        return str(e), 502

# ── Doctor-portal note image proxy (kept for backwards compatibility) ───────
@app.route("/doctor/note_images/<filename>")
def doctor_note_image(filename):
    return note_image_proxy(filename)


# ── Resolve patient username → profile_code (used by doctor EMR forms) ─────
@app.route("/api/resolve_patient", methods=["POST"])
def api_resolve_patient():
    """Accept a patient username or profile_code and return the profile_code."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    d = request.get_json(force=True) or {}
    raw = (d.get("username") or d.get("patient_code") or "").strip()
    if not raw:
        return jsonify({"error": "username required"}), 400
    resolved = _resolve_patient_code(raw)
    if resolved == raw:
        # Try to verify it actually exists as a patient profile_code on backend
        try:
            r = http.get(f"{BACKEND}/get_patient_public/{resolved}",
                         headers=_headers(), timeout=5)
            if not r.ok:
                return jsonify({"error": f"Patient '{raw}' not found"}), 404
        except Exception as e:
            return jsonify({"error": f"Backend error: {e}"}), 502
    return jsonify({"profile_code": resolved})


# ── QR data (just returns doctor code + name from session) ─────────────────
@app.route("/doctor/qr_data")
def doctor_qr_data():
    err = _doctor_session_check()
    if err: return err
    return jsonify({
        "doctor_code": session.get("doctor_code", ""),
        "name": session.get("name", ""),
    })


# ── Doctor reads patient notes from patient's LOCAL device ─────────────────
# Notes are deleted from the server once patient views them (decentralised
# model).  The doctor accesses the patient's local notes.json directly —
# this works because both are running on the same machine in this demo.
@app.route("/doctor/patient_notes/<patient_code>")
def doctor_patient_notes(patient_code):
    err = _doctor_session_check()
    if err: return err
    try:
        # Resolve username → profile_code (folder name on disk)
        resolved_code = _resolve_patient_code(patient_code)
        notes_file = os.path.join(USERS_DIR, resolved_code, "notes.json")
        if not os.path.exists(notes_file):
            return jsonify({"notes": [], "source": "local"}), 200
        notes = json.load(open(notes_file, encoding="utf-8"))
        if not isinstance(notes, list):
            notes = []
        # Sort newest first
        notes.sort(key=lambda n: n.get("created_at", ""), reverse=True)
        return jsonify({"notes": notes, "source": "local"}), 200
    except Exception as e:
        app.logger.exception("doctor_patient_notes error")
        return jsonify({"error": str(e), "notes": []}), 500


# ── Doctor: list all patients this doctor has (or had) access to ─────────────
@app.route("/doctor/my_patients", methods=["GET"])
def doctor_my_patients():
    """Return all patients the logged-in doctor has ever had access to,
    with active/expired status and timeline counts per patient."""
    err = _doctor_session_check()
    if err: return err

    from datetime import datetime as _dt, timezone as _tz, timedelta as _td

    doc_code   = session.get("doctor_code", "")
    SERVER_DIR = os.path.join(ROOT, "server")
    PATIENTS_DIR = os.path.join(SERVER_DIR, "Patients")

    # ── Load users_db so we can look up username → name ──────────────────
    users_db = {}
    try:
        users_db = json.load(open(os.path.join(SERVER_DIR, "users_db.json"), encoding="utf-8"))
    except Exception:
        pass

    # Build profile_code → {username, name} map
    code_to_info = {}
    for _email, _u in users_db.items():
        if isinstance(_u, dict) and _u.get("profile_code"):
            code_to_info[_u["profile_code"]] = {
                "username": _u.get("username", ""),
                "name":     _u.get("name", ""),
                "email":    _email,
            }

    # ── Scan active_requests for all entries for this doctor ──────────────
    requests_path = os.path.join(SERVER_DIR, "active_requests.json")
    all_requests = _load_json_safe(requests_path) if os.path.exists(requests_path) else []
    if not isinstance(all_requests, list):
        all_requests = []

    seen_codes = set()
    patients = []

    for req in all_requests:
        if req.get("doctor_code") != doc_code:
            continue
        pat_code = req.get("profile_code", "")
        if not pat_code or pat_code in seen_codes:
            continue
        seen_codes.add(pat_code)

        info = code_to_info.get(pat_code, {})
        username = info.get("username") or pat_code
        name     = info.get("name", "")

        # ── Resolve expiry from wrapped_keys dir ──────────────────────────
        expires_at = None
        approved_at = req.get("approved_at") or req.get("timestamp", "")
        wk_dir = os.path.join(PATIENTS_DIR, pat_code, "wrapped_keys")
        if os.path.isdir(wk_dir):
            for fn in os.listdir(wk_dir):
                if not fn.lower().endswith(".json"):
                    continue
                try:
                    wk = json.load(open(os.path.join(wk_dir, fn), encoding="utf-8"))
                    if wk.get("doctor_code", os.path.splitext(fn)[0]) != doc_code:
                        continue
                    expires_at = wk.get("temp_key_expires_at")
                    if not expires_at:
                        ua_str = wk.get("uploaded_at", "")
                        if ua_str:
                            ua = _dt.fromisoformat(ua_str)
                            expires_at = (ua + _td(hours=24)).isoformat()
                    break
                except Exception:
                    continue

        # ── Determine active/expired ──────────────────────────────────────
        now = _dt.now(_tz.utc)
        is_active = False
        if expires_at:
            try:
                exp = _dt.fromisoformat(expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=_tz.utc)
                is_active = exp > now
            except Exception:
                pass

        # ── Count EMR records ─────────────────────────────────────────────
        all_rx   = _read_emr_file("emr_prescriptions.json")
        all_labs = _read_emr_file("emr_lab_reports.json")
        rx_count  = sum(1 for r in all_rx   if r.get("patient_id") == pat_code)
        lab_count = sum(1 for r in all_labs if r.get("patient_id") == pat_code)

        # Notes — quick count from backend
        note_count = 0
        try:
            rn = http.get(f"{BACKEND}/doctor_notes/patient/{pat_code}",
                          headers=_headers(), timeout=5)
            if rn.ok:
                nd = rn.json()
                nl = nd.get("notes", nd) if isinstance(nd, dict) else nd
                note_count = len(nl) if isinstance(nl, list) else 0
        except Exception:
            pass

        patients.append({
            "patient_code": pat_code,
            "username":     username,
            "name":         name,
            "status":       "active" if is_active else "expired",
            "expires_at":   expires_at,
            "approved_at":  approved_at,
            "rx_count":     rx_count,
            "lab_count":    lab_count,
            "note_count":   note_count,
        })

    # Sort: active first, then by approved_at descending
    patients.sort(key=lambda p: (0 if p["status"] == "active" else 1, -(p.get("approved_at") or "").__len__()))
    return jsonify({"patients": patients}), 200


# ── Doctor access expiry: return how long this doctor's key is valid ────────
@app.route("/doctor/access_expiry/<patient_code>")
def doctor_access_expiry(patient_code):
    """Return temp_key_expires_at for the logged-in doctor's wrapped key.
    Falls back to uploaded_at + 24 h if temp_key_expires_at is absent."""
    err = _doctor_session_check()
    if err: return err
    try:
        from datetime import timezone as _tz, timedelta as _td
        doc_code   = session.get("doctor_code", "")
        # Resolve username → profile_code
        resolved_code = _resolve_patient_code(patient_code)
        SERVER_DIR = os.path.join(ROOT, "server")
        wk_dir     = os.path.join(SERVER_DIR, "Patients", resolved_code, "wrapped_keys")
        if not os.path.isdir(wk_dir):
            return jsonify({"expires_at": None}), 200
        for fn in os.listdir(wk_dir):
            if not fn.lower().endswith(".json"):
                continue
            try:
                data   = json.load(open(os.path.join(wk_dir, fn), encoding="utf-8"))
                stored = data.get("doctor_code", os.path.splitext(fn)[0])
                if stored != doc_code:
                    continue
                expires_at = data.get("temp_key_expires_at")
                # If the patient approved without specifying an expiry, fall back
                # to uploaded_at + 24 hours (the system default access window).
                if not expires_at:
                    uploaded_at = data.get("uploaded_at")
                    if uploaded_at:
                        from datetime import datetime as _dt
                        ua = _dt.fromisoformat(uploaded_at)
                        expires_at = (ua + _td(hours=24)).isoformat()
                return jsonify({"expires_at": expires_at}), 200
            except Exception:
                continue
        return jsonify({"expires_at": None}), 200
    except Exception as e:
        return jsonify({"expires_at": None, "error": str(e)}), 200


# ════════════════════════════════════════════════════════════════════════════
#   EMR MODULE PROXY ROUTES  (landing → backend /emr/*)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/emr/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def emr_proxy(subpath):
    """Generic proxy for all /emr/* endpoints on the backend."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401

    jwt_token = session.get("jwt_token", "")
    if not jwt_token:
        return jsonify({
            "error": "Session has no JWT token. Please log out and log in again to refresh your session."
        }), 401

    headers = {**_headers()}
    headers["Authorization"] = f"Bearer {jwt_token}"

    url = f"{BACKEND}/emr/{subpath}"
    try:
        if request.method == "GET":
            r = http.get(url, headers=headers, params=request.args, timeout=10)
        elif request.method == "DELETE":
            r = http.delete(url, headers=headers, json=request.get_json(silent=True), timeout=10)
        elif request.method == "PUT":
            r = http.put(url, headers=headers, json=request.get_json(force=True), timeout=10)
        else:  # POST
            r = http.post(url, headers=headers, json=request.get_json(force=True), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# Alias so dashboard JS can call /api/emr/* and land here too
@app.route("/api/emr/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def api_emr_proxy(subpath):
    """Alias of emr_proxy — dashboard JS sends requests to /api/emr/*."""
    return emr_proxy(subpath)


# ── Appointment proxy helpers ─────────────────────────────────────────────────
def _jwt_headers():
    """Headers with the session JWT for forwarding to the backend."""
    h = {**_headers()}
    jwt_token = session.get("jwt_token", "")
    if jwt_token:
        h["Authorization"] = f"Bearer {jwt_token}"
    return h


# Patient: submit an appointment request
@app.route("/api/patient/appointment-request", methods=["POST"])
def proxy_patient_appt_request():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    try:
        r = http.post(f"{BACKEND}/api/patient/appointment-request",
                      json=request.get_json(force=True) or {},
                      headers=_jwt_headers(), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# Patient: list their own appointment requests
@app.route("/api/patient/appointment-requests", methods=["GET"])
def proxy_patient_appt_list():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    try:
        r = http.get(f"{BACKEND}/api/patient/appointment-requests",
                     headers=_jwt_headers(), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# Doctor: list incoming appointment requests
@app.route("/api/doctor/appointment-requests", methods=["GET"])
def proxy_doctor_appt_list():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    try:
        r = http.get(f"{BACKEND}/api/doctor/appointment-requests",
                     headers=_jwt_headers(), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# Doctor: respond (accept / reject / complete) to an appointment request
@app.route("/api/doctor/appointment-requests/<req_id>/respond", methods=["POST"])
def proxy_doctor_appt_respond(req_id):
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    try:
        r = http.post(f"{BACKEND}/api/doctor/appointment-requests/{req_id}/respond",
                      json=request.get_json(force=True) or {},
                      headers=_jwt_headers(), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# Doctor: create a new appointment for a patient (resolves username → patient_id)
@app.route("/api/doctor/appointment-create", methods=["POST"])
def proxy_doctor_appt_create():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    d = request.get_json(force=True) or {}
    # Resolve patient username in patient_username field → profile_code
    raw = d.get("patient_username", "").strip()
    if raw:
        d["patient_id"] = _resolve_patient_code(raw)
    try:
        r = http.post(f"{BACKEND}/emr/appointments",
                      json=d,
                      headers=_jwt_headers(), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502



# ── Merged appointment endpoints (bypass JWT uid mismatch via session) ─────────

APPT_DB = os.path.join(ROOT, "server", "appointments_db.json")
EMR_APPT = os.path.join(ROOT, "server", "emr_data", "emr_appointments.json")
EMR_RX   = os.path.join(ROOT, "server", "emr_data", "emr_prescriptions.json")
EMR_LR   = os.path.join(ROOT, "server", "emr_data", "emr_lab_reports.json")
NOTES_DB = os.path.join(ROOT, "server", "doctor_notes.json")


def _load_json_safe(path):
    try:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []


def _save_json_safe(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


@app.route("/api/patient/appointments-merged", methods=["GET"])
def patient_appts_merged():
    """Returns all appointments for the logged-in patient from both stores."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid = session.get("profile_code", "")
    username = session.get("username", "")

    # Source 1: appointments_db (patient-requested)
    db = _load_json_safe(APPT_DB)
    pat_appts = [a for a in db
                 if a.get("patient_id") == pid
                 or a.get("patient_username") == username]

    # Normalize format and tag source
    for a in pat_appts:
        a.setdefault("source", "request")
        a.setdefault("date_display", f"{a.get('date', '')} {a.get('time', '')}")

    # Source 2: EMR appointments (doctor-created)
    emr = _load_json_safe(EMR_APPT)
    emr_pat = [a for a in emr if a.get("patient_id") == pid]
    for a in emr_pat:
        a.setdefault("source", "emr")
        a.setdefault("date_display", a.get("date_time", ""))
        a.setdefault("notes", a.get("reason", ""))
        a.setdefault("doctor_username", "Your Doctor")

    all_appts = pat_appts + emr_pat
    all_appts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify({"appointments": all_appts}), 200


@app.route("/api/doctor/appointments-merged", methods=["GET"])
def doctor_appts_merged():
    """Returns all appointments for the logged-in doctor from both stores."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    doc_code = session.get("doctor_code", "")
    username  = session.get("username", "")

    # Source 1: appointments_db (patient-requested)
    db = _load_json_safe(APPT_DB)
    req_appts = [a for a in db
                 if a.get("doctor_username") == username
                 or a.get("doctor_id") == doc_code]
    for a in req_appts:
        a.setdefault("source", "request")
        a.setdefault("date_display", f"{a.get('date', '')} {a.get('time', '')}")

    # Source 2: EMR appointments (doctor-created)
    emr = _load_json_safe(EMR_APPT)
    emr_doc = [a for a in emr if a.get("doctor_id") == doc_code]
    for a in emr_doc:
        a.setdefault("source", "emr")
        a.setdefault("date_display", a.get("date_time", ""))
        a.setdefault("notes", a.get("reason", ""))
        # Resolve patient username from patient_id
        pat_username = a.get("patient_id", "")
        if pat_username == _resolve_patient_code(pat_username):
            # It's a profile_code — try to reverse-map
            users = _load_json_safe(os.path.join(ROOT, "server", "users_db.json")) if os.path.exists(os.path.join(ROOT, "server", "users_db.json")) else {}
            if isinstance(users, dict):
                for u in users.values():
                    if u.get("profile_code") == a.get("patient_id"):
                        pat_username = u.get("username", a.get("patient_id", ""))
                        break
        a["patient_username"] = pat_username

    all_appts = req_appts + emr_doc
    all_appts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify({"appointments": all_appts}), 200


@app.route("/api/patient/timeline", methods=["GET"])
def patient_timeline():
    """Returns full chronological timeline for the logged-in patient."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid      = session.get("profile_code", "")
    username = session.get("username", "")

    events = []

    # Prescriptions
    for rx in _load_json_safe(EMR_RX):
        if rx.get("patient_id") == pid:
            events.append({
                "type": "prescription", "icon": "💊",
                "title": rx.get("diagnosis", "Prescription"),
                "detail": f"Medications: {', '.join(m.get('name','') for m in rx.get('medications', []))}",
                "date": rx.get("created_at", ""),
                "id": rx.get("id", "")
            })

    # Lab Reports
    for lr in _load_json_safe(EMR_LR):
        if lr.get("patient_id") == pid:
            events.append({
                "type": "lab_report", "icon": "🧪",
                "title": lr.get("report_type", "Lab Report"),
                "detail": lr.get("notes", ""),
                "date": lr.get("created_at", ""),
                "id": lr.get("id", "")
            })

    # Appointments (both stores)
    for a in _load_json_safe(APPT_DB):
        if a.get("patient_id") == pid or a.get("patient_username") == username:
            events.append({
                "type": "appointment", "icon": "📅",
                "title": f"Appointment with Dr. {a.get('doctor_username', '—')}",
                "detail": f"{a.get('date', '')} {a.get('time', '')} — {a.get('notes', '')} [{a.get('status','pending')}]",
                "date": a.get("created_at", ""),
                "id": a.get("id", "")
            })
    for a in _load_json_safe(EMR_APPT):
        if a.get("patient_id") == pid:
            events.append({
                "type": "appointment", "icon": "📅",
                "title": f"Scheduled Appointment",
                "detail": f"{a.get('date_time', '')} — {a.get('reason', '')} [{a.get('status','scheduled')}]",
                "date": a.get("created_at", ""),
                "id": a.get("id", "")
            })

    # Doctor Notes
    for n in _load_json_safe(NOTES_DB):
        if n.get("patient_code") == pid or n.get("patient_username") == username:
            events.append({
                "type": "note", "icon": "📝",
                "title": f"Note from Dr. {n.get('doctor_name', '—')}",
                "detail": n.get("note_text", ""),
                "date": n.get("created_at", ""),
                "id": n.get("note_id", "")
            })

    # Sort newest first
    events.sort(key=lambda x: x.get("date", ""), reverse=True)
    return jsonify({"timeline": events}), 200


@app.route("/api/patient/prescriptions-direct", methods=["GET"])
def patient_prescriptions_direct():
    """Returns all prescriptions for the logged-in patient directly from file (no JWT needed)."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid = session.get("profile_code", "")
    rxs = [r for r in _load_json_safe(EMR_RX) if r.get("patient_id") == pid]
    rxs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify(rxs), 200


@app.route("/api/patient/lab-reports-direct", methods=["GET"])
def patient_lab_reports_direct():
    """Returns all lab reports for the logged-in patient directly from file (no JWT needed)."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid = session.get("profile_code", "")
    lrs = [r for r in _load_json_safe(EMR_LR) if r.get("patient_id") == pid]
    lrs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify(lrs), 200


@app.route("/api/patient/emr-profile-direct", methods=["GET", "POST"])
def patient_emr_profile_direct():
    """Read or update the EMR profile for the logged-in patient directly from file."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid = session.get("profile_code", "")
    EMR_PROFILES = os.path.join(ROOT, "server", "emr_data", "emr_profiles.json")
    profiles = _load_json_safe(EMR_PROFILES)
    if not isinstance(profiles, list):
        profiles = []

    if request.method == "POST":
        d = request.get_json(force=True) or {}
        d["patient_id"] = pid
        # Update existing or insert
        updated = False
        for i, p in enumerate(profiles):
            if p.get("patient_id") == pid:
                profiles[i] = {**p, **d}
                updated = True
                break
        if not updated:
            profiles.append(d)
        _save_json_safe(EMR_PROFILES, profiles)
        return jsonify({"status": "saved"}), 200

    profile = next((p for p in profiles if p.get("patient_id") == pid), {})
    return jsonify({"profile_code": pid, **profile}), 200



@app.route("/api/patient/appointment-request-submit", methods=["POST"])
def patient_appt_submit():
    """Patient submits an appointment request — stored directly with correct profile_code."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    d = request.get_json(force=True) or {}
    import uuid
    from datetime import datetime, timezone
    pid      = session.get("profile_code", "")
    username = session.get("username", "")
    name     = session.get("name", "")
    entry = {
        "id": str(uuid.uuid4()),
        "patient_id": pid,
        "patient_username": username,
        "patient_name": name,
        "doctor_username": d.get("doctor_username", "").strip(),
        "date": d.get("date", "").strip(),
        "time": d.get("time", "").strip(),
        "notes": d.get("notes", "").strip(),
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    db = _load_json_safe(APPT_DB)
    db.append(entry)
    _save_json_safe(APPT_DB, db)
    return jsonify({"message": "requested", "appointment": entry}), 201


@app.route("/api/doctor/appointment-respond/<req_id>", methods=["POST"])
def doctor_appt_respond(req_id):
    """Doctor accepts/rejects/completes an appointment request in appointments_db."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    d = request.get_json(force=True) or {}
    status = d.get("status")
    if status not in ("accepted", "rejected", "completed"):
        return jsonify({"error": "invalid_status"}), 400
    from datetime import datetime, timezone
    db = _load_json_safe(APPT_DB)
    found = False
    for a in db:
        if a["id"] == req_id:
            a["status"] = status
            a["updated_at"] = datetime.now(timezone.utc).isoformat()
            found = True
            break
    if not found:
        # Try EMR appointments
        emr = _load_json_safe(EMR_APPT)
        for a in emr:
            if a["id"] == req_id:
                a["status"] = status
                a["updated_at"] = datetime.now(timezone.utc).isoformat()
                found = True
                break
        if found:
            _save_json_safe(EMR_APPT, emr)
            return jsonify({"message": "updated"}), 200
        return jsonify({"error": "not_found"}), 404
    _save_json_safe(APPT_DB, db)
    return jsonify({"message": "updated"}), 200



# ── Run ───────────────────────────────────────────────────────────────────────

# ── Missing page routes ───────────────────────────────────────────────────────
@app.route("/prescriptions")
def page_prescriptions():
    if not session.get("logged_in"): return redirect("/")
    ctx = _page_context()
    return render_template("prescriptions.html", **ctx)

@app.route("/lab-reports")
def page_lab_reports():
    if not session.get("logged_in"): return redirect("/")
    ctx = _page_context()
    return render_template("lab_reports.html", **ctx)

@app.route("/emr")
def page_emr():
    if not session.get("logged_in"): return redirect("/")
    ctx = _page_context()
    return render_template("emr.html", **ctx)

@app.route("/my-patients")
def page_my_patients():
    if not session.get("logged_in"): return redirect("/")
    ctx = _page_context()
    return render_template("my_patients.html", **ctx)

@app.route("/patient-detail")
def page_patient_detail():
    if not session.get("logged_in"): return redirect("/")
    code = request.args.get("code", "")
    ctx  = _page_context()
    ctx["patient_code"] = code
    return render_template("patient_detail.html", **ctx)


# ── Patient QR code proxy ─────────────────────────────────────────────────────
@app.route("/api/patient/qr")
def proxy_patient_qr():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    # Generate QR data: profile_code + username in JSON
    pid      = session.get("profile_code", "")
    username = session.get("username", "")
    name     = session.get("name", "")
    return jsonify({
        "profile_code": pid,
        "username":     username,
        "name":         name,
        "qr_data":      json.dumps({"profile_code": pid, "username": username, "name": name}),
    })


# ── Patient search (doctor only) ─────────────────────────────────────────────
@app.route("/api/users/search")
def proxy_users_search():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    if session.get("role") != "doctor":
        return jsonify({"error": "forbidden"}), 403
    q = request.args.get("q", "")
    try:
        r = http.get(f"{BACKEND}/users/search",
                     params={"q": q, "role": "patient"},
                     headers=_jwt_headers(), timeout=8)
        if r.ok:
            return jsonify(r.json()), 200
        return jsonify({"users": []}), 200
    except Exception as e:
        return jsonify({"error": str(e), "users": []}), 200


# ── Patient: revoke an approved access grant ──────────────────────────────────
@app.route("/patient/revoke", methods=["POST"])
def patient_revoke():
    err = _patient_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        # Use the access/respond endpoint with action=revoke
        r = http.post(
            f"{BACKEND}/access/respond",
            json={"request_id": d.get("request_id"), "action": "revoke"},
            headers=_jwt_headers(), timeout=10,
        )
        if r.ok:
            return jsonify({"message": "revoked"}), 200
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Doctor: my patients list (approved + pending) ─────────────────────────────
@app.route("/doctor/my_requests", methods=["GET"])
def doctor_my_requests():
    err = _doctor_session_check()
    if err: return err
    try:
        r = http.get(f"{BACKEND}/access/doctor_patients",
                     headers=_jwt_headers(), timeout=8)
        if r.ok:
            data = r.json()
            reqs = data if isinstance(data, list) else data.get("requests", data.get("patients", []))
            return jsonify({"requests": reqs}), 200
        # Fallback: read local access_requests.json
        ar_path = os.path.join(ROOT, "server", "access_requests.json")
        if os.path.exists(ar_path):
            all_reqs = json.load(open(ar_path, encoding="utf-8"))
            doc_code = session.get("doctor_code", "")
            mine = [req for req in all_reqs if req.get("doctor_code") == doc_code]
            return jsonify({"requests": mine}), 200
        return jsonify({"requests": []}), 200
    except Exception as e:
        return jsonify({"error": str(e), "requests": []}), 200


if __name__ == "__main__":
    print("  🌐  Landing Page → http://127.0.0.1:5003")
    app.run(host="127.0.0.1", port=5003, debug=True, threaded=True)


