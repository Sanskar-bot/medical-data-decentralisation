#!/usr/bin/env python3
"""
landing.py â€” MedVault Unified Landing Page (port 5003)

Serves:
  GET  /              â†’ Landing page (Login / Sign Up)
  POST /login         â†’ Authenticate via backend, set Flask session
  POST /register/patient â†’ Register patient, set session
  POST /register/doctor  â†’ Register doctor, set session
  GET  /dashboard     â†’ Protected role-based dashboard
  GET  /logout        â†’ Clear session, redirect to /
"""
import os, sys, json, secrets, string, hashlib, re
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from auth_utils import hash_password, check_password, cors_after_request, get_server_api_key
try:
    import psycopg2
    import psycopg2.extras
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False
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

# â”€â”€ App setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€ Template context: inject `now` for dashboard greeting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from datetime import datetime as _datetime
@app.context_processor
def _inject_now():
    return {'now': _datetime.now()}

# â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
BACKEND     = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")
USERS_DIR   = os.path.join(ROOT, "client", "Users")
DOCTORS_DIR = os.path.join(ROOT, "doctor", "Doctors")
DB_URL      = os.environ.get("DATABASE_URL",
    "postgresql://medvault_user:StrongPassword123!@127.0.0.1:5432/medvault")
os.makedirs(USERS_DIR,   exist_ok=True)
os.makedirs(DOCTORS_DIR, exist_ok=True)

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _api_key():
    return get_server_api_key()

def _headers():
    return {"X-API-Key": _api_key(), "Content-Type": "application/json"}

def _user_json_path(profile_code):
    return os.path.join(USERS_DIR, profile_code, "user_data.json")

def _require_session():
    """Redirect to landing if not logged in."""
    if not session.get("logged_in"):
        return redirect(url_for("landing"))
    return None


def _refresh_jwt():
    """Re-issue a fresh JWT for the currently logged-in user by re-calling the backend login.
    Returns the new token string on success, or None on failure.
    This is called automatically when the backend returns invalid_or_expired_token.
    """
    email    = session.get("email", "")
    username = session.get("username", "")
    password = session.get("_pw_cache", "")   # only set if user opted to cache
    role     = session.get("role", "")

    # Strategy 1: re-issue JWT from backend using stored credentials
    if email and password:
        try:
            r = http.post(f"{BACKEND}/login",
                          json={"email": email, "password": password},
                          headers=_headers(), timeout=10)
            if r.ok:
                tok = r.json().get("token") or r.json().get("access_token", "")
                if tok:
                    session["jwt_token"] = tok
                    return tok
        except Exception:
            pass

    # Strategy 2: ask the backend to reissue based on username (no-pw path, some deployments)
    if username:
        try:
            r = http.post(f"{BACKEND}/api/refresh_token",
                          json={"username": username, "role": role},
                          headers=_headers(), timeout=10)
            if r.ok:
                tok = r.json().get("token") or r.json().get("access_token", "")
                if tok:
                    session["jwt_token"] = tok
                    return tok
        except Exception:
            pass

    return None



# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#   ROUTES
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/health")
def health_check():
    return jsonify({"status": "ok"}), 200

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


# â”€â”€ ADDITIONAL PAGE ROUTES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        # Bug 1: cross-device key availability flag
        key_available=session.get("key_available", True),
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


@app.route("/admin/doctors")
def admin_create_doctor_page():
    guard = _require_session()
    if guard: return guard
    if session.get("role") not in ("admin", "receptionist"):
        return redirect(url_for("dashboard"))
    return render_template("admin_create_doctor.html", **_page_context())


@app.route("/admin/doctors", methods=["POST"])
def admin_create_doctor_proxy():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    if session.get("role") not in ("admin", "receptionist"):
        return jsonify({"error": "Only verified team members can create doctor accounts."}), 403
    jwt_tok = session.get("jwt_token", "")
    if not jwt_tok:
        return jsonify({"error": "Session expired. Please sign in again."}), 401
    try:
        r = http.post(
            f"{BACKEND}/admin/doctors",
            json=request.get_json(force=True) or {},
            headers={**_headers(), "Authorization": f"Bearer {jwt_tok}"},
            timeout=20,
        )
        try:
            return jsonify(r.json()), r.status_code
        except Exception:
            return jsonify({"error": "Backend returned an unreadable response."}), r.status_code
    except Exception as e:
        return jsonify({"error": f"Cannot reach backend: {e}"}), 502


@app.route("/encounter/<encounter_id>")
def encounter_detail(encounter_id):
    """Render the read-only encounter detail page.

    Session-authenticated (same pattern as /health-record, /emr, etc.).
    Proxies to GET /emr/encounters/<id>/bundle using the session JWT, then
    renders encounter_detail.html with the bundle data.
    """
    guard = _require_session()
    if guard: return guard
    jwt_tok = session.get("jwt_token", "")
    hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
    try:
        r = http.get(f"{BACKEND}/emr/encounters/{encounter_id}/bundle",
                     headers=hdrs, timeout=10)
        if r.status_code == 404:
            return render_template("base.html", error="Encounter not found."), 404
        if r.status_code == 403:
            return render_template("base.html", error="Access denied."), 403
        if not r.ok:
            return render_template("base.html",
                                   error=f"Could not load encounter ({r.status_code})."), 502
        bundle = r.json()
    except Exception as e:
        app.logger.warning("encounter_detail proxy failed: %s", e)
        return render_template("base.html",
                               error="Backend unreachable. Ensure the server is running."), 503
    return render_template("encounter_detail.html", bundle=bundle, **_page_context())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# â”€â”€ LOGIN â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/login", methods=["POST"])
def login():
    try:
        d = request.get_json(force=True) or {}
        # Accept either email or username in the same field
        identifier = (d.get("email") or d.get("username") or "").strip().lower()
        password   = d.get("password") or ""

        if not identifier or not password:
            return jsonify({"error": "Username/email and password are required"}), 400


        # Send raw password to backend â€” server handles both SHA-256 and werkzeug
        try:
            r = http.post(
                f"{BACKEND}/auth/login",
                json={"email": identifier, "password": password},
                headers=_headers(),
                timeout=10,
            )
            data = r.json()
        except Exception as e:
            return jsonify({"error": f"Cannot reach backend: {e}"}), 502

        # â”€â”€ Legacy hash detected: surface as upgrade_required â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if r.status_code == 403 and data.get("error") == "password_reset_required":
            return jsonify({
                "upgrade_required": True,
                "identifier": identifier,
                "old_hash": hashlib.sha256(password.encode()).hexdigest(),
                "message": "Your account uses an outdated password format. Set a new password to continue.",
            }), 403

        if r.status_code == 403 and data.get("error") == "password_change_required":
            return jsonify({
                "password_change_required": True,
                "temp_token": data.get("temp_token", ""),
                "message": "Welcome to MedVault. Choose your own password to finish setting up your account.",
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
        # Cache password in encrypted session for silent JWT refresh on expiry
        session["_pw_cache"]    = password
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

        # ── Bug 1: Cross-device key availability check ────────────────────────
        # After login, test whether the private key is available on THIS device.
        # This flag drives UI degradation and recovery CTAs across all templates.
        _key_id = None
        if role == "patient" and pcode:
            _key_id = f"patient__{pcode}"
        elif role == "doctor" and dcode:
            _key_id = f"doctor__{dcode}"
        if _key_id:
            try:
                session["key_available"] = SecureKeyStore.exists(_key_id)
            except Exception:
                session["key_available"] = False
        else:
            session["key_available"] = True  # non-crypto roles always available

        return jsonify({"message": "ok", "redirect": "/dashboard",
                        "role": session["role"],
                        "key_available": session.get("key_available", True)})
    except Exception as e:
        app.logger.exception("Login error")
        return jsonify({"error": str(e)}), 500


# â”€â”€ Password upgrade proxy (legacy SHA-256 â†’ werkzeug pbkdf2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/auth/set_initial_password", methods=["POST"])
def set_initial_password():
    try:
        d = request.get_json(force=True) or {}
        temp_token = (d.get("temp_token") or "").strip()
        new_pw = d.get("new_password") or ""
        if not temp_token or not new_pw:
            return jsonify({"error": "Missing fields."}), 400
        if len(new_pw) < 8:
            return jsonify({"error": "Password must be at least 8 characters."}), 400

        try:
            r = http.post(
                f"{BACKEND}/auth/set_initial_password",
                json={"temp_token": temp_token, "new_password": new_pw},
                headers=_headers(),
                timeout=10,
            )
            data = r.json()
        except Exception as e:
            return jsonify({"error": f"Cannot reach backend: {e}"}), 502

        if not r.ok:
            human = {
                "invalid_or_expired_token": "This setup session expired. Please sign in with the temporary password again.",
                "password_too_short": "Password must be at least 8 characters.",
                "password_already_set": "This account already has its password set. Please sign in normally.",
            }.get(data.get("error"), data.get("error", "Could not set password."))
            return jsonify({"error": human}), r.status_code

        session.clear()
        role = data.get("role", "patient")
        pcode = data.get("profile_code", "")
        dcode = data.get("doctor_code", "") or (pcode if role == "doctor" else "")
        session["logged_in"] = True
        session["role"] = role
        session["name"] = data.get("name", "")
        session["email"] = data.get("email", "")
        session["username"] = data.get("username", "")
        session["user_id"] = data.get("user_id", "")
        session["profile_code"] = pcode if role == "patient" else ""
        session["doctor_code"] = dcode if role == "doctor" else ""
        session["jwt_token"] = data.get("access_token", "")
        session["_pw_cache"] = new_pw
        session.permanent = True
        return jsonify({"message": "ok", "redirect": "/dashboard"})
    except Exception as e:
        app.logger.exception("set_initial_password error")
        return jsonify({"error": str(e)}), 500


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
                "not_legacy": "Account already upgraded â€” just sign in normally.",
            }.get(err, err)
            return jsonify({"error": human}), r.status_code

        # Upgrade succeeded â€” now log the user in by re-using the new token from the response
        # Immediately call login with the new password to populate session
        r2 = http.post(
            f"{BACKEND}/auth/login",
            json={"email": identifier, "password": new_pw},
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




# â”€â”€ REGISTER PATIENT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # â”€â”€ Generate RSA keypair + encrypt record â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # Unique profile code â€” MUST be alphanumeric only (Windows CredWrite rejects '+', '/', etc.)
        _CHARS = string.ascii_uppercase + string.digits
        profile_code = ''.join(secrets.choice(_CHARS) for _ in range(10))
        pdir = os.path.join(USERS_DIR, profile_code)
        os.makedirs(pdir, exist_ok=True)

        # Local user data â€” all values are JSON-serializable (strings/dicts)
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
            "password_hash": hash_password(password),
            "jwt_token": "",
        }
        with open(_user_json_path(profile_code), "w", encoding="utf-8") as f:
            json.dump(local, f, indent=2, ensure_ascii=False)

        # Store private key in Windows Credential Manager (DPAPI-backed)
        SecureKeyStore.store_private_key(f"patient__{profile_code}", priv_pem)

        with open(os.path.join(pdir, "patient_public.pem"), "wb") as f:
            f.write(pub_pem)

        # â”€â”€ Register on backend (best-effort â€” don't crash if backend is slow) â”€
        try:
            http.post(
                f"{BACKEND}/register_user",
                json={"profile_code": profile_code, "encrypted_record": enc,
                      "signature": sig, "patient_public_pem": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
        except Exception as e:
            app.logger.warning("backend /register_user failed: %s", e)

        # â”€â”€ Create users_db entry (enables /auth/login after logout) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            resp = http.post(
                f"{BACKEND}/internal/register_user_db",
                json={"email": email, "username": username, "name": name, "role": "patient",
                      "password_hash": hash_password(password),
                      "profile_code": profile_code,
                      "public_key": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
            if resp.status_code == 409:
                return jsonify({"error": resp.json().get("error", "Username or email is already taken. Try a different username.")}), 409
        except Exception as e:
            app.logger.warning("backend /internal/register_user_db failed: %s", e)

        # â”€â”€ Set session â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        session.clear()
        session["logged_in"]    = True
        session["role"]         = "patient"
        session["name"]         = name
        session["email"]        = email
        session["username"]     = username
        session["profile_code"] = profile_code
        session["doctor_code"]  = ""
        session.permanent       = True

        # â”€â”€ Fetch JWT immediately so EMR endpoints work right away â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            _lr = http.post(
                f"{BACKEND}/auth/login",
                json={"email": email, "password": password},
                headers=_headers(), timeout=10,
            )
            if _lr.ok:
                _lr_data = _lr.json()
                session["jwt_token"] = _lr_data.get("access_token", "")
                session["user_id"]   = _lr_data.get("user_id", "")
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


# â”€â”€ REGISTER DOCTOR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # â”€â”€ Generate RSA keypair â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # â”€â”€ Register on backend (best-effort) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            http.post(
                f"{BACKEND}/register_doctor",
                json={"doctor_id": doctor_id, "doctor_code": doctor_code,
                      "public_pem": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
        except Exception as e:
            app.logger.warning("backend /register_doctor failed: %s", e)

        # â”€â”€ Create users_db entry (enables /auth/login after logout) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            resp = http.post(
                f"{BACKEND}/internal/register_user_db",
                json={"email": email, "username": username, "name": name, "role": "doctor",
                      "password_hash": hash_password(password),
                      "profile_code": doctor_code,
                      "doctor_code": doctor_code,
                      "public_key": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
            if resp.status_code == 409:
                return jsonify({"error": resp.json().get("error", "Username or email is already taken. Try a different username.")}), 409
        except Exception as e:
            app.logger.warning("backend register_user_db failed: %s", e)

        # â”€â”€ Set session â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # â”€â”€ Fetch JWT immediately so EMR endpoints work right away â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            _lr = http.post(
                f"{BACKEND}/auth/login",
                json={"email": email, "password": password},
                headers=_headers(), timeout=10,
            )
            if _lr.ok:
                _lr_data = _lr.json()
                session["jwt_token"] = _lr_data.get("access_token", "")
                session["user_id"]   = _lr_data.get("user_id", "")
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#   PATIENT API ROUTES  (called by dashboard.html via fetch)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _patient_session_check():
    if not session.get("logged_in") or session.get("role") != "patient":
        return jsonify({"error": "unauthenticated"}), 401
    return None

# â”€â”€ Load decrypted patient record â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/patient/record", methods=["GET", "POST"])
def patient_record():
    """Return (and optionally update) the patient's personal health record.
    Supports both legacy local-file users and new PostgreSQL-only users.
    """
    err = _patient_session_check()
    if err: return err
    try:
        d            = request.get_json(force=True) or {}
        pw           = d.get("password", "")
        update_data  = d.get("update", None)
        profile_code = session.get("profile_code", "")
        email        = session.get("email", "")
        upath        = _user_json_path(profile_code)

        # Path A: Legacy local-file user
        if os.path.exists(upath):
            try:
                from common.crypto_utils import (
                    derive_kek_from_password, unwrap_key_with_kek,
                )
                local = json.load(open(upath, encoding="utf-8"))
                kp    = local.get("key_protection", {})
                if kp and "salt_b64" in kp and "wrapped_k" in kp:
                    try:
                        salt   = b64decode(kp["salt_b64"])
                        kek, _ = derive_kek_from_password(pw, salt=salt)
                        unwrap_key_with_kek(kek, kp["wrapped_k"])
                    except Exception:
                        return jsonify({"error": "Wrong password - please try again."}), 401
                    if update_data:
                        details = local.get("patient_details", {})
                        details.update({k: v for k, v in update_data.items() if v is not None})
                        local["patient_details"] = details
                        with open(upath, "w", encoding="utf-8") as fw:
                            json.dump(local, fw, indent=2)
                        return jsonify({"record": details, "profile_code": profile_code})
                    return jsonify({"record": local.get("patient_details", {}),
                                    "profile_code": profile_code})
            except Exception as le:
                app.logger.warning("patient_record local-file path: %s", le)

        # Path B: New-system PostgreSQL-only user - verify password via backend
        if pw:
            try:
                vr = http.post(f"{BACKEND}/auth/login",
                               json={"email": email, "password": pw},
                               headers=_headers(), timeout=10)
                if not vr.ok:
                    try: err_body = vr.json()
                    except Exception: err_body = {}
                    err_str = err_body.get("error", "")
                    if "credentials" in err_str or "invalid" in err_str:
                        return jsonify({"error": "Wrong password - please try again."}), 401
            except Exception:
                pass  # backend unreachable - allow through

        if _HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(DB_URL)
                cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute(
                    "SELECT name, email, patient_details FROM users "
                    "WHERE profile_code=%s LIMIT 1",
                    (profile_code,)
                )
                row = cur.fetchone()
                if row is not None:
                    details = row.get("patient_details") or {}
                    if isinstance(details, str):
                        try: details = json.loads(details)
                        except Exception: details = {}
                    if not details.get("name") and row.get("name"):
                        details["name"] = row["name"]
                    if not details.get("email") and row.get("email"):
                        details["email"] = row["email"]
                    if update_data:
                        details.update({k: v for k, v in update_data.items() if v is not None})
                        cur.execute(
                            "UPDATE users SET patient_details=%s WHERE profile_code=%s",
                            (json.dumps(details), profile_code)
                        )
                        conn.commit()
                    cur.close(); conn.close()
                    return jsonify({"record": details, "profile_code": profile_code})
                cur.close(); conn.close()
            except Exception as de:
                app.logger.warning("patient_record DB path: %s", de)

        # Fallback: return session-cached info
        return jsonify({
            "record": {"name": session.get("name", ""), "email": email},
            "profile_code": profile_code,
        })
    except Exception as e:
        app.logger.exception("patient_record error")
        return jsonify({"error": str(e)}), 500


@app.route("/patient/requests")
def patient_requests():
    err = _patient_session_check()
    if err: return err
    try:
        profile_code = session.get("profile_code", "")
        jwt          = session.get("jwt_token", "")
        normalized   = []
        seen_ids     = set()

        # â”€â”€ Source 1: PostgreSQL via JWT /access/patient_requests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if jwt:
            try:
                hdrs = {**_headers(), "Authorization": f"Bearer {jwt}"}
                r = http.get(f"{BACKEND}/access/patient_requests", headers=hdrs, timeout=8)
                if r.ok:
                    db_reqs = r.json() if isinstance(r.json(), list) else r.json().get("requests", [])
                    for x in db_reqs:
                        rid = str(x.get("id", x.get("request_id", "")))
                        if rid in seen_ids:
                            continue
                        seen_ids.add(rid)
                        normalized.append({
                            "id":           rid,
                            "request_id":   rid,
                            "doctor_code":  x.get("doctor_code", x.get("doctor_email", "")),
                            "doctor_name":  x.get("doctor_name", x.get("doctor_email", "Doctor")),
                            "status":       x.get("status", "pending"),
                            "requested_at": x.get("created_at", x.get("requested_at", "")),
                        })
            except Exception as e:
                app.logger.debug("patient_requests JWT source: %s", e)

        # (Legacy flat-file /active_requests removed â€” PostgreSQL is the source of truth)

        # â”€â”€ Source 3: Direct PostgreSQL query (most reliable) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if _HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(DB_URL)
                cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                # Get patient UUID from profile_code
                cur.execute(
                    "SELECT id FROM users WHERE profile_code=%s AND role='patient' LIMIT 1",
                    (profile_code,)
                )
                pt = cur.fetchone()
                if pt:
                    cur.execute("""
                        SELECT a.id, a.status, a.created_at, a.responded_at,
                               a.doctor_id, a.doctor_email,
                               u.doctor_code, u.name AS doctor_name, u.username AS doctor_username
                        FROM access_db a
                        LEFT JOIN users u ON a.doctor_id = u.id
                        WHERE a.patient_id = %s
                        ORDER BY a.created_at DESC
                    """, (str(pt["id"]),))
                    rows = cur.fetchall()
                    for x in rows:
                        rid = str(x["id"])
                        if rid in seen_ids:
                            continue
                        seen_ids.add(rid)
                        doc_display = (x.get("doctor_name") or x.get("doctor_username") or
                                       x.get("doctor_email") or "Doctor")
                        doc_code    = (x.get("doctor_code") or x.get("doctor_email") or
                                       str(x.get("doctor_id", "")))
                        responded   = x.get("responded_at")
                        normalized.append({
                            "id":           rid,
                            "request_id":   rid,
                            "doctor_code":  doc_code,
                            "doctor_name":  doc_display,
                            "status":       x.get("status", "pending"),
                            "requested_at": x["created_at"].isoformat() if hasattr(x.get("created_at"), "isoformat") else str(x.get("created_at", "")),
                            "responded_at": responded.isoformat() if responded and hasattr(responded, "isoformat") else str(responded or ""),
                        })
                cur.close(); conn.close()
            except Exception as e:
                app.logger.debug("patient_requests psycopg2 source: %s", e)

        return jsonify({"requests": normalized})

    except Exception as e:
        return jsonify({"error": str(e)}), 502



# â”€â”€ Approve access request â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/patient/approve", methods=["POST"])
def patient_approve():
    err = _patient_session_check()
    if err: return err
    try:
        d            = request.get_json(force=True) or {}
        pw           = d.get("password", "")
        request_id   = d.get("request_id", "")
        doc_code     = d.get("doctor_code", "")
        profile_code = session.get("profile_code", "")
        jwt_tok      = session.get("jwt_token", "")

        if not pw:
            return jsonify({"error": "Password is required"}), 400
        if not request_id:
            return jsonify({"error": "Request ID is required"}), 400

        # â”€â”€ Verify the patient's password before approving â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        upath = _user_json_path(profile_code)
        if os.path.exists(upath):
            try:
                from common.crypto_utils import derive_kek_from_password, unwrap_key_with_kek
                local = json.load(open(upath, encoding="utf-8"))
                kp    = local.get("key_protection", {})
                salt  = b64decode(kp["salt_b64"])
                kek, _ = derive_kek_from_password(pw, salt=salt)
                unwrap_key_with_kek(kek, kp["wrapped_k"])  # raises if wrong password
            except (KeyError, ValueError, Exception) as e:
                if "password" in str(e).lower() or "decrypt" in str(e).lower() or "tag" in str(e).lower():
                    return jsonify({"error": "Wrong password"}), 401
                # No local profile â€” allow without crypto verification (new-system user)
        # else: new-system user with no local profile â€” skip password crypto check
        # (their password was already verified on login via JWT)

        # â”€â”€ Path 1: New system â€” JWT /access/respond â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if jwt_tok:
            try:
                hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
                rb = http.post(
                    f"{BACKEND}/access/respond",
                    json={"request_id": request_id, "action": "approve"},
                    headers=hdrs, timeout=10,
                )
                try:
                    data = rb.json()
                except Exception:
                    data = {"status": "approved"} if rb.ok else {"error": f"Backend {rb.status_code}"}
                if rb.ok:
                    return jsonify({"status": "approved", "message": "Access granted successfully"}), 200
                # If 404, fall through to legacy path
                if rb.status_code != 404:
                    return jsonify(data), rb.status_code
            except Exception as e:
                app.logger.debug("patient_approve JWT path: %s", e)
        # -- Fallback: direct psycopg2 approve (ownership verified via profile_code) --
        if _HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(DB_URL)
                cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute("""
                    UPDATE access_db a SET status='approved', responded_at=NOW()
                    FROM users p
                    WHERE a.patient_id = p.id
                      AND p.profile_code = %s
                      AND a.id = %s
                    RETURNING a.id, a.status
                """, (profile_code, request_id))
                updated = cur.fetchone()
                conn.commit(); cur.close(); conn.close()
                if updated:
                    return jsonify({"status": "approved", "message": "Access granted"}), 200
                return jsonify({"error": "Access request not found or not yours"}), 404
            except Exception as e:
                app.logger.debug("patient_approve psycopg2 fallback: %s", e)

        return jsonify({"status": "approved", "message": "Access granted"}), 200
    except Exception as e:
        app.logger.exception("patient_approve error")
        return jsonify({"error": str(e)}), 500


# ── Bug 1: Cross-device key recovery endpoints ──────────────────────────────

@app.route("/api/patient/key-status", methods=["GET"])
def patient_key_status():
    """
    Report whether the patient's private key is available on this device.
    Updates session['key_available'] on every call so it stays fresh.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    profile_code = session.get("profile_code", "")
    doc_code     = session.get("doctor_code", "")
    role         = session.get("role", "patient")
    key_id = (f"patient__{profile_code}" if role == "patient" and profile_code
              else f"doctor__{doc_code}" if role == "doctor" and doc_code
              else None)
    available = True
    if key_id:
        try:
            available = SecureKeyStore.exists(key_id)
        except Exception:
            available = False
    session["key_available"] = available
    return jsonify({
        "available": available,
        "message": "Key present on this device." if available else (
            "Your encryption key is not available on this device. "
            "Use the key recovery option to restore access."
        ),
    }), 200


@app.route("/api/patient/encrypted-key", methods=["GET"])
def patient_get_encrypted_key():
    """
    Return the encrypted_private_key blob stored in the users DB.
    The frontend decrypts it client-side using the user's password (Web Crypto API),
    then sends the PEM to /api/patient/reimport-key. Never returns plaintext.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    user_id = session.get("user_id", "")
    email   = session.get("email", "")
    if not _HAS_PSYCOPG2:
        return jsonify({"error": "Database not available"}), 503
    try:
        conn = psycopg2.connect(DB_URL)
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT encrypted_private_key FROM users WHERE id=%s OR email=%s LIMIT 1",
            (user_id, email)
        )
        row = cur.fetchone()
        cur.close(); conn.close()
        if not row:
            return jsonify({"error": "User not found"}), 404
        epk = row.get("encrypted_private_key")
        if not epk:
            return jsonify({"error": "No encrypted key stored. Key recovery requires the original device."}), 404
        return jsonify({"encrypted_private_key": epk}), 200
    except Exception as e:
        app.logger.exception("get_encrypted_key error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/patient/reimport-key", methods=["POST"])
def patient_reimport_key():
    """
    Re-import a private key onto this device via DPAPI.

    Request body: { "pem": "<plaintext RSA private key PEM>" }

    The frontend decrypts the encrypted_private_key blob (from /api/patient/encrypted-key)
    using the user's password in-browser, then POSTs the plaintext PEM here.
    This endpoint stores it via DPAPI and immediately discards the PEM from memory.
    The server never logs or persists the plaintext key.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    role         = session.get("role", "patient")
    profile_code = session.get("profile_code", "")
    doc_code     = session.get("doctor_code", "")
    try:
        body = request.get_json(force=True) or {}
        pem  = (body.get("pem") or "").strip()
        if not pem:
            return jsonify({"error": "pem is required"}), 400
        if not pem.startswith("-----BEGIN"):
            return jsonify({"error": "pem must be a valid PEM-encoded private key"}), 400
        key_id = (f"patient__{profile_code}" if role == "patient" and profile_code
                  else f"doctor__{doc_code}" if role == "doctor" and doc_code
                  else None)
        if not key_id:
            return jsonify({"error": "Could not determine key identifier for this account"}), 400
        SecureKeyStore.store_private_key(key_id, pem.encode())
        session["key_available"] = True
        return jsonify({"message": "Key successfully restored on this device.", "key_available": True}), 200
    except Exception as e:
        app.logger.exception("reimport_key error")
        return jsonify({"error": str(e)}), 500


# -- Deny access request -------------------------------------------------------
@app.route("/patient/deny", methods=["POST"])
def patient_deny():
    err = _patient_session_check()
    if err: return err
    try:
        d       = request.get_json(force=True) or {}
        jwt_tok = session.get("jwt_token", "")
        request_id = d.get("request_id", "")
        if not request_id:
            return jsonify({"error": "Request ID required"}), 400
        profile_code = session.get("profile_code", "")

        # â”€â”€ Use JWT /access/respond (PostgreSQL) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if jwt_tok:
            hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
            try:
                rb = http.post(f"{BACKEND}/access/respond",
                               json={"request_id": request_id, "action": "deny"},
                               headers=hdrs, timeout=8)
                if rb.ok:
                    try:
                        return jsonify(rb.json()), 200
                    except Exception:
                        return jsonify({"status": "denied"}), 200
                # 404 â†’ fall through to psycopg2 fallback
                if rb.status_code != 404:
                    try:
                        return jsonify(rb.json()), rb.status_code
                    except Exception:
                        return jsonify({"error": f"Backend {rb.status_code}"}), rb.status_code
            except Exception as e:
                app.logger.debug("patient_deny JWT path: %s", e)

        # â”€â”€ Fallback: direct psycopg2 update (with ownership check) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if _HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(DB_URL)
                cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute("""
                    UPDATE access_db a SET status='denied', responded_at=NOW()
                    FROM users p
                    WHERE a.patient_id = p.id
                      AND p.profile_code = %s
                      AND a.id = %s
                    RETURNING a.id, a.status
                """, (profile_code, request_id))
                updated = cur.fetchone()
                conn.commit(); cur.close(); conn.close()
                if updated:
                    return jsonify({"status": "denied"}), 200
                return jsonify({"error": "Access request not found or not yours"}), 404
            except Exception as e:
                app.logger.debug("patient_deny psycopg2: %s", e)

        return jsonify({"error": "Could not deny request"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# -- Doctor notes (pull -> save locally -> delete from server) -----------------
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

        # Build dedup set — handle both 'id' and 'note_id' key names
        local_ids = set()
        for n in local_notes:
            nid = n.get("id") or n.get("note_id")
            if nid:
                local_ids.add(nid)

        # 2. Fetch new notes from server (temporary relay)
        # BUG FIX: backend returns a plain JSON list, NOT {"notes": [...]}
        # Calling .get("notes", []) on a list raises AttributeError (silently caught
        # as except Exception -> server_notes = []), so notes were never fetched.
        try:
            r = http.get(f"{BACKEND}/doctor_notes/patient/{profile_code}",
                         headers=_headers(), timeout=8)
            if r.ok:
                body = r.json()
                server_notes = body if isinstance(body, list) else body.get("notes", [])
            else:
                server_notes = []
        except Exception:
            server_notes = []

        # 3. Pull each new note onto the patient's device
        newly_pulled = []
        for note in server_notes:
            # BUG FIX: backend field is 'note_id', not 'id'
            note_id = note.get("note_id") or note.get("id") or ""
            if not note_id:
                continue  # skip malformed notes

            if note_id in local_ids:
                # Already saved locally -- still delete the server copy
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
                        with open(local_img_path, "wb") as fimg:
                            fimg.write(ri.content)
                    else:
                        img_filename = ""   # image unavailable
                except Exception:
                    img_filename = ""

            # BUG FIX: normalise both 'id' and 'note_id' keys so dedup works on next sync
            local_note = {**note, "id": note_id, "note_id": note_id,
                          "image_filename": img_filename}
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


# â”€â”€ Login history â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# ——— Full audit log proxy ————————————————————————————————————————————————————————————
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




# ——— Patient: list all registered doctors ————————————————————————————————————————————
@app.route("/patient/doctors", methods=["GET"])
def patient_list_doctors():
    """Return all registered doctors from PostgreSQL users table."""
    doctors = []
    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("""
                SELECT id, username, email, name, doctor_code,
                       specialization, hospital
                FROM users WHERE role='doctor'
                ORDER BY LOWER(COALESCE(name, username, email))
            """)
            for row in cur.fetchall():
                doctors.append({
                    "doctor_code":    row.get("doctor_code") or str(row["id"]),
                    "name":           row.get("name") or row.get("username") or "",
                    "username":       row.get("username") or "",
                    "email":          row.get("email") or "",
                    "specialization": row.get("specialization") or "",
                    "hospital":       row.get("hospital") or "",
                })
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("patient_list_doctors psycopg2: %s", e)
    return jsonify({"doctors": doctors}), 200


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#   DOCTOR API ROUTES  (called by dashboard.html via fetch)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

DOCTOR_PORTAL = "http://127.0.0.1:5002"

def _doctor_session_check():
    if not session.get("logged_in") or session.get("role") != "doctor":
        return jsonify({"error": "unauthenticated"}), 401
    return None

def _resolve_patient_code(username_or_code: str) -> str:
    """Resolve a patient username OR profile_code to a valid profile_code.
    Source of truth: PostgreSQL users table.
    Falls back to returning the raw value so raw profile_codes still work.
    """
    if not username_or_code:
        return username_or_code
    raw = username_or_code.strip()

    # â”€â”€ 1. Direct PostgreSQL query (primary) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                """SELECT profile_code FROM users
                   WHERE (LOWER(username)=LOWER(%s) OR LOWER(email)=LOWER(%s))
                   AND role='patient' LIMIT 1""",
                (raw, raw)
            )
            row = cur.fetchone()
            cur.close(); conn.close()
            if row and row.get("profile_code"):
                return row["profile_code"]
        except Exception as e:
            app.logger.debug("_resolve_patient_code psycopg2: %s", e)

    # â”€â”€ 2. Backend HTTP resolve (fallback) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        r = http.get(f"{BACKEND}/api/resolve_username/{raw}",
                     headers=_headers(), timeout=5)
        if r.ok:
            pc = r.json().get("profile_code") or r.json().get("patient_code") or ""
            if pc:
                return pc
    except Exception as e:
        app.logger.debug("_resolve_patient_code backend: %s", e)

    # Fallback: treat as raw profile_code
    return raw


def _resolve_patient_uuid_or_code(patient_code: str) -> tuple[str, str]:
    """Resolve a patient identifier to (profile_code, patient_id).
    Supports username, email, profile_code, patient UUID, or access_db request id.
    """
    if not patient_code:
        return "", ""
    raw = patient_code.strip()
    profile_code = ""
    patient_id = ""
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # If the input is a request UUID, resolve it to the associated patient.
            if re.match(uuid_pattern, raw.lower()):
                cur.execute(
                    "SELECT patient_id FROM access_db WHERE id::text=%s LIMIT 1",
                    (raw,)
                )
                row = cur.fetchone()
                if row and row.get("patient_id"):
                    patient_id = str(row["patient_id"])
                    if re.match(uuid_pattern, patient_id.lower()):
                        cur.execute(
                            "SELECT profile_code FROM users WHERE id::text=%s LIMIT 1",
                            (patient_id,)
                        )
                        user_row = cur.fetchone()
                        if user_row and user_row.get("profile_code"):
                            profile_code = user_row["profile_code"]
                        else:
                            profile_code = patient_id
                    else:
                        profile_code = patient_id

            if not profile_code:
                profile_code = _resolve_patient_code(raw)

            if profile_code:
                cur.execute(
                    "SELECT id FROM users WHERE profile_code=%s LIMIT 1",
                    (profile_code,)
                )
                user_row = cur.fetchone()
                if user_row and user_row.get("id"):
                    patient_id = str(user_row["id"])

            if not patient_id:
                cur.execute(
                    """SELECT id, profile_code FROM users
                       WHERE id::text=%s OR profile_code=%s OR LOWER(username)=LOWER(%s) OR LOWER(email)=LOWER(%s)
                       LIMIT 1""",
                    (raw, raw, raw, raw)
                )
                user_row = cur.fetchone()
                if user_row:
                    patient_id = str(user_row.get("id", ""))
                    profile_code = profile_code or user_row.get("profile_code", "")

            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("_resolve_patient_uuid_or_code psycopg2: %s", e)

    return profile_code or raw, patient_id or raw


def _require_active_access(doctor_code: str, patient_code: str = None):
    """Return None if the logged-in doctor has active approved patient access."""
    err = _doctor_session_check()
    if err:
        return err

    # Backward-compatible until existing call sites are wired to pass doctor_code.
    if patient_code is None:
        patient_code = doctor_code
        doctor_code = session.get("doctor_code", "")

    if not patient_code:
        return jsonify({"error": "patient_code_required"}), 400

    doc_code = session.get("doctor_code", "") or doctor_code
    if not doc_code:
        return jsonify({"error": "unauthenticated"}), 401

    profile_code = _resolve_patient_code(patient_code)
    if not profile_code:
        return jsonify({"error": "patient_not_found"}), 404

    if not _HAS_PSYCOPG2:
        return jsonify({"error": "no_database"}), 500

    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute(
            "SELECT id FROM users WHERE doctor_code=%s OR LOWER(username)=LOWER(%s) LIMIT 1",
            (doc_code, doc_code)
        )
        doc_row = cur.fetchone()
        if not doc_row:
            cur.close(); conn.close()
            return jsonify({"error": "doctor_not_found"}), 403

        doctor_uuid = str(doc_row["id"])
        cur.execute(
            """
            SELECT a.status, a.responded_at, wk.temp_key_expires_at
            FROM access_db a
            LEFT JOIN users p ON a.patient_id::text = p.id::text
            LEFT JOIN wrapped_keys wk ON wk.profile_code = p.profile_code AND wk.doctor_code = %s
            WHERE (a.doctor_id::text = %s OR a.doctor_id::text = %s)
              AND (p.profile_code = %s OR a.patient_id::text = %s)
            ORDER BY a.responded_at DESC NULLS LAST, a.created_at DESC
            LIMIT 1
            """,
            (doc_code, doctor_uuid, doc_code, profile_code, profile_code)
        )
        row = cur.fetchone()
        cur.close(); conn.close()
    except Exception as e:
        app.logger.debug("_require_active_access psycopg2: %s", e)
        return jsonify({"error": "access_check_failed", "detail": str(e)}), 500

    if not row:
        return jsonify({"error": "access_denied", "message": "You do not have access to this patient."}), 403

    if row.get("status") != "approved":
        return jsonify({"error": "access_not_approved", "message": "Access to this patient is not approved."}), 403

    expires_at = row.get("temp_key_expires_at")
    if not expires_at:
        responded_at = row.get("responded_at")
        if not responded_at:
            return jsonify({"error": "access_expired", "message": "Your access to this patient has expired."}), 403
        expires_at = responded_at + _td(hours=24)

    if isinstance(expires_at, str):
        try:
            expires_at = _dt.fromisoformat(expires_at)
        except Exception:
            expires_at = None

    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=_tz.utc)

    if expires_at and expires_at < _dt.now(_tz.utc):
        return jsonify({"error": "access_expired", "message": "Your access to this patient has expired."}), 403

    return None


def _fwd_headers():
    """Build headers that carry the Flask session cookie to doctor_portal."""
    h = {"Content-Type": "application/json", "X-API-Key": _api_key()}
    return h


# â”€â”€ Load doctor profile (verify password + get profile details) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ Request patient access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/request_access", methods=["POST"])
# ── Request patient access ─────────────────────────────────────────────────────────
@app.route("/doctor/request_access", methods=["POST"])
def doctor_request_access():
    """Send an access request to a patient - no password required.
    Uses the JWT-authenticated /access/request endpoint on the backend.
    """
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        raw_code = d.get("profile_code") or d.get("patient_code") or ""
        pat_code = _resolve_patient_code(raw_code.strip())
        if not pat_code:
            return jsonify({"error": "Patient identifier is required"}), 400

        jwt = session.get("jwt_token", "")
        if not jwt:
            return jsonify({"error": "Doctor session expired - please log in again"}), 401

        patient_uid = None
        if _HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(DB_URL)
                cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute(
                    "SELECT id FROM users WHERE profile_code=%s AND role='patient' LIMIT 1",
                    (pat_code,)
                )
                row = cur.fetchone()
                cur.close(); conn.close()
                if row:
                    patient_uid = str(row["id"])
            except Exception as e:
                app.logger.warning("doctor_request_access uid lookup: %s", e)

        if not patient_uid:
            try:
                rx = http.get(
                    f"{BACKEND}/api/resolve_username/{raw_code.strip()}",
                    headers=_headers(), timeout=5
                )
                if rx.ok:
                    patient_uid = rx.json().get("id") or rx.json().get("uid") or pat_code
            except Exception:
                patient_uid = pat_code

        hdrs = {**_headers(), "Authorization": f"Bearer {jwt}"}
        rb = http.post(
            f"{BACKEND}/access/request",
            json={"patient_id": patient_uid},
            headers=hdrs, timeout=10,
        )

        if rb.status_code == 401:
            try:
                err_str = rb.json().get("error", "")
            except Exception:
                err_str = ""
            if "expired" in err_str or "invalid" in err_str:
                new_tok = _refresh_jwt()
                if new_tok:
                    hdrs["Authorization"] = f"Bearer {new_tok}"
                    rb = http.post(
                        f"{BACKEND}/access/request",
                        json={"patient_id": patient_uid},
                        headers=hdrs, timeout=10,
                    )

        try:
            data = rb.json()
        except Exception:
            if rb.ok:
                data = {"message": "Access request sent successfully"}
            else:
                data = {"error": f"Backend error ({rb.status_code}): {rb.text[:200]}"}
        return jsonify(data), rb.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502




# â”€â”€ Fetch & decrypt patient record â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/fetch_record", methods=["POST"])
def doctor_fetch_record():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        # Accept either key name â€” JS sends 'profile_code', older callers send 'patient_code'
        raw_code = d.get("profile_code") or d.get("patient_code") or ""
        pat_code, _ = _resolve_patient_uuid_or_code(raw_code.strip())
        if not pat_code:
            return jsonify({"error": "Patient identifier is required"}), 400

        err = _require_active_access(session.get("doctor_code", ""), pat_code)
        if err:
            return err

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


# â”€â”€ Shared helper: read EMR files directly (no JWT needed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    # â”€â”€ Doctor notes via backend API (uses API-key auth, not JWT) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # â”€â”€ Prescriptions â€” read JSON directly (no JWT needed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    all_rx = _read_emr_file("emr_prescriptions.json")
    prescriptions = [r for r in all_rx if r.get("patient_id") == pat_code]
    prescriptions.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # â”€â”€ Lab reports â€” read JSON directly â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    all_labs = _read_emr_file("emr_lab_reports.json")
    lab_reports = [r for r in all_labs if r.get("patient_id") == pat_code]
    lab_reports.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return notes, prescriptions, lab_reports


# â”€â”€ Doctor: patient medical timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/patient_timeline/<username>", methods=["GET"])
def doctor_patient_timeline(username):
    """All clinical notes + prescriptions + lab reports for a patient (doctor view)."""
    err = _doctor_session_check()
    if err: return err

    pat_code = _resolve_patient_code(username)
    if not pat_code:
        return jsonify({"error": "Patient not found"}), 404

    err = _require_active_access(session.get("doctor_code", ""), pat_code)
    if err:
        return err

    notes, prescriptions, lab_reports = _fetch_timeline_for(pat_code)
    emr_profile = _read_emr_profile(pat_code)
    return jsonify({
        "patient_code": pat_code,
        "emr_profile":  emr_profile,
        "notes": notes,
        "prescriptions": prescriptions,
        "lab_reports": lab_reports,
    }), 200


# â”€â”€ Patient: own medical timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# -- Add clinical note ----------------------------------------------------------
@app.route("/doctor/add_note", methods=["POST"])
def doctor_add_note():
    err = _doctor_session_check()
    if err: return err
    try:
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        d = request.get_json(force=True) or {}

        pat_code = _resolve_patient_code(
            (d.get("patient_code") or d.get("profile_code") or "").strip()
        )
        if not pat_code:
            return jsonify({"error": "Patient username is required"}), 400

        doc_code = session.get("doctor_code", "")
        if not doc_code:
            return jsonify({"error": "Doctor code missing from session. Please log out and log in again."}), 401

        err = _require_active_access(doc_code, pat_code)
        if err:
            return err

        # visit_date always uses server UTC time - prevents backdating
        server_visit_date = _dt.utcnow().strftime("%Y-%m-%d")

        note_payload = {
            "patient_code":          pat_code,
            "doctor_code":           doc_code,
            "doctor_name":           session.get("name", ""),
            "doctor_specialization": session.get("specialization", ""),
            "doctor_hospital":       session.get("hospital", ""),
            "note_type":             d.get("note_type", "General"),
            "note_text":             d.get("note_text", ""),
            "visit_date":            server_visit_date,
        }

        jwt_tok = session.get("jwt_token", "")
        hdrs = {**_headers()}
        if jwt_tok:
            hdrs["Authorization"] = f"Bearer {jwt_tok}"
        rb = http.post(
            f"{BACKEND}/doctor_notes/add",
            json=note_payload,
            headers=hdrs,
            timeout=30,
        )
        try:
            resp_data = rb.json()
        except Exception:
            resp_data = {
                "error": (
                    f"Backend error (HTTP {rb.status_code}). "
                    f"Ensure you have active approved access for patient '{pat_code}'."
                )
            }

        # Audit log on success
        if rb.status_code in (200, 201) and _HAS_PSYCOPG2:
            try:
                conn2 = psycopg2.connect(DB_URL)
                cur2  = conn2.cursor()
                cur2.execute(
                    "INSERT INTO audit_log (action, actor, target, detail, ip) "
                    "VALUES (%s,%s,%s,%s,%s)",
                    (
                        "ADD_CLINICAL_NOTE",
                        doc_code,
                        pat_code,
                        f"note_type={note_payload['note_type']}, visit_date={server_visit_date}",
                        request.remote_addr or "",
                    )
                )
                conn2.commit()
                cur2.close(); conn2.close()
            except Exception as _al:
                app.logger.debug("doctor_add_note audit log: %s", _al)

        return jsonify(resp_data), rb.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/doctor/notes/<patient_code>")
def doctor_notes_list(patient_code):
    err = _doctor_session_check()
    if err: return err

    resolved_code = _resolve_patient_code(patient_code)
    err = _require_active_access(session.get("doctor_code", ""), resolved_code)
    if err:
        return err

    try:
        doc_code = session.get("doctor_code", "")
        r = http.get(
            f"{DOCTOR_PORTAL}/api/doctor_notes/{resolved_code}?doctor_code={doc_code}",
            cookies={"session": request.cookies.get("session", "")},
            headers=_fwd_headers(), timeout=10,
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# â”€â”€ Delete a note â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/delete_note/<note_id>", methods=["DELETE"])
def doctor_delete_note(note_id):
    err = _doctor_session_check()
    if err: return err

    note_patient_code = None
    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT patient_code FROM doctor_notes WHERE note_id=%s LIMIT 1",
                (note_id,)
            )
            note_row = cur.fetchone()
            if note_row:
                note_patient_code = note_row.get("patient_code")
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("doctor_delete_note note lookup: %s", e)

    if note_patient_code:
        resolved_note_patient_code = _resolve_patient_code(note_patient_code)
        err = _require_active_access(session.get("doctor_code", ""), resolved_note_patient_code)
        if err:
            return err

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


# â”€â”€ Universal note image proxy (any logged-in user) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€ Doctor-portal note image proxy (kept for backwards compatibility) â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/note_images/<filename>")
def doctor_note_image(filename):
    return note_image_proxy(filename)


# â”€â”€ Resolve patient username â†’ profile_code (used by doctor EMR forms) â”€â”€â”€â”€â”€
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
        import re as _re
        looks_like_code = bool(_re.match(r'^[A-Za-z0-9]{8,12}$', resolved)) and not resolved.islower()
        if looks_like_code:
            # Treat as a profile code â€” verify it exists on backend
            try:
                r = http.get(f"{BACKEND}/get_patient_public/{resolved.upper()}",
                             headers=_headers(), timeout=5)
                if not r.ok:
                    return jsonify({"error": f"No patient found with code '{raw}'"}), 404
                resolved = resolved.upper()
            except Exception as e:
                return jsonify({"error": f"Backend error: {e}"}), 502
        else:
            # Username lookup failed across all 4 strategies
            return jsonify({
                "error": f"No patient with username \'{raw}\' was found. "
                         "Please check the spelling or ask the patient for their 10-character profile code."
            }), 404
    return jsonify({"profile_code": resolved})


# â”€â”€ QR data (just returns doctor code + name from session) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/qr_data")
def doctor_qr_data():
    err = _doctor_session_check()
    if err: return err
    return jsonify({
        "doctor_code": session.get("doctor_code", ""),
        "name": session.get("name", ""),
    })


# â”€â”€ Doctor reads patient notes from patient's LOCAL device â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Notes are deleted from the server once patient views them (decentralised
# model).  The doctor accesses the patient's local notes.json directly â€”
# this works because both are running on the same machine in this demo.
@app.route("/doctor/patient_notes/<patient_code>")
def doctor_patient_notes(patient_code):
    err = _doctor_session_check()
    if err: return err

    resolved_code = _resolve_patient_code(patient_code)
    err = _require_active_access(session.get("doctor_code", ""), resolved_code)
    if err:
        return err
    try:
        # Resolve username â†’ profile_code (folder name on disk)
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


# â”€â”€ Doctor: list all patients this doctor has (or had) access to â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/my_patients", methods=["GET"])
def doctor_my_patients():
    """Return all patients the doctor has access to, sourced from PostgreSQL."""
    err = _doctor_session_check()
    if err: return err

    from datetime import datetime as _dt, timezone as _tz

    doc_code = session.get("doctor_code", "")
    jwt_tok  = session.get("jwt_token", "")
    patients = []

    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Get doctor's UUID
            cur.execute(
                "SELECT id FROM users WHERE doctor_code=%s OR LOWER(username)=LOWER(%s) LIMIT 1",
                (doc_code, doc_code)
            )
            doc_row = cur.fetchone()
            if not doc_row and jwt_tok:
                # fallback: get uid from JWT payload
                pass

            if doc_row:
                cur.execute("""
                    SELECT a.id as req_id, a.status, a.created_at,
                           p.profile_code, p.username, p.name, p.email
                    FROM access_db a
                    JOIN users p ON a.patient_id = p.id
                    WHERE a.doctor_id = %s
                    ORDER BY a.created_at DESC
                """, (str(doc_row["id"]),))
                seen = set()
                for row in cur.fetchall():
                    pc = row.get("profile_code", "")
                    if pc in seen:
                        continue
                    seen.add(pc)
                    ca = row.get("created_at")
                    ts = ca.isoformat() if ca else ""
                    patients.append({
                        "profile_code":  pc,
                        "patient_code":  pc,         # alias for templates
                        "username":      row.get("username") or pc,
                        "name":          row.get("name") or "",
                        "email":         row.get("email") or "",
                        "status":        row.get("status", "pending"),
                        "approved_at":   ts,
                        "requested_at":  ts,         # alias for templates
                        "timestamp":     ts,         # alias for templates
                        "is_active":     row.get("status") == "approved",
                        "expires_at":    "",
                        "rx_count":      0,
                        "lab_count":     0,
                        "note_count":    0,
                    })
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("doctor_my_patients psycopg2: %s", e)

    # If psycopg2 unavailable, try JWT endpoint
    if not patients and jwt_tok:
        try:
            hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
            r = http.get(f"{BACKEND}/access/doctor_patients", headers=hdrs, timeout=8)
            if r.ok:
                for p in (r.json() if isinstance(r.json(), list) else []):
                    patients.append({
                        "profile_code": p.get("profile_code", ""),
                        "username":     p.get("username", ""),
                        "name":         p.get("name", ""),
                        "email":        p.get("email", ""),
                        "status":       p.get("status", "approved"),
                        "approved_at":  p.get("approved_at", ""),
                        "is_active":    True,
                        "expires_at":   "",
                        "rx_count":     0,
                        "lab_count":    0,
                    })
        except Exception as e:
            app.logger.debug("doctor_my_patients JWT: %s", e)

    # Sort: approved first, then by created_at descending
    patients.sort(key=lambda p: (0 if p.get("is_active") else 1, p.get("approved_at", "") or ""))
    return jsonify({"patients": patients}), 200



# â”€â”€ Doctor access expiry: return how long this doctor's key is valid â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/access_expiry/<patient_code>")
def doctor_access_expiry(patient_code):
    """Return temp_key_expires_at for the logged-in doctor's wrapped key.
    Falls back to uploaded_at + 24 h if temp_key_expires_at is absent."""
    err = _doctor_session_check()
    if err: return err
    try:
        from datetime import timezone as _tz, timedelta as _td
        doc_code   = session.get("doctor_code", "")
        # Resolve username â†’ profile_code
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


# Doctor: respond to appointment — URL that appointments.html frontend actually calls.
# The route /api/doctor/appointment-requests/<id>/respond above is the backend-proxy
# variant; this one works directly on the local JSON store so it never needs a
# backend round-trip for patient-submitted requests.
@app.route("/api/doctor/appointment-respond/<req_id>", methods=["POST"])
def doctor_appt_respond_direct(req_id):
    """Accept / reject / complete an appointment.

    Primary  → update appointments_db.json (patient-submitted requests).
    Fallback → forward to backend PostgreSQL via JWT.
    """
    if not session.get("logged_in") or session.get("role") != "doctor":
        return jsonify({"error": "unauthenticated"}), 401

    d      = request.get_json(force=True) or {}
    status = d.get("status", "")
    if status not in ("accepted", "rejected", "completed", "rescheduled"):
        return jsonify({"error": "invalid_status"}), 400

    username = session.get("username", "")
    doc_code = session.get("doctor_code", "")

    # ── Path 1: flat JSON file (patient-submitted appointments) ──────────────
    # _load_json_safe / _save_json_safe / APPT_DB are defined later in this
    # module but resolved at call-time, so referencing them here is safe.
    try:
        entries = _load_json_safe(APPT_DB)
        if not isinstance(entries, list):
            entries = []
        updated = False
        for entry in entries:
            if entry.get("id") == req_id and (
                entry.get("doctor_username", "").lower() == username.lower()
                or entry.get("doctor_id") == doc_code
            ):
                entry["status"] = status
                updated = True
                break
        if updated:
            _save_json_safe(APPT_DB, entries)
            return jsonify({"message": "updated"}), 200
    except Exception as _je:
        app.logger.debug("doctor_appt_respond_direct JSON path: %s", _je)

    # ── Path 2: backend PostgreSQL via JWT ────────────────────────────────────
    try:
        jwt_tok = session.get("jwt_token", "")
        if jwt_tok:
            hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
            r = http.post(
                f"{BACKEND}/api/doctor/appointment-requests/{req_id}/respond",
                json={"status": status},
                headers=hdrs,
                timeout=8,
            )
            if r.ok:
                return jsonify({"message": "updated"}), 200
            try:
                return jsonify(r.json()), r.status_code
            except Exception:
                return jsonify({"error": f"Backend {r.status_code}"}), r.status_code
    except Exception as _be:
        app.logger.debug("doctor_appt_respond_direct backend path: %s", _be)

    return jsonify({"error": "Appointment not found or not authorized"}), 404


@app.route("/api/patient/timeline", methods=["GET"])
def patient_timeline():
    """Returns full chronological timeline for the logged-in patient.

    Part C (option a chosen): reads from PostgreSQL via server.emr.store
    instead of stale flat JSON files (EMR_RX, EMR_LR, etc.).

    Events with an encounter_id are grouped under their encounter entry.
    Events without an encounter_id are returned as individual ungrouped
    items — this preserves backward compatibility for records created
    before the encounters table existed.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid = session.get("profile_code", "")
    if not pid:
        return jsonify({"timeline": []}), 200

    # Import emr.store here (not at module top) to avoid import-time DB init
    try:
        import sys as _sys
        import os as _os
        _server_dir = _os.path.join(ROOT, "server")
        if _server_dir not in _sys.path:
            _sys.path.insert(0, _server_dir)
        from emr import store as _emr_store
    except Exception as _ie:
        app.logger.warning("patient_timeline: cannot import emr.store: %s", _ie)
        return jsonify({"timeline": []}), 200

    # ── Collect all raw events from Postgres ──────────────────────────────────
    ungrouped = []   # events with no encounter_id
    encounter_ids_seen = set()
    encounters_map = {}  # encounter_id -> encounter dict

    try:
        # 1. Encounters — the primary grouping unit
        for enc in _emr_store.encounters_for_patient(pid):
            eid = enc["id"]
            encounter_ids_seen.add(eid)
            encounters_map[eid] = {
                "type":        "encounter",
                "encounter_id": eid,
                "status":      enc.get("status", "in_progress"),
                "reason":      enc.get("reason", ""),
                "doctor_id":   enc.get("doctor_id", ""),
                "date":        enc.get("started_at", enc.get("created_at", "")),
                "items":       [],
            }

        # 2. Prescriptions
        for rx in _emr_store.prescriptions_for_patient(pid):
            meds = rx.get("medications") or []
            med_names = ", ".join(m.get("name", "") for m in meds if m.get("name"))
            event = {
                "type":        "prescription",
                "title":       rx.get("diagnosis") or "Prescription",
                "detail":      f"Medications: {med_names}" if med_names else "",
                "date":        rx.get("created_at", ""),
                "id":          rx.get("id", ""),
                "encounter_id": rx.get("encounter_id"),
            }
            eid = rx.get("encounter_id")
            if eid and eid in encounters_map:
                encounters_map[eid]["items"].append(event)
            else:
                ungrouped.append(event)

        # 3. Lab reports
        for lr in _emr_store.lab_reports_for_patient(pid):
            event = {
                "type":        "lab_report",
                "title":       lr.get("report_type", "Lab Report"),
                "detail":      lr.get("notes", ""),
                "date":        lr.get("created_at", ""),
                "id":          lr.get("id", ""),
                "encounter_id": lr.get("encounter_id"),
            }
            eid = lr.get("encounter_id")
            if eid and eid in encounters_map:
                encounters_map[eid]["items"].append(event)
            else:
                ungrouped.append(event)

        # 4. EMR appointments
        for a in _emr_store.appointments_for_patient(pid):
            event = {
                "type":   "appointment",
                "title":  f"Appointment — {a.get('reason', 'Scheduled visit')}",
                "detail": f"{a.get('date_time', '')} [{a.get('status', 'scheduled')}]",
                "date":   a.get("created_at", ""),
                "id":     a.get("id", ""),
                "encounter_id": a.get("encounter_id"),
            }
            eid = a.get("encounter_id")
            if eid and eid in encounters_map:
                encounters_map[eid]["items"].append(event)
            else:
                ungrouped.append(event)

        # 5. Doctor notes (direct DB — doctor_notes is outside emr.store)
        if _HAS_PSYCOPG2:
            try:
                import psycopg2 as _pg2
                import psycopg2.extras as _pg2e
                _conn = _pg2.connect(DB_URL)
                _cur  = _conn.cursor(cursor_factory=_pg2e.RealDictCursor)
                _cur.execute(
                    "SELECT * FROM doctor_notes WHERE patient_code = %s ORDER BY created_at DESC",
                    (pid,)
                )
                for n in _cur.fetchall():
                    nd = dict(n)
                    for _k, _v in nd.items():
                        if hasattr(_v, "isoformat"):
                            nd[_k] = _v.isoformat()
                    event = {
                        "type":   "note",
                        "title":  f"Note from Dr. {nd.get('doctor_name', 'Unknown')}",
                        "detail": nd.get("note_text", ""),
                        "date":   nd.get("created_at", ""),
                        "id":     nd.get("note_id", ""),
                        "encounter_id": nd.get("encounter_id"),
                    }
                    eid = nd.get("encounter_id")
                    if eid and eid in encounters_map:
                        encounters_map[eid]["items"].append(event)
                    else:
                        ungrouped.append(event)
                _cur.close(); _conn.close()
            except Exception as _ne:
                app.logger.debug("patient_timeline notes fetch: %s", _ne)

    except Exception as _e:
        app.logger.warning("patient_timeline Postgres fetch failed: %s", _e)
        return jsonify({"timeline": []}), 200

    # ── Assemble final timeline ───────────────────────────────────────────────
    # Encounter groups come first (sorted by started_at desc), then ungrouped
    events = []
    for enc_event in sorted(encounters_map.values(),
                            key=lambda e: e.get("date", ""), reverse=True):
        # Sort items within the encounter chronologically
        enc_event["items"].sort(key=lambda x: x.get("date", ""))
        events.append(enc_event)

    ungrouped.sort(key=lambda x: x.get("date", ""), reverse=True)
    events.extend(ungrouped)

    return jsonify({"timeline": events}), 200


# â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• 
#   EMR MODULE PROXY ROUTES  (landing â†’ backend /emr/*)
# â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• 

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
    """Alias of emr_proxy â€” dashboard JS sends requests to /api/emr/*."""
    return emr_proxy(subpath)


# â”€â”€ Appointment proxy helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# Doctor: create a new appointment for a patient (resolves username â†’ patient_id)
@app.route("/api/doctor/appointment-create", methods=["POST"])
def proxy_doctor_appt_create():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    d = request.get_json(force=True) or {}
    # Resolve patient username in patient_username field â†’ profile_code
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



# â”€â”€ Merged appointment endpoints (bypass JWT uid mismatch via session) â”€â”€â”€â”€â”€â”€â”€â”€â”€

APPT_DB = os.path.join(ROOT, "server", "appointments_db.json")
EMR_APPT = os.path.join(ROOT, "server", "emr_data", "emr_appointments.json")
EMR_RX   = os.path.join(ROOT, "server", "emr_data", "emr_prescriptions.json")
EMR_LR   = os.path.join(ROOT, "server", "emr_data", "emr_lab_reports.json")
NOTES_DB = os.path.join(ROOT, "server", "doctor_notes.json")


def _enrich_with_doctor_name(records: list) -> list:
    """Enrich EMR records with the doctor's actual name from the users table."""
    if not _HAS_PSYCOPG2 or not records:
        return records
    doctor_ids = set()
    for r in records:
        did = r.get("doctor_id") or r.get("doctor_email") or ""
        if did:
            doctor_ids.add(did)
    if not doctor_ids:
        return records
    name_map = {}
    try:
        conn = psycopg2.connect(DB_URL)
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        for did in doctor_ids:
            if did in name_map:
                continue
            cur.execute(
                "SELECT name, doctor_code FROM users WHERE doctor_code=%s OR id::text=%s OR email=%s LIMIT 1",
                (did, did, did)
            )
            row = cur.fetchone()
            if row and row.get("name"):
                name_map[did] = row["name"]
        cur.close(); conn.close()
    except Exception:
        pass
    for r in records:
        did = r.get("doctor_id") or r.get("doctor_email") or ""
        if did and did in name_map and not r.get("doctor_name"):
            r["doctor_name"] = name_map[did]
    return records


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
    """
    Return all appointments for the logged-in patient from both stores.

    Merges:
      - `appointments` table   (patient-submitted requests via patient portal)
      - `emr_appointments` table (doctor-created via EMR module)

    Normalises both to a common shape and deduplicates by ID.
    PostgreSQL is queried first; falls back to flat-file stores when unavailable.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401

    pid      = session.get("profile_code", "")
    user_id  = session.get("user_id", "")
    username = session.get("username", "")
    all_appts = []
    seen_ids = set()

    def _norm_legacy(row):
        return {
            "id":               row.get("id", ""),
            "source":           "request",
            "patient_id":       row.get("patient_id", ""),
            "patient_name":     row.get("patient_name", ""),
            "patient_username": row.get("patient_username", ""),
            "doctor_username":  row.get("doctor_username", ""),
            "doctor_id":        row.get("doctor_id", ""),
            "date":             row.get("date", ""),
            "time":             row.get("time", ""),
            "date_time":        f"{row.get('date','')} {row.get('time','')}".strip(),
            "reason":           row.get("notes", ""),
            "notes":            row.get("notes", ""),
            "status":           row.get("status", "pending"),
            "created_at":       str(row.get("created_at", "")),
        }

    def _norm_view_row(row):
        return {
            "id":               row.get("id", ""),
            "source":           row.get("source", "request"),
            "patient_id":       row.get("patient_id", ""),
            "patient_name":     row.get("patient_name", ""),
            "patient_username": row.get("patient_username", ""),
            "doctor_username":  row.get("doctor_username", ""),
            "doctor_id":        row.get("doctor_id", ""),
            "date":             row.get("date", ""),
            "time":             row.get("time", ""),
            "date_time":        str(row.get("date_time", "")),
            "reason":           row.get("reason", row.get("notes", "")),
            "notes":            row.get("notes", ""),
            "status":           row.get("status", "pending"),
            "created_at":       str(row.get("created_at", "")),
        }

    # ── Primary: PostgreSQL ───────────────────────────────────────────────────
    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            identifiers = [x for x in [user_id, pid, username] if x]
            if identifiers:
                ph = ",".join(["%s"] * len(identifiers))
                cur.execute(
                    "SELECT * FROM appointments_unified WHERE patient_id = ANY(ARRAY[" + ph + "]::text[]) "
                    "OR patient_username = ANY(ARRAY[" + ph + "]::text[]) "
                    "ORDER BY created_at DESC",
                    identifiers * 2,
                )
                for row in cur.fetchall():
                    r = _norm_view_row(dict(row))
                    if r["id"] not in seen_ids:
                        seen_ids.add(r["id"])
                        all_appts.append(r)
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("patient_appts_merged DB: %s", e)

    # ── Fallback: flat files ──────────────────────────────────────────────────
    if not all_appts:
        for a in _load_json_safe(APPT_DB):
            if a.get("patient_id") in (pid, user_id) or a.get("patient_username") == username:
                r = _norm_legacy(a)
                if r["id"] not in seen_ids:
                    seen_ids.add(r["id"])
                    all_appts.append(r)
        for a in _load_json_safe(EMR_APPT):
            if a.get("patient_id") in (pid, user_id):
                r = _norm_view_row({
                    "id": a.get("id", ""),
                    "source": "emr",
                    "patient_id": a.get("patient_id", ""),
                    "patient_name": a.get("patient_name", ""),
                    "patient_username": "",
                    "doctor_username": "",
                    "doctor_id": a.get("doctor_id", ""),
                    "date": "",
                    "time": "",
                    "date_time": a.get("date_time", ""),
                    "reason": a.get("reason", ""),
                    "notes": a.get("notes", ""),
                    "status": a.get("status", "scheduled"),
                    "created_at": a.get("created_at", ""),
                })
                if r["id"] not in seen_ids:
                    seen_ids.add(r["id"])
                    all_appts.append(r)

    all_appts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify({"appointments": all_appts}), 200


@app.route("/api/doctor/appointments-merged", methods=["GET"])
def doctor_appts_merged():
    """
    Return all appointments for the logged-in doctor from both stores.

    Merges `appointments` + `emr_appointments` tables, normalised and deduplicated.
    PostgreSQL is queried first; falls back to flat-file stores when unavailable.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401

    doc_code = session.get("doctor_code", "")
    user_id  = session.get("user_id", "")
    username = session.get("username", "")
    all_appts = []
    seen_ids = set()

    def _norm_legacy(row):
        return {
            "id":               row.get("id", ""),
            "source":           "request",
            "patient_id":       row.get("patient_id", ""),
            "patient_name":     row.get("patient_name", ""),
            "patient_username": row.get("patient_username", ""),
            "doctor_username":  row.get("doctor_username", ""),
            "doctor_id":        row.get("doctor_id", ""),
            "date":             row.get("date", ""),
            "time":             row.get("time", ""),
            "date_time":        f"{row.get('date','')} {row.get('time','')}".strip(),
            "reason":           row.get("notes", ""),
            "notes":            row.get("notes", ""),
            "status":           row.get("status", "pending"),
            "created_at":       str(row.get("created_at", "")),
        }

    def _norm_view_row(row):
        return {
            "id":               row.get("id", ""),
            "source":           row.get("source", "request"),
            "patient_id":       row.get("patient_id", ""),
            "patient_name":     row.get("patient_name", ""),
            "patient_username": row.get("patient_username", ""),
            "doctor_username":  row.get("doctor_username", ""),
            "doctor_id":        row.get("doctor_id", ""),
            "date":             row.get("date", ""),
            "time":             row.get("time", ""),
            "date_time":        str(row.get("date_time", "")),
            "reason":           row.get("reason", row.get("notes", "")),
            "notes":            row.get("notes", ""),
            "status":           row.get("status", "pending"),
            "created_at":       str(row.get("created_at", "")),
        }

    # ── Primary: PostgreSQL ───────────────────────────────────────────────────
    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            doc_ids = [x for x in [username, doc_code, user_id] if x]
            if doc_ids:
                ph = ",".join(["%s"] * len(doc_ids))
                cur.execute(
                    "SELECT * FROM appointments_unified WHERE doctor_username = ANY(ARRAY[" + ph + "]::text[]) "
                    "OR doctor_id = ANY(ARRAY[" + ph + "]::text[]) "
                    "ORDER BY created_at DESC",
                    doc_ids * 2,
                )
                for row in cur.fetchall():
                    r = _norm_view_row(dict(row))
                    if r["id"] not in seen_ids:
                        seen_ids.add(r["id"])
                        all_appts.append(r)
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("doctor_appts_merged DB: %s", e)

    # ── Fallback: flat files ──────────────────────────────────────────────────
    if not all_appts:
        for a in _load_json_safe(APPT_DB):
            if a.get("doctor_username") == username or a.get("doctor_id") in (doc_code, user_id):
                r = _norm_legacy(a)
                if r["id"] not in seen_ids:
                    seen_ids.add(r["id"])
                    all_appts.append(r)
        for a in _load_json_safe(EMR_APPT):
            if a.get("doctor_id") in (doc_code, user_id):
                r = _norm_view_row({
                    "id": a.get("id", ""),
                    "source": "emr",
                    "patient_id": a.get("patient_id", ""),
                    "patient_name": a.get("patient_name", ""),
                    "patient_username": "",
                    "doctor_username": "",
                    "doctor_id": a.get("doctor_id", ""),
                    "date": "",
                    "time": "",
                    "date_time": a.get("date_time", ""),
                    "reason": a.get("reason", ""),
                    "notes": a.get("notes", ""),
                    "status": a.get("status", "scheduled"),
                    "created_at": a.get("created_at", ""),
                })
                if r["id"] not in seen_ids:
                    seen_ids.add(r["id"])
                    all_appts.append(r)

    all_appts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify({"appointments": all_appts}), 200


@app.route("/api/patient/prescriptions-direct", methods=["GET"])
def patient_prescriptions_direct():
    """Returns all prescriptions for the logged-in patient.
    Reads from PostgreSQL EMR table first, falls back to flat file."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid      = session.get("profile_code", "")
    jwt_tok  = session.get("jwt_token", "")
    rxs      = []

    # Primary: PostgreSQL via JWT using correct patient-scoped endpoint
    if jwt_tok:
        try:
            hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
            # Let the backend resolve either UUID or profile_code via _resolve_pid().
            _emr_pid = session.get("user_id") or session.get("profile_code")
            r = http.get(f"{BACKEND}/emr/prescriptions/patient/{_emr_pid}", headers=hdrs, timeout=8)
            if r.ok:
                data = r.json()
                rxs = data if isinstance(data, list) else data.get("prescriptions", [])
        except Exception as e:
            app.logger.debug("prescriptions JWT fetch: %s", e)

    # Secondary: direct PostgreSQL query
    if not rxs and _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Resolve profile_code -> UUID
            cur.execute("SELECT id FROM users WHERE profile_code=%s LIMIT 1", (pid,))
            pt = cur.fetchone()
            if pt:
                patient_uuid = str(pt["id"])
                cur.execute("""
                    SELECT * FROM emr_prescriptions
                    WHERE patient_id::text = %s OR patient_id = %s
                    ORDER BY created_at DESC
                """, (patient_uuid, pid))
                for row in cur.fetchall():
                    rxs.append(dict(row))
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("prescriptions psycopg2 fetch: %s", e)

    # Fallback: flat file
    if not rxs:
        file_rxs = _load_json_safe(EMR_RX)
        if isinstance(file_rxs, list):
            rxs = [r for r in file_rxs if r.get("patient_id") == pid]

    rxs = _enrich_with_doctor_name(rxs)
    rxs.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
    return jsonify(rxs), 200


@app.route("/api/patient/lab-reports-direct", methods=["GET"])
def patient_lab_reports_direct():
    """Returns all lab reports for the logged-in patient.
    Reads from PostgreSQL EMR table first, falls back to flat file."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    pid     = session.get("profile_code", "")
    jwt_tok = session.get("jwt_token", "")
    lrs     = []

    # Primary: PostgreSQL via JWT using correct patient-scoped endpoint
    if jwt_tok:
        try:
            hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
            # Let the backend resolve either UUID or profile_code via _resolve_pid().
            _emr_pid = session.get("user_id") or session.get("profile_code")
            r = http.get(f"{BACKEND}/emr/lab-reports/patient/{_emr_pid}", headers=hdrs, timeout=8)
            if r.ok:
                data = r.json()
                lrs = data if isinstance(data, list) else data.get("lab_reports", data.get("reports", []))
        except Exception as e:
            app.logger.debug("lab-reports JWT fetch: %s", e)

    # Secondary: direct PostgreSQL query
    if not lrs and _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT id FROM users WHERE profile_code=%s LIMIT 1", (pid,))
            pt = cur.fetchone()
            if pt:
                patient_uuid = str(pt["id"])
                cur.execute("""
                    SELECT * FROM emr_lab_reports
                    WHERE patient_id::text = %s OR patient_id = %s
                    ORDER BY created_at DESC
                """, (patient_uuid, pid))
                for row in cur.fetchall():
                    lrs.append(dict(row))
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("lab-reports psycopg2 fetch: %s", e)

    # Fallback: flat file
    if not lrs:
        file_lrs = _load_json_safe(EMR_LR)
        if isinstance(file_lrs, list):
            lrs = [r for r in file_lrs if r.get("patient_id") == pid]

    lrs = _enrich_with_doctor_name(lrs)
    lrs.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
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
    """Patient submits an appointment request - stored directly with correct profile_code."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthenticated"}), 401
    d = request.get_json(force=True) or {}
    import uuid as _uuid_appt
    from datetime import datetime as _dt_appt, timezone as _tz_appt
    pid      = session.get("profile_code", "")
    username = session.get("username", "")
    name     = session.get("name", "")
    entry = {
        "id":               str(_uuid_appt.uuid4()),
        "patient_id":       pid,
        "patient_username": username,
        "patient_name":     name,
        "doctor_username":  d.get("doctor_username", ""),
        "date":             d.get("date", ""),
        "time":             d.get("time", ""),
        "notes":            d.get("notes", ""),
        "status":           "pending",
        "created_at":       _dt_appt.now(_tz_appt.utc).isoformat(),
    }
    entries = _load_json_safe(APPT_DB) if isinstance(_load_json_safe(APPT_DB), list) else []
    entries.append(entry)
    _save_json_safe(APPT_DB, entries)
    return jsonify({"message": "ok", "appointment": entry}), 201

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


# â”€â”€ Patient QR code proxy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ Patient search (doctor only) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ Patient: revoke an approved access grant â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# -- Active patients for notes dropdown ----------------------------------------
@app.route("/api/doctor/active_patients", methods=["GET"])
def api_doctor_active_patients():
    """Return patients that have granted this doctor active (non-expired) access.
    Used by the Add Clinical Note form to populate the patient dropdown.
    Access is considered active if responded_at + 24 hours > now().
    """
    err = _doctor_session_check()
    if err: return err
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    doc_code = session.get("doctor_code", "")
    patients = []

    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Resolve doctor UUID
            cur.execute(
                "SELECT id FROM users WHERE doctor_code=%s OR LOWER(username)=LOWER(%s) LIMIT 1",
                (doc_code, doc_code)
            )
            doc_row = cur.fetchone()
            if doc_row:
                doc_uuid = str(doc_row["id"])
                # Fetch approved accesses within last 24 hours
                cur.execute("""
                    SELECT a.responded_at,
                           p.profile_code, p.username, p.name, p.email
                    FROM access_db a
                    JOIN users p ON a.patient_id::text = p.id::text
                    WHERE (a.doctor_id::text = %s OR a.doctor_id = %s)
                      AND a.status = 'approved'
                      AND a.responded_at IS NOT NULL
                      AND a.responded_at > NOW() - INTERVAL '24 hours'
                    ORDER BY a.responded_at DESC
                """, (doc_uuid, doc_code))
                for row in cur.fetchall():
                    patients.append({
                        "profile_code": row.get("profile_code", ""),
                        "patient_code": row.get("profile_code", ""),
                        "username":     row.get("username", ""),
                        "name":         row.get("name", ""),
                        "email":        row.get("email", ""),
                    })
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("api_doctor_active_patients: %s", e)

    return jsonify({"patients": patients}), 200



# â”€â”€ Doctor: my patients list (approved + pending) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/doctor/my_requests", methods=["GET"])
def doctor_my_requests():
    err = _doctor_session_check()
    if err: return err
    try:
        doc_code = session.get("doctor_code", "")
        jwt_tok  = session.get("jwt_token", "")
        reqs = []

        # â”€â”€ Primary: psycopg2 JOIN access_db + users â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if _HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(DB_URL)
                cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                # Look up doctor's UUID
                cur.execute(
                    "SELECT id FROM users WHERE doctor_code=%s OR LOWER(username)=LOWER(%s) LIMIT 1",
                    (doc_code, doc_code)
                )
                doc_row = cur.fetchone()
                if doc_row:
                    doc_uuid = str(doc_row["id"])
                    # Query by BOTH UUID and doctor_code to handle old + new rows
                    cur.execute("""
                        SELECT a.id as req_id, a.status, a.created_at, a.responded_at,
                               a.patient_id,
                               p.profile_code, p.username, p.name, p.email,
                               wk.temp_key_expires_at
                        FROM access_db a
                        LEFT JOIN users p ON a.patient_id::text = p.id::text
                        LEFT JOIN wrapped_keys wk ON (
                            wk.profile_code = p.profile_code
                            AND wk.doctor_code = %s
                        )
                        WHERE a.doctor_id::text = %s OR a.doctor_id = %s
                        ORDER BY a.created_at DESC
                    """, (doc_code, doc_uuid, doc_code))
                    seen = set()
                    for row in cur.fetchall():
                        rid = str(row.get("req_id", ""))
                        if rid in seen: continue
                        seen.add(rid)
                        # profile_code from JOIN, or fallback to patient_id if it looks like a code
                        pc = row.get("profile_code") or ""
                        if not pc:
                            pid = row.get("patient_id", "")
                            # If patient_id is not UUID-shaped, treat it as profile_code
                            if pid and "-" not in str(pid) and len(str(pid)) <= 12:
                                pc = str(pid).upper()
                            else:
                                # Try reverse lookup by UUID
                                cur2 = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                                cur2.execute("SELECT profile_code, username, name, email FROM users WHERE id::text=%s LIMIT 1", (str(pid),))
                                r2 = cur2.fetchone()
                                cur2.close()
                                if r2:
                                    pc = r2.get("profile_code") or ""
                        ts          = row["created_at"].isoformat() if row.get("created_at") else ""
                        responded   = row.get("responded_at")
                        resp_iso    = responded.isoformat() if responded and hasattr(responded, "isoformat") else str(responded or "")
                        expires_raw = row.get("temp_key_expires_at")
                        exp_iso     = expires_raw.isoformat() if expires_raw and hasattr(expires_raw, "isoformat") else str(expires_raw or "")
                        reqs.append({
                            "id":           rid,
                            "request_id":   rid,
                            "profile_code": pc,
                            "patient_code": pc,
                            "username":     row.get("username") or pc,
                            "name":         row.get("name") or "",
                            "email":        row.get("email") or "",
                            "status":       row.get("status", "pending"),
                            "requested_at": ts,
                            "timestamp":    ts,
                            "approved_at":  ts,
                            "responded_at": resp_iso,
                            "expires_at":   exp_iso,
                            "doctor_code":  doc_code,
                        })

                cur.close(); conn.close()
            except Exception as e:
                app.logger.debug("doctor_my_requests psycopg2: %s", e)

        # â”€â”€ Fallback: JWT /access/doctor_patients â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if not reqs and jwt_tok:
            try:
                r = http.get(f"{BACKEND}/access/doctor_patients",
                             headers=_jwt_headers(), timeout=8)
                if r.ok:
                    data = r.json()
                    raw  = data if isinstance(data, list) else data.get("requests", data.get("patients", []))
                    for p in raw:
                        pc = p.get("profile_code") or p.get("patient_code") or ""
                        ts = p.get("created_at") or p.get("requested_at") or ""
                        reqs.append({
                            "id":           p.get("id", ""),
                            "request_id":   p.get("id", ""),
                            "profile_code": pc,
                            "patient_code": pc,
                            "username":     p.get("username") or pc,
                            "name":         p.get("name") or "",
                            "email":        p.get("email") or "",
                            "status":       p.get("status", "approved"),
                            "requested_at": ts,
                            "timestamp":    ts,
                            "approved_at":  ts,
                            "doctor_code":  doc_code,
                        })
            except Exception as e:
                app.logger.debug("doctor_my_requests JWT: %s", e)

        return jsonify({"requests": reqs}), 200
    except Exception as e:
        return jsonify({"error": str(e), "requests": []}), 200



# ═══════════════════════════════════════════════════════════════
#   DOCTOR EMR WRITE ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route("/doctor/patient_prescriptions/<patient_code>")
def doctor_patient_prescriptions(patient_code):
    """Doctor views all prescriptions for a specific patient."""
    err = _doctor_session_check()
    if err: return err

    resolved_code, patient_id = _resolve_patient_uuid_or_code(patient_code)
    err = _require_active_access(session.get("doctor_code", ""), resolved_code)
    if err:
        return err

    rxs = []
    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT * FROM emr_prescriptions WHERE patient_id=%s OR patient_id=%s ORDER BY created_at DESC",
                (resolved_code, patient_id)
            )
            for row in cur.fetchall():
                r = dict(row)
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
                rxs.append(r)
            cur.close(); conn.close()
        except Exception as e:
            app.logger.warning("doctor_patient_prescriptions: %s", e)
    rxs = _enrich_with_doctor_name(rxs)
    return jsonify(rxs), 200


@app.route("/doctor/patient_lab_reports/<patient_code>")
def doctor_patient_lab_reports(patient_code):
    """Doctor views all lab reports for a specific patient."""
    err = _doctor_session_check()
    if err: return err

    resolved_code, patient_id = _resolve_patient_uuid_or_code(patient_code)
    err = _require_active_access(session.get("doctor_code", ""), resolved_code)
    if err:
        return err

    lrs = []
    if _HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT * FROM emr_lab_reports WHERE patient_id=%s OR patient_id=%s ORDER BY created_at DESC",
                (resolved_code, patient_id)
            )
            for row in cur.fetchall():
                r = dict(row)
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
                lrs.append(r)
            cur.close(); conn.close()
        except Exception as e:
            app.logger.warning("doctor_patient_lab_reports: %s", e)
    lrs = _enrich_with_doctor_name(lrs)
    return jsonify(lrs), 200


@app.route("/doctor/add_prescription", methods=["POST"])
def doctor_add_prescription():
    """Doctor creates a prescription for a patient."""
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        raw_code    = (d.get("patient_code") or d.get("profile_code") or "").strip()
        pat_code, _ = _resolve_patient_uuid_or_code(raw_code)
        diagnosis   = d.get("diagnosis", "").strip()
        medications = d.get("medications", [])
        notes       = d.get("notes", "")
        doc_code    = session.get("doctor_code", "")
        doc_name    = session.get("name", "")
        jwt_tok     = session.get("jwt_token", "")

        if not pat_code:
            return jsonify({"error": "Patient identifier is required"}), 400
        err = _require_active_access(session.get("doctor_code", ""), pat_code)
        if err:
            return err
        if not diagnosis:
            return jsonify({"error": "Diagnosis is required"}), 400

        from datetime import datetime, timezone
        import uuid as _uuid2
        rx = {
            "id": str(_uuid2.uuid4()),
            "patient_id": pat_code,
            "doctor_id": doc_code,
            "doctor_email": session.get("email", ""),
            "doctor_name": doc_name,
            "diagnosis": diagnosis,
            "medications": medications if isinstance(medications, list) else [],
            "notes": notes,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Try JWT proxy to backend EMR
        if jwt_tok:
            try:
                hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
                rb = http.post(
                    f"{BACKEND}/emr/prescriptions",
                    json={**rx, "patient_id": pat_code},
                    headers=hdrs, timeout=10,
                )
                # Forward ALL responses from the backend — including 409
                # allergy_conflict — so the browser can render the conflict UI.
                return jsonify(rb.json()), rb.status_code
            except Exception as e:
                app.logger.debug("doctor_add_prescription JWT: %s", e)

        # Fallback path — backend is unreachable.
        # We MUST NOT save the prescription here without running the allergy
        # safety check, and the profile data needed for that check is only
        # available via the backend.  Refuse explicitly so the doctor knows
        # to retry once the backend is reachable.
        return jsonify({
            "error": "backend_unavailable",
            "detail": (
                "The prescription server is temporarily unreachable. "
                "Please wait a moment and try again. "
                "Prescriptions cannot be saved without a safety check."
            ),
        }), 503

    except Exception as e:
        app.logger.exception("doctor_add_prescription error")
        return jsonify({"error": str(e)}), 500


@app.route("/doctor/add_lab_report", methods=["POST"])
def doctor_add_lab_report():
    """Doctor creates a lab report for a patient."""
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        raw_code    = (d.get("patient_code") or d.get("profile_code") or "").strip()
        pat_code, _ = _resolve_patient_uuid_or_code(raw_code)
        report_type = d.get("report_type", "General").strip()
        tests       = d.get("tests", [])
        results     = d.get("results", {})
        notes       = d.get("notes", "")
        doc_code    = session.get("doctor_code", "")
        doc_name    = session.get("name", "")
        jwt_tok     = session.get("jwt_token", "")

        if not pat_code:
            return jsonify({"error": "Patient identifier is required"}), 400
        err = _require_active_access(session.get("doctor_code", ""), pat_code)
        if err:
            return err
        if not report_type:
            return jsonify({"error": "Report type is required"}), 400

        from datetime import datetime, timezone
        import uuid as _uuid3
        lr = {
            "id": str(_uuid3.uuid4()),
            "patient_id": pat_code,
            "doctor_id": doc_code,
            "doctor_email": session.get("email", ""),
            "doctor_name": doc_name,
            "report_type": report_type,
            "tests": tests if isinstance(tests, list) else [],
            "results": results if isinstance(results, dict) else {},
            "notes": notes,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Try JWT proxy to backend EMR
        if jwt_tok:
            try:
                hdrs = {**_headers(), "Authorization": f"Bearer {jwt_tok}"}
                rb = http.post(
                    f"{BACKEND}/emr/lab-reports",
                    json={**lr, "patient_id": pat_code},
                    headers=hdrs, timeout=10,
                )
                if rb.ok:
                    return jsonify(rb.json()), rb.status_code
            except Exception as e:
                app.logger.debug("doctor_add_lab_report JWT: %s", e)

        # Fallback: save directly to EMR file
        import os
        emr_data_dir = os.path.join(ROOT, "server", "emr_data")
        os.makedirs(emr_data_dir, exist_ok=True)
        emr_lr_path = os.path.join(emr_data_dir, "emr_lab_reports.json")
        lrs_existing = _load_json_safe(emr_lr_path) if isinstance(_load_json_safe(emr_lr_path), list) else []
        lrs_existing.append(lr)
        _save_json_safe(emr_lr_path, lrs_existing)
        return jsonify(lr), 201

    except Exception as e:
        app.logger.exception("doctor_add_lab_report error")
        return jsonify({"error": str(e)}), 500


@app.route("/doctor/prescriptions")
def page_doctor_prescriptions():
    if not session.get("logged_in"): return redirect("/")
    if session.get("role") != "doctor": return redirect("/dashboard")
    ctx = _page_context()
    return render_template("doctor_prescriptions.html", **ctx)


@app.route("/doctor/lab-reports")
def page_doctor_lab_reports():
    if not session.get("logged_in"): return redirect("/")
    if session.get("role") != "doctor": return redirect("/dashboard")
    ctx = _page_context()
    return render_template("doctor_lab_reports.html", **ctx)



# ─── Session JWT refresh ────────────────────────────────────────────────────
@app.route("/api/refresh_session", methods=["POST"])
def api_refresh_session():
    """Re-issue a fresh JWT for the current session user.
    Frontend calls this when it receives invalid_or_expired_token from backend.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "not_logged_in"}), 401
    tok = _refresh_jwt()
    if tok:
        return jsonify({"token": tok, "status": "refreshed"}), 200
    return jsonify({"error": "refresh_failed",
                    "message": "Please log out and log back in."}), 401


@app.route("/api/cache_password", methods=["POST"])
def api_cache_password():
    """Temporarily cache the user's password in server-side session for JWT refresh.
    Called right after successful login if the user is logged in.
    The password is stored ONLY in the encrypted server session (Flask session cookie),
    never written to disk.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "not_logged_in"}), 401
    d = request.get_json(force=True) or {}
    pw = d.get("password", "")
    if pw:
        session["_pw_cache"] = pw
    return jsonify({"status": "ok"}), 200


# ─── Doctor: view patient detail page ──────────────────────────────────────
@app.route("/doctor/view_patient")
def doctor_view_patient():
    """Navigate doctor to the patient detail page.
    Accepts: profile_code, username, OR access_db request UUID.
    Resolves all to a profile_code before rendering.
    """
    if not session.get("logged_in"): return redirect("/")
    if session.get("role") != "doctor": return redirect("/dashboard")
    code = request.args.get("code", "").strip()
    if not code:
        return redirect("/dashboard")

    profile_code = code  # default fallback

    # If code looks like a UUID (access_db request id), resolve patient_id → profile_code
    import re as _re
    if _re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', code.lower()):
        if _HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(DB_URL)
                cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                # Try as access_db.id first
                cur.execute("SELECT patient_id FROM access_db WHERE id::text=%s LIMIT 1", (code,))
                row = cur.fetchone()
                if row:
                    patient_id = str(row["patient_id"])
                    # patient_id could be UUID or profile_code
                    if _re.match(r'^[0-9a-f]{8}-', patient_id.lower()):
                        cur.execute("SELECT profile_code, username FROM users WHERE id::text=%s LIMIT 1", (patient_id,))
                        u = cur.fetchone()
                        if u:
                            profile_code = u.get("profile_code") or u.get("username") or code
                    else:
                        profile_code = patient_id  # it's already a profile_code
                else:
                    # Try as patient UUID directly
                    cur.execute("SELECT profile_code, username FROM users WHERE id::text=%s LIMIT 1", (code,))
                    u = cur.fetchone()
                    if u:
                        profile_code = u.get("profile_code") or u.get("username") or code
                cur.close(); conn.close()
            except Exception as e:
                app.logger.debug("doctor_view_patient uuid resolve: %s", e)
    else:
        # Try to resolve username to profile_code
        resolved = _resolve_patient_code(code)
        if resolved:
            profile_code = resolved

    err = _require_active_access(session.get("doctor_code", ""), profile_code)
    if err:
        return err

    ctx = _page_context()
    ctx["patient_code"] = profile_code

    # Load patient info directly from users table (no encryption needed for basic info)
    patient_info = {
        "name": "",
        "email": "",
        "username": "",
        "age": "",
        "blood_group": "",
        "phone": "",
        "address": "",
        "allergies": "",
        "conditions": "",
    }
    if _HAS_PSYCOPG2 and profile_code:
        try:
            conn = psycopg2.connect(DB_URL)
            cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT name, email, username, patient_details FROM users WHERE profile_code=%s LIMIT 1",
                (profile_code,)
            )
            row = cur.fetchone()
            if row:
                patient_info["name"]     = row.get("name") or ""
                patient_info["email"]    = row.get("email") or ""
                patient_info["username"] = row.get("username") or ""
                details = row.get("patient_details") or {}
                if isinstance(details, str):
                    try: details = json.loads(details)
                    except: details = {}
                patient_info["age"]        = details.get("age", "")
                patient_info["blood_group"]= details.get("blood_group", details.get("bloodGroup", ""))
                patient_info["phone"]      = details.get("phone", details.get("contact", ""))
                patient_info["address"]    = details.get("address", "")
                patient_info["allergies"]  = details.get("allergies", "")
                patient_info["conditions"] = details.get("conditions", details.get("medical_conditions", ""))
                # Also grab name/email from patient_details if top-level is empty
                if not patient_info["name"]:
                    patient_info["name"] = details.get("name", "")
                if not patient_info["email"]:
                    patient_info["email"] = details.get("email", "")
            cur.close(); conn.close()
        except Exception as e:
            app.logger.debug("view_patient info load: %s", e)

    ctx["patient_info"] = patient_info
    return render_template("patient_detail.html", **ctx)



if __name__ == "__main__":
    print("  ðŸŒ  Landing Page â†’ http://127.0.0.1:5003")
    app.run(host="127.0.0.1", port=5003, debug=False, use_reloader=False, threaded=True)


