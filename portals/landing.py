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
app = Flask(__name__, template_folder=TEMPLATE_DIR)

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
    PERMANENT_SESSION_LIFETIME=3600 * 8,   # 8-hour session
)

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
        profile_code=session.get("profile_code", ""),
        doctor_code=doctor_code,
        specialization=spec,
        hospital=hosp,
        uid=session.get("profile_code", "") if role == "patient" else doctor_code,
        jwt_token=session.get("jwt_token", ""),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ── LOGIN ─────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    try:
        d = request.get_json(force=True) or {}
        email    = (d.get("email") or "").strip().lower()
        password = d.get("password") or ""

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Send raw password to backend — server handles both SHA-256 and werkzeug
        try:
            r = http.post(
                f"{BACKEND}/auth/login",
                json={"email": email, "password": password,
                      "password_hash": hashlib.sha256(password.encode()).hexdigest()},
                headers=_headers(),
                timeout=10,
            )
            data = r.json()
        except Exception as e:
            return jsonify({"error": f"Cannot reach backend: {e}"}), 502

        if not r.ok:
            return jsonify({"error": data.get("error", "Invalid credentials")}), r.status_code

        # Populate Flask session
        session.clear()
        role  = data.get("role", "patient")
        pcode = data.get("profile_code", "")
        dcode = data.get("doctor_code", "") or (pcode if role == "doctor" else "")
        session["logged_in"]    = True
        session["role"]         = role
        session["name"]         = data.get("name", "")
        session["email"]        = email
        session["user_id"]      = data.get("user_id", "")
        session["profile_code"] = pcode if role == "patient" else ""
        session["doctor_code"]  = dcode if role == "doctor" else ""
        session["jwt_token"]    = data.get("access_token", "")
        # Load doctor specialization & hospital from local doctor_data.json
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
        session.permanent       = True

        return jsonify({"message": "ok", "redirect": "/dashboard",
                        "role": session["role"]})
    except Exception as e:
        app.logger.exception("Login error")
        return jsonify({"error": str(e)}), 500


# ── REGISTER PATIENT ──────────────────────────────────────────────────────────
@app.route("/register/patient", methods=["POST"])
def register_patient():
    try:
        d        = request.get_json(force=True) or {}
        name     = (d.get("name") or "").strip()
        email    = (d.get("email") or "").strip().lower()
        age      = (d.get("age") or "").strip()
        notes    = d.get("notes", "")
        password = d.get("password") or ""

        if not name:     return jsonify({"error": "Name is required"}), 400
        if not email:    return jsonify({"error": "Email is required"}), 400
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
            http.post(
                f"{BACKEND}/internal/register_user_db",
                json={"email": email, "name": name, "role": "patient",
                      "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                      "profile_code": profile_code,
                      "public_key": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
        except Exception as e:
            app.logger.warning("backend /internal/register_user_db failed: %s", e)

        # ── Set session ────────────────────────────────────────────────────────
        session.clear()
        session["logged_in"]    = True
        session["role"]         = "patient"
        session["name"]         = name
        session["email"]        = email
        session["profile_code"] = profile_code
        session["doctor_code"]  = ""
        session["jwt_token"]    = ""
        session.permanent       = True

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
        spec     = (d.get("specialization") or "").strip()
        hosp     = (d.get("hospital") or "").strip()
        password = d.get("password") or ""

        if not name:     return jsonify({"error": "Name is required"}), 400
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
            http.post(
                f"{BACKEND}/internal/register_user_db",
                json={"email": email, "name": name, "role": "doctor",
                      "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                      "profile_code": doctor_code,
                      "doctor_code": doctor_code,
                      "public_key": pub_pem.decode("utf-8")},
                headers=_headers(), timeout=10,
            )
        except Exception as e:
            app.logger.warning("backend register_user_db failed: %s", e)

        # ── Set session ────────────────────────────────────────────────────────
        session.clear()
        session["logged_in"]      = True
        session["role"]           = "doctor"
        session["name"]           = name
        session["email"]          = email
        session["profile_code"]   = ""
        session["doctor_code"]    = doctor_code
        session["specialization"] = spec
        session["hospital"]       = hosp
        session["jwt_token"]      = ""
        session.permanent         = True

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


# ════════════════════════════════════════════════════════════════════════════
#   DOCTOR API ROUTES  (called by dashboard.html via fetch)
# ════════════════════════════════════════════════════════════════════════════

DOCTOR_PORTAL = "http://127.0.0.1:5002"

def _doctor_session_check():
    if not session.get("logged_in") or session.get("role") != "doctor":
        return jsonify({"error": "unauthenticated"}), 401
    return None

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
        r = http.post(
            f"{DOCTOR_PORTAL}/api/load_profile",
            json={"doctor_code": doc_code, "password": pw},
            cookies={"session": request.cookies.get("session", "")},
            headers=_fwd_headers(), timeout=10,
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Request patient access ─────────────────────────────────────────────────
@app.route("/doctor/request_access", methods=["POST"])
def doctor_request_access():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        r = http.post(
            f"{DOCTOR_PORTAL}/api/request_access",
            json={
                "doctor_code": session.get("doctor_code", ""),
                "patient_code": d.get("patient_code", ""),
                "password": d.get("password", ""),
            },
            cookies={"session": request.cookies.get("session", "")},
            headers=_fwd_headers(), timeout=10,
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Fetch & decrypt patient record ─────────────────────────────────────────
@app.route("/doctor/fetch_record", methods=["POST"])
def doctor_fetch_record():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        r = http.post(
            f"{DOCTOR_PORTAL}/api/fetch_record",
            json={
                "doctor_code": session.get("doctor_code", ""),
                "patient_code": d.get("patient_code", ""),
                "password": d.get("password", ""),
            },
            cookies={"session": request.cookies.get("session", "")},
            headers=_fwd_headers(), timeout=10,
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── Add clinical note ──────────────────────────────────────────────────────
@app.route("/doctor/add_note", methods=["POST"])
def doctor_add_note():
    err = _doctor_session_check()
    if err: return err
    try:
        d = request.get_json(force=True) or {}
        d["doctor_code"] = session.get("doctor_code", "")
        r = http.post(
            f"{DOCTOR_PORTAL}/api/add_note",
            json=d,
            cookies={"session": request.cookies.get("session", "")},
            headers=_fwd_headers(), timeout=30,
        )
        return jsonify(r.json()), r.status_code
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
        notes_file = os.path.join(USERS_DIR, patient_code, "notes.json")
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
        SERVER_DIR = os.path.join(ROOT, "server")
        wk_dir     = os.path.join(SERVER_DIR, "Patients", patient_code, "wrapped_keys")
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
    headers = {**_headers()}
    if jwt_token:
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


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("  🌐  Landing Page → http://127.0.0.1:5003")
    app.run(host="127.0.0.1", port=5003, debug=True, threaded=True)

