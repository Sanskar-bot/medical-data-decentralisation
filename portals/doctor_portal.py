#!/usr/bin/env python3
"""
Doctor Portal  —  http://127.0.0.1:5002
Serves the doctor-facing web UI and handles all crypto on the doctor's machine.
"""
import json, os, sys, uuid, secrets
from datetime import datetime, timezone, timedelta
from base64 import b64encode, b64decode
from flask import Flask, request, jsonify, send_file, session, redirect, Response
import requests as http

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)

from common.crypto_utils import (
    generate_rsa_keypair, rsa_serialize_private, rsa_serialize_public,
    derive_kek_from_password, wrap_key_with_kek, unwrap_key_with_kek,
    rsa_load_private, rsa_unwrap_key, rsa_load_public, rsa_hybrid_encrypt,
    aesgcm_decrypt, rsa_verify,
)
from common.secure_key_store import SecureKeyStore

# Add portals dir to sys.path so auth_utils is importable as a sibling module
_PORTALS_DIR = os.path.dirname(__file__)
if _PORTALS_DIR not in sys.path:
    sys.path.insert(0, _PORTALS_DIR)
from auth_utils import login_required, cors_after_request, get_server_api_key  # noqa: E402

BACKEND     = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")
DOCTORS_DIR = os.path.join(ROOT, "doctor", "Doctors")
LANDING     = os.environ.get("LANDING_URL", "http://127.0.0.1:5003")
os.makedirs(DOCTORS_DIR, exist_ok=True)


# NOTE: Old embedded doctor UI removed — all features served by unified dashboard.



app = Flask(__name__)
# Shared secret key — same file as landing.py so cross-app sessions work
_SK_FILE = os.path.join(ROOT, "server", "flask_secret.key")
if os.path.exists(_SK_FILE):
    app.secret_key = open(_SK_FILE, "rb").read()
else:
    app.secret_key = secrets.token_bytes(32)
    with open(_SK_FILE, "wb") as _f:
        _f.write(app.secret_key)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") != "development",  # fix #14
)

@app.after_request
def cors(r):
    # Whitelist-based CORS - replaces the old wildcard
    return cors_after_request(r)

def _api_key():
    return get_server_api_key()

def bh(token=None):
    """Headers for backend calls. If no token is explicitly passed, tries to
    forward the Authorization header from the incoming request automatically
    — so a caller can no longer forget to attach it."""
    if token is None:
        auth_hdr = request.headers.get("Authorization", "")
        token = auth_hdr.replace("Bearer ", "").strip() if auth_hdr.startswith("Bearer ") else ""
    h = {"X-API-Key": _api_key(), "Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h
def doc_dir(code):
    # find by doctor_code inside any subfolder
    for d in os.listdir(DOCTORS_DIR):
        folder = os.path.join(DOCTORS_DIR, d)
        meta   = os.path.join(folder, "doctor_data.json")
        if os.path.exists(meta):
            try:
                m = json.load(open(meta))
                if m.get("doctor_code") == code or m.get("doctor_id","").startswith(code):
                    return folder
            except Exception: pass
    return None


def unlock_doctor_private_key(doc_code: str, password: str):
    """Unlock a doctor's RSA private key from the local credential store.

    Returns (priv_pem: bytes, priv_obj) on success.
    Raises ValueError with a user-friendly message on any failure:
      - "Password must be at least 8 characters"
      - "Doctor profile not found on this machine"
      - "Private key not found in credential store – re-register on this machine"
      - "Wrong password – please use the same password you registered with"
    """
    if not password:
        raise ValueError("Password is required")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    folder = doc_dir(doc_code)
    if not folder:
        raise ValueError("Doctor profile not found on this machine")

    kp_path = os.path.join(folder, "key_protection.json")
    try:
        kp = json.load(open(kp_path))
    except FileNotFoundError:
        raise ValueError("Key-protection file missing – re-register on this machine")

    try:
        salt = b64decode(kp["salt_b64"])
        kek, _ = derive_kek_from_password(password, salt=salt)
        wrapped_bytes = SecureKeyStore.load_private_key(f"doctor__{doc_code}")
        priv_pem = unwrap_key_with_kek(kek, wrapped_bytes.decode())
        priv_obj = rsa_load_private(priv_pem)
        return priv_pem, priv_obj
    except KeyError:
        raise ValueError(
            "Private key not found in credential store – re-register on this machine"
        )
    except Exception:
        # KEK derivation succeeded but unwrap failed → genuinely wrong password
        raise ValueError(
            "Wrong password – please use the same password you registered with"
        )



# ── API ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # Redirect to unified dashboard at landing page
    if not session.get("logged_in"):
        return redirect(LANDING)
    return redirect(LANDING + "/dashboard")

@app.route("/api/register", methods=["POST","OPTIONS"])
@login_required(role="doctor")
def api_register():
    if request.method == "OPTIONS": return jsonify({}), 200
    d    = request.get_json(force=True)
    name = d.get("name",""); spec = d.get("specialization","")
    hosp = d.get("hospital",""); email = d.get("email",""); pw = d.get("password","")
    if not name: return jsonify({"error":"Name is required"}), 400
    if not pw:   return jsonify({"error":"Password is required"}), 400
    if len(pw) < 8: return jsonify({"error":"Password must be at least 8 characters"}), 400

    priv, pub = generate_rsa_keypair()
    doctor_id   = str(uuid.uuid4())
    doctor_code = doctor_id[:8]

    priv_pem = rsa_serialize_private(priv)
    pub_pem  = rsa_serialize_public(pub)

    kek, salt = derive_kek_from_password(pw)
    wrapped   = wrap_key_with_kek(kek, priv_pem)

    folder = os.path.join(DOCTORS_DIR, doctor_id)
    os.makedirs(folder, exist_ok=True)

    # Store the KEK-wrapped private key in Windows Credential Manager.
    # The file `doctor_private_wrapped.b64` is intentionally NOT created.
    SecureKeyStore.store_private_key(f"doctor__{doctor_code}", wrapped.encode())
    with open(os.path.join(folder,"key_protection.json"),"w") as f:
        json.dump({"salt_b64": b64encode(salt).decode()}, f, indent=2)
    with open(os.path.join(folder,"doctor_public.pem"),"wb") as f: f.write(pub_pem)
    meta = {"doctor_id":doctor_id,"doctor_code":doctor_code,"name":name,
            "specialization":spec,"hospital":hosp,"email":email}
    with open(os.path.join(folder,"doctor_data.json"),"w") as f:
        json.dump(meta, f, indent=2)

    # register on backend (public key only)
    try:
        http.post(f"{BACKEND}/register_doctor",
            json={"doctor_id":doctor_id,"doctor_code":doctor_code,"public_pem":pub_pem.decode()},
            headers=bh(), timeout=8)
    except Exception as e:
        print(f"[warn] backend register failed: {e}")

    return jsonify({"doctor_code": doctor_code})

@app.route("/api/load_profile", methods=["POST","OPTIONS"])
@login_required(role="doctor")
def api_load_profile():
    if request.method == "OPTIONS": return jsonify({}), 200
    d    = request.get_json(force=True)
    code = d.get("doctor_code","").strip(); pw = d.get("password","")
    folder = doc_dir(code)
    if not folder: return jsonify({"error":"Profile not found on this machine. Register first."}), 404
    kp = json.load(open(os.path.join(folder,"key_protection.json")))
    try:
        salt  = b64decode(kp["salt_b64"])
        kek,_ = derive_kek_from_password(pw, salt=salt)
        wrapped_bytes = SecureKeyStore.load_private_key(f"doctor__{code}")
        priv_pem = unwrap_key_with_kek(kek, wrapped_bytes.decode())
        rsa_load_private(priv_pem)   # validate key is parseable
    except KeyError:
        return jsonify({"error": "Private key not found in credential store. "
                                 "Re-register on this machine."}), 404
    except Exception:
        return jsonify({"error":"Wrong password"}), 401
    meta = json.load(open(os.path.join(folder,"doctor_data.json")))
    return jsonify({"name":meta.get("name",""),"specialization":meta.get("specialization",""),
                    "hospital":meta.get("hospital","")})

@app.route("/api/request_access", methods=["POST","OPTIONS"])
@login_required(role="doctor")
def api_request_access():
    if request.method == "OPTIONS": return jsonify({}), 200
    d         = request.get_json(force=True)
    doc_code  = d.get("doctor_code",""); pat_code = d.get("patient_code",""); pw = d.get("password","")

    try:
        _, _ = unlock_doctor_private_key(doc_code, pw)
    except ValueError as e:
        code = 404 if "not found" in str(e).lower() else 401
        return jsonify({"error": str(e)}), code

    folder  = doc_dir(doc_code)
    pub_pem = open(os.path.join(folder,"doctor_public.pem"),"rb").read().decode()
    meta    = json.load(open(os.path.join(folder,"doctor_data.json")))

    # fetch patient public key from backend
    try:
        r = http.get(f"{BACKEND}/get_patient_public/{pat_code}", headers=bh(), timeout=8)
        if r.status_code == 404: return jsonify({"error":"Patient not found on server"}), 404
        pat_pub_pem = r.json().get("patient_public_pem","")
        if not pat_pub_pem: return jsonify({"error":"Patient public key missing"}), 500
    except Exception as e:
        return jsonify({"error":f"Cannot reach backend: {e}"}), 502

    # encrypt doctor profile with patient's public key
    profile_bytes = json.dumps({
        "doctor_id": meta.get("doctor_id"), "doctor_code": doc_code,
        "name": meta.get("name"), "specialization": meta.get("specialization"),
        "hospital": meta.get("hospital"), "email": meta.get("email"),
    }, separators=(",",":")).encode()

    pat_pub_obj = rsa_load_public(pat_pub_pem.encode())
    enc_b64     = rsa_hybrid_encrypt(pat_pub_obj, profile_bytes)

    try:
        r = http.post(f"{BACKEND}/request_access_simple/{pat_code}",
            json={"doctor_code":doc_code,"doctor_public_pem":pub_pem,
                  "encrypted_doctor_profile_b64":enc_b64},
            headers=bh(), timeout=8)
        rd = r.json()
        if not r.ok: return jsonify({"error":rd.get("error",r.text)}), r.status_code
        return jsonify({"request_id": rd.get("request_id","")})
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/fetch_record", methods=["POST","OPTIONS"])
@login_required(role="doctor")
def api_fetch_record():
    if request.method == "OPTIONS": return jsonify({}), 200
    d        = request.get_json(force=True)
    doc_code = d.get("doctor_code",""); pat_code = d.get("patient_code",""); pw = d.get("password","")

    try:
        _, priv = unlock_doctor_private_key(doc_code, pw)
    except ValueError as e:
        code = 404 if "not found" in str(e).lower() else 401
        return jsonify({"error": str(e)}), code

    # fetch encrypted record from backend
    try:
        r = http.get(f"{BACKEND}/get_patient_data/{pat_code}", headers=bh(), timeout=8)
        if r.status_code == 404: return jsonify({"error":"Patient not found"}), 404
        enc_resp = r.json()
    except Exception as e:
        return jsonify({"error":f"Backend error: {e}"}), 502

    # fetch wrapped key
    try:
        rw = http.get(f"{BACKEND}/wrapped_key/{pat_code}", headers=bh(), timeout=8)
        wk_data = rw.json() if rw.ok else {}
    except Exception as e:
        return jsonify({"error":f"Cannot fetch wrapped key: {e}"}), 502

    # find our wrapped key for this doctor only.
    wrapped_key_b64 = None; expires_at = None
    wkmap = wk_data.get("wrapped_keys", wk_data)
    if isinstance(wkmap, dict) and doc_code in wkmap:
        entry = wkmap[doc_code]
        wrapped_key_b64 = entry.get("wrapped_key") if isinstance(entry, dict) else entry
        expires_at      = entry.get("temp_key_expires_at") if isinstance(entry, dict) else None

    if not wrapped_key_b64:
        return jsonify({"error":"No access key found. The patient may not have approved your request yet, or access has expired."}), 403

    # check expiry
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
                return jsonify({"error":"Your access to this patient's record has expired."}), 403
        except Exception: pass

    # unwrap temp key T, then decrypt K_data, then decrypt record
    try:
        enc_rec = enc_resp.get("encrypted_record",{})
        enc_kdata_with_temp = None
        # find encrypted_kdata_with_temp from wrapped keys entry
        if doc_code in wkmap and isinstance(wkmap[doc_code], dict):
            enc_kdata_with_temp = wkmap[doc_code].get("encrypted_kdata_with_temp")
        elif len(wkmap) == 1:
            enc_kdata_with_temp = next(iter(wkmap.values())).get("encrypted_kdata_with_temp") if isinstance(next(iter(wkmap.values())), dict) else None

        T      = rsa_unwrap_key(priv, wrapped_key_b64)
        if enc_kdata_with_temp:
            K_data = aesgcm_decrypt(T, enc_kdata_with_temp["nonce"], enc_kdata_with_temp["ciphertext"])
        else:
            K_data = T  # direct wrap fallback

        plaintext = aesgcm_decrypt(K_data, enc_rec["nonce"], enc_rec["ciphertext"])
        record    = json.loads(plaintext.decode())
    except Exception as e:
        return jsonify({"error":f"Decryption failed: {e}"}), 500

    # verify signature
    sig_valid = False
    try:
        pat_pub_pem = enc_resp.get("patient_public_pem","")
        sig         = enc_resp.get("signature","")
        if pat_pub_pem and sig:
            pat_pub  = rsa_load_public(pat_pub_pem.encode())
            to_verify = (enc_rec["nonce"] + "|" + enc_rec["ciphertext"]).encode()
            sig_valid = rsa_verify(pat_pub, to_verify, sig)
    except Exception: pass

    # fetch all doctor notes for this patient
    notes = []
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        rn = http.get(f"{BACKEND}/doctor_notes/patient/{pat_code}", headers=bh(token), timeout=8)
        if rn.ok:
            nd = rn.json()
            notes = nd.get("notes", nd) if isinstance(nd, dict) else nd
            if isinstance(notes, list):
                # sort newest first
                notes = sorted(notes, key=lambda n: n.get("created_at",""), reverse=True)
    except Exception:
        pass   # notes are best-effort; don't fail the whole request

    return jsonify({"record": record, "sig_valid": sig_valid,
                    "expires_at": expires_at, "notes": notes})


# ── NEW ENDPOINTS ─────────────────────────────────────────────────────────

@app.route("/api/lookup_patient", methods=["POST","OPTIONS"])
@login_required(role="doctor")
def api_lookup_patient():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    code = d.get("profile_code","").strip()
    # check backend has this patient
    try:
        r = http.get(f"{BACKEND}/get_patient_public/{code}", headers=bh(), timeout=6)
        if r.ok:
            return jsonify({"found": True, "profile_code": code})
        return jsonify({"found": False}), 404
    except Exception as e:
        return jsonify({"found": False, "error": str(e)}), 502

@app.route("/api/upload_report", methods=["POST","OPTIONS"])
@login_required(role="doctor")
def api_upload_report():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = request.headers.get("Authorization","").replace("Bearer ","")
    d = request.get_json(force=True)
    try:
        r = http.post(f"{BACKEND}/reports/upload",
            json={"patient_id":d.get("patient_id",""),
                  "encrypted_report_blob":d.get("encrypted_report_blob",{}),
                  "encrypted_aes_key":d.get("encrypted_aes_key",""),
                  "file_hash":d.get("file_hash","")},
            headers=bh(token), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/upload_image", methods=["POST","OPTIONS"])
@login_required(role="doctor")
def api_upload_image():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        files = {"image": (request.files["image"].filename, request.files["image"].stream, "application/octet-stream")}
        data = {k:v for k,v in request.form.items()}
        r = http.post(f"{BACKEND}/images/upload", files=files, data=data,
            headers={"X-API-Key":api_key(),"Authorization":f"Bearer {token}"}, timeout=30)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/doctor_patients")
@login_required(role="doctor")
def api_doctor_patients():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/access/doctor_patients", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/health")
def health_check():
    return jsonify({"status": "ok"}), 200

@app.route("/api/audit_log")
@login_required(role="doctor")
def api_audit_log():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/audit/log", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/doctor/appointment-requests", methods=["GET"])
@login_required(role="doctor")
def proxy_doctor_appointments():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        r = http.get(f"{BACKEND}/api/doctor/appointment-requests", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error": str(e)}), 502

@app.route("/api/doctor/appointment-requests/<req_id>/respond", methods=["POST"])
@login_required(role="doctor")
def proxy_doctor_respond_appointment(req_id):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        r = http.post(f"{BACKEND}/api/doctor/appointment-requests/{req_id}/respond", json=request.get_json(force=True), headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error": str(e)}), 502

@app.route("/api/doctor/qr", methods=["GET"])
@login_required(role="doctor")
def proxy_doctor_qr():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        r = http.get(f"{BACKEND}/api/doctor/qr", headers=bh(token), timeout=8)
        # Note: qr returns an image
        return Response(r.content, content_type=r.headers.get("Content-Type", "image/png"))
    except Exception as e: return jsonify({"error": str(e)}), 502

# ── DOCTOR NOTES ──────────────────────────────────────────────────────────

@app.route("/api/add_note", methods=["POST", "OPTIONS"])
@login_required(role="doctor")
def api_add_note():
    """Doctor adds a clinical note to a patient profile. Server enforces access check."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    body = request.get_json(force=True) or {}

    doc_code = body.get("doctor_code", "").strip()
    pw       = body.get("password", "")

    try:
        unlock_doctor_private_key(doc_code, pw)   # validates password only
    except ValueError as e:
        code = 404 if "not found" in str(e).lower() else 401
        return jsonify({"error": str(e)}), code

    folder = doc_dir(doc_code)
    meta   = json.load(open(os.path.join(folder, "doctor_data.json")))
    try:
        r = http.post(f"{BACKEND}/doctor_notes/add",
            json={
                "patient_code":          body.get("patient_code", ""),
                "doctor_code":           doc_code,
                "doctor_name":           meta.get("name", ""),
                "doctor_specialization": meta.get("specialization", ""),
                "doctor_hospital":       meta.get("hospital", ""),
                "note_type":             body.get("note_type", "General"),
                "note_text":             body.get("note_text", ""),
                "visit_date":            body.get("visit_date", ""),
                "image_b64":             body.get("image_b64", ""),
                "image_type":            body.get("image_type", ""),
            },
            headers=bh(), timeout=30)
        try:
            resp_json = r.json()
        except Exception:
            resp_json = {"error": f"Server error (HTTP {r.status_code}) — could not save note. "
                                  f"Ensure access is approved and server is running."}
        return jsonify(resp_json), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/doctor_notes/<patient_code>")
@login_required(role="doctor")
def api_doctor_notes_list(patient_code):
    """Fetch all notes for a patient; returns filtered list for this doctor."""
    doc_code = request.args.get("doctor_code", "")
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        r = http.get(f"{BACKEND}/doctor_notes/patient/{patient_code}",
                     headers=bh(token), timeout=8)
        # Server returns a JSON list directly (not a dict with "notes" key)
        notes = r.json() if r.ok else []
        if isinstance(notes, dict):
            notes = notes.get("notes", [])
        if not isinstance(notes, list):
            notes = []
        # Filter by doctor_code client side (server returns all notes for patient)
        if doc_code:
            notes = [n for n in notes if n.get("doctor_code") == doc_code]
        # Normalise field name: server stores id as 'id', JS expects 'note_id'
        for n in notes:
            if "note_id" not in n and "id" in n:
                n["note_id"] = n["id"]
        return jsonify(notes), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/delete_note/<note_id>", methods=["DELETE", "OPTIONS"])
@login_required(role="doctor")
def api_delete_note(note_id):
    """Doctor deletes their own note."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    body     = request.get_json(force=True) or {}
    doc_code = body.get("doctor_code", "").strip()
    pw       = body.get("password", "")

    try:
        unlock_doctor_private_key(doc_code, pw)   # validates password only
    except ValueError as e:
        code = 404 if "not found" in str(e).lower() else 401
        return jsonify({"error": str(e)}), code

    try:
        r = http.delete(f"{BACKEND}/doctor_notes/{note_id}",
                        json={"doctor_code": doc_code},
                        headers=bh(), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/note_images/<filename>")
@login_required(role="doctor")
def api_note_image(filename):
    """Proxy note images from the backend server for display in the doctor portal."""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        r = http.get(f"{BACKEND}/note_images/{filename}",
                     headers=bh(token), timeout=10, stream=True)
        if not r.ok:
            return jsonify({"error": "image not found"}), 404
        from flask import Response
        return Response(r.content, content_type=r.headers.get("Content-Type", "image/jpeg"))
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ════════════════════════════════════════════════════════════════════════════
#   EMR MODULE PROXY ROUTES  (doctor portal → backend /emr/*)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/emr/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
@login_required(role="doctor")
def emr_proxy(subpath):
    """Generic proxy for all /emr/* endpoints on the backend."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    headers = bh()
    if token:
        headers["Authorization"] = f"Bearer {token}"
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


if __name__ == "__main__":
    print("  Doctor Portal → http://127.0.0.1:5002")
    app.run(host="127.0.0.1", port=5002, debug=False)
