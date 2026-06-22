#!/usr/bin/env python3
"""Patient Portal — http://127.0.0.1:5001"""
import os, sys, json, time, secrets
from datetime import datetime, timezone, timedelta
from base64 import b64encode, b64decode
from flask import Flask, request, jsonify, send_file, session, redirect, Response
import requests as http

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from common.crypto_utils import (
    generate_rsa_keypair, rsa_serialize_private, rsa_serialize_public,
    generate_aes_key, aesgcm_encrypt, aesgcm_decrypt, rsa_sign, rsa_verify,
    derive_kek_from_password, wrap_key_with_kek, unwrap_key_with_kek,
    rsa_load_private, rsa_load_public, rsa_unwrap_key, rsa_wrap_key,
)
from common.secure_key_store import SecureKeyStore

# Add portals dir to sys.path so auth_utils is importable as a sibling module
_PORTALS_DIR = os.path.dirname(__file__)
if _PORTALS_DIR not in sys.path:
    sys.path.insert(0, _PORTALS_DIR)
from auth_utils import login_required  # noqa: E402

BACKEND   = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")
USERS_DIR = os.path.join(ROOT, "client", "Users")
LANDING   = "http://127.0.0.1:5003"
os.makedirs(USERS_DIR, exist_ok=True)

app = Flask(__name__)
# Shared secret key (same file used by landing.py so sessions are consistent)
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
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type,X-API-Key,Authorization"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,DELETE"
    return r

def api_key():
    kf = os.path.join(ROOT, "server", "api_key.txt")
    return open(kf).read().strip() if os.path.exists(kf) else ""

def bh(token=""):
    h = {"X-API-Key": api_key(), "Content-Type": "application/json"}
    if token: h["Authorization"] = f"Bearer {token}"
    return h

def user_dir(code):  return os.path.join(USERS_DIR, code)
def user_json(code): return os.path.join(user_dir(code), "user_data.json")

_HTML_CACHE = {}
def get_html():
    ui = os.path.join(os.path.dirname(__file__), "patient_ui.html")
    if os.path.exists(ui):
        return open(ui, encoding="utf-8").read()
    return "<h1>patient_ui.html not found</h1>"

@app.route("/")
def index():
    # If no active session, send user to the landing page to log in first
    if not session.get("logged_in"):
        return redirect(LANDING)
    return get_html()

# ── LEGACY ROUTES ──────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST","OPTIONS"])
@login_required(role="patient")
def api_register():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    name, age    = d.get("name",""), d.get("age","")
    email, notes = d.get("email",""), d.get("notes","")
    pw           = d.get("password","")
    if not name: return jsonify({"error":"Name is required"}), 400
    if not pw:   return jsonify({"error":"Password is required"}), 400
    priv, pub = generate_rsa_keypair()
    K_data = generate_aes_key()
    record = {"name":name,"age":age,"email":email,"notes":notes}
    plain  = json.dumps(record, ensure_ascii=False).encode()
    enc    = aesgcm_encrypt(K_data, plain)
    sig    = rsa_sign(priv, (enc["nonce"]+"|"+enc["ciphertext"]).encode())
    kek, salt = derive_kek_from_password(pw)
    wrapped_k = wrap_key_with_kek(kek, K_data)
    priv_pem  = rsa_serialize_private(priv)
    pub_pem   = rsa_serialize_public(pub)
    profile_code = b64encode(os.urandom(6)).decode().replace("=","").replace("/","_")
    pdir = user_dir(profile_code)
    os.makedirs(pdir, exist_ok=True)
    import hashlib
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
    local = {"profile_code":profile_code,"patient_details":record,
             "patient_public_pem":pub_pem.decode(),"encrypted_record":enc,
             "signature":sig,"key_protection":{"wrapped_k":wrapped_k,"salt_b64":b64encode(salt).decode()},
             "password_hash":pw_hash,"jwt_token":""}
    with open(user_json(profile_code),"w") as f: json.dump(local,f,indent=2)
    # Store private key in Windows Credential Manager (DPAPI-backed).
    # The key exists only in memory here and in the OS credential vault —
    # never written to a project file.
    SecureKeyStore.store_private_key(f"patient__{profile_code}", priv_pem)
    with open(os.path.join(pdir,"patient_public.pem"),"wb") as f:  f.write(pub_pem)
    try:
        http.post(f"{BACKEND}/register_user",
            json={"profile_code":profile_code,"encrypted_record":enc,
                  "signature":sig,"patient_public_pem":pub_pem.decode()},
            headers=bh(), timeout=8)
    except Exception as e: print(f"[warn] legacy: {e}")

    # Also register in users_db so JWT login works for Reports/History/Audit
    if email:
        try:
            http.post(f"{BACKEND}/internal/register_user_db",
                json={"email":email,"name":name,"role":"patient",
                      "password_hash":pw_hash,"profile_code":profile_code,
                      "public_key":pub_pem.decode(),
                      "encrypted_private_key":""},
                headers=bh(), timeout=8)
        except Exception as e: print(f"[warn] users_db register: {e}")

    return jsonify({"profile_code":profile_code})

@app.route("/api/load_profile", methods=["POST","OPTIONS"])
@login_required(role="patient")
def api_load_profile():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    code, pw = d.get("profile_code","").strip(), d.get("password","")
    uf = user_json(code)
    if not os.path.exists(uf): return jsonify({"error":"Profile not found on this machine"}), 404
    with open(uf) as f: local = json.load(f)
    kp = local.get("key_protection",{})
    if kp.get("wrapped_k"):
        try:
            salt = b64decode(kp["salt_b64"])
            kek,_ = derive_kek_from_password(pw, salt=salt)
            unwrap_key_with_kek(kek, kp["wrapped_k"])
        except: return jsonify({"error":"Wrong password"}), 401
    rec = local.get("patient_details",{})
    return jsonify({"name":rec.get("name",""),"email":rec.get("email","")})

@app.route("/api/record/<code>")
@login_required(role="patient")
def api_record(code):
    uf = user_json(code)
    if not os.path.exists(uf): return jsonify({"error":"Profile not found"}), 404
    with open(uf) as f: local = json.load(f)
    return jsonify({"record":local.get("patient_details",{})})

@app.route("/api/requests/<code>")
@login_required(role="patient")
def api_requests(code):
    try:
        r = http.get(f"{BACKEND}/active_requests", headers=bh(), timeout=8)
        all_r = r.json() if r.ok else []
    except: return jsonify({"error":"Cannot reach backend"}), 502
    mine = [x for x in all_r if x.get("profile_code")==code]
    priv = None
    try:
        priv_pem = SecureKeyStore.load_private_key(f"patient__{code}")
        priv = rsa_load_private(priv_pem)
    except KeyError:
        # Key not in credential store (account registered on another machine or
        # before this refactor). Doctor profile info will be omitted from results.
        pass
    except Exception as e:
        print(f"[warn] could not load patient private key from credential store: {e}")
    result = []
    for req in mine:
        entry = {**req,"doctor_name":None,"doctor_specialization":None,"doctor_hospital":None}
        enc_b64 = req.get("encrypted_doctor_profile_b64")
        if enc_b64 and priv:
            try:
                raw = rsa_unwrap_key(priv, enc_b64)
                p   = json.loads(raw.decode())
                entry.update({"doctor_name":p.get("name"),"doctor_specialization":p.get("specialization"),
                              "doctor_hospital":p.get("hospital")})
            except: pass
        result.append(entry)
    return jsonify({"requests":result})

@app.route("/api/approve", methods=["POST","OPTIONS"])
@login_required(role="patient")
def api_approve():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    code, req_id = d.get("profile_code",""), d.get("request_id","")
    doc_code, doc_pub, pw = d.get("doctor_code",""), d.get("doctor_public_pem",""), d.get("password","")
    uf = user_json(code)
    if not os.path.exists(uf): return jsonify({"error":"Profile not found"}), 404
    with open(uf) as f: local = json.load(f)
    kp = local.get("key_protection",{})
    try:
        salt = b64decode(kp["salt_b64"]); kek,_ = derive_kek_from_password(pw, salt=salt)
        K_data = unwrap_key_with_kek(kek, kp["wrapped_k"])
    except: return jsonify({"error":"Wrong password"}), 401
    try:
        doc_pub_obj = rsa_load_public(doc_pub.encode())
        T = os.urandom(32); enc_kdata = aesgcm_encrypt(T, K_data)
        wrapped_T = rsa_wrap_key(doc_pub_obj, T)
        expires = (datetime.now(timezone.utc)+timedelta(hours=24)).isoformat()
    except Exception as e: return jsonify({"error":f"Crypto: {e}"}), 500
    try:
        r = http.post(f"{BACKEND}/approve_request",
            json={"request_id":req_id,"doctor_code":doc_code,"patient_code":code,
                  "wrapped_key":wrapped_T,"encrypted_kdata_with_temp":enc_kdata,
                  "temp_key_expires_at":expires},
            headers=bh(), timeout=8)
        if not r.ok: return jsonify({"error":r.text}), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502
    return jsonify({"status":"ok"})

@app.route("/api/deny", methods=["POST","OPTIONS"])
@login_required(role="patient")
def api_deny():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    try:
        r = http.post(f"{BACKEND}/update_request_status",
            json={"request_id":d.get("request_id"),"status":"denied"}, headers=bh(), timeout=8)
        return jsonify({"status":"ok"}) if r.ok else (jsonify({"error":r.text}), r.status_code)
    except Exception as e: return jsonify({"error":str(e)}), 502

# ── NEW ENDPOINTS ──────────────────────────────────────────────────────────

@app.route("/api/auth/otp", methods=["POST","OPTIONS"])
def patient_otp():  # intentionally unprotected — used during registration flow
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    try:
        r = http.post(f"{BACKEND}/auth/otp/send", json={"email":d.get("email","")}, headers=bh(), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/auth/verify_otp", methods=["POST","OPTIONS"])
def patient_verify_otp():  # intentionally unprotected — used during registration flow
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    try:
        r = http.post(f"{BACKEND}/auth/otp/verify",
                      json={"email":d.get("email",""),"otp":d.get("otp","")}, headers=bh(), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/auth/login", methods=["POST","OPTIONS"])
def patient_login():  # intentionally unprotected — this IS the login endpoint
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    import hashlib
    pw_hash = hashlib.sha256(d.get("password","").encode()).hexdigest()
    try:
        r = http.post(f"{BACKEND}/auth/login",
                      json={"email":d.get("email",""),"password_hash":pw_hash}, headers=bh(), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/reports/<patient_id>")
@login_required(role="patient")
def patient_reports(patient_id):
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/reports/patient/{patient_id}", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/report/<record_id>")
@login_required(role="patient")
def patient_report_detail(record_id):
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/reports/{record_id}", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/access_requests_jwt")
@login_required(role="patient")
def patient_jwt_access_requests():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/access/patient_requests", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/access_respond", methods=["POST","OPTIONS"])
@login_required(role="patient")
def patient_access_respond():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = request.headers.get("Authorization","").replace("Bearer ","")
    d = request.get_json(force=True)
    try:
        r = http.post(f"{BACKEND}/access/respond", json=d, headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/login_history")
@login_required(role="patient")
def patient_login_history():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/auth/login_history", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/audit_log")
@login_required(role="patient")
def patient_audit_log():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/audit/log", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502

@app.route("/api/lookup_doctor", methods=["POST","OPTIONS"])
@login_required(role="patient")
def api_lookup_doctor():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True); code = d.get("doctor_code","").strip()
    doctors_dir = os.path.join(ROOT, "doctor", "Doctors")
    if os.path.exists(doctors_dir):
        for folder in os.listdir(doctors_dir):
            mp = os.path.join(doctors_dir, folder, "doctor_data.json")
            if os.path.exists(mp):
                try:
                    m = json.load(open(mp))
                    if m.get("doctor_code") == code:
                        return jsonify({"found":True,"name":m.get("name",""),
                            "specialization":m.get("specialization",""),"hospital":m.get("hospital","")})
                except: pass
    sp = os.path.join(ROOT,"server","Doctors",f"{code}.json")
    if os.path.exists(sp): return jsonify({"found":True,"name":"","specialization":"","hospital":""})
    return jsonify({"found":False}), 404

@app.route("/api/qr_transfer", methods=["POST","OPTIONS"])
@login_required(role="patient")
def api_qr_transfer():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    pat_code, doc_code, pw = d.get("profile_code",""), d.get("doctor_code",""), d.get("password","")
    uf = user_json(pat_code)
    if not os.path.exists(uf): return jsonify({"error":"Patient profile not found"}), 404
    with open(uf) as f: local = json.load(f)
    kp = local.get("key_protection",{})
    try:
        salt = b64decode(kp["salt_b64"]); kek,_ = derive_kek_from_password(pw, salt=salt)
        K_data = unwrap_key_with_kek(kek, kp["wrapped_k"])
    except: return jsonify({"error":"Wrong password"}), 401
    doc_pub_pem = None
    doctors_dir = os.path.join(ROOT, "doctor", "Doctors")
    if os.path.exists(doctors_dir):
        for folder in os.listdir(doctors_dir):
            mp = os.path.join(doctors_dir, folder, "doctor_data.json")
            pp = os.path.join(doctors_dir, folder, "doctor_public.pem")
            if os.path.exists(mp) and os.path.exists(pp):
                try:
                    m = json.load(open(mp))
                    if m.get("doctor_code") == doc_code:
                        doc_pub_pem = open(pp,"rb").read().decode(); break
                except: pass
    if not doc_pub_pem:
        sp = os.path.join(ROOT,"server","Doctors",f"{doc_code}.json")
        if os.path.exists(sp):
            try: doc_pub_pem = json.load(open(sp)).get("public_pem","")
            except: pass
    if not doc_pub_pem: return jsonify({"error":"Doctor not found"}), 404
    try:
        doc_pub_obj = rsa_load_public(doc_pub_pem.encode())
        T = os.urandom(32); enc_kdata = aesgcm_encrypt(T, K_data)
        wrapped_T = rsa_wrap_key(doc_pub_obj, T)
        expires   = (datetime.now(timezone.utc)+timedelta(hours=24)).isoformat()
        enc_b64   = rsa_wrap_key(doc_pub_obj,
                      json.dumps({"doctor_code":doc_code,"name":"QR"}).encode())
    except Exception as e: return jsonify({"error":f"Crypto: {e}"}), 500
    try:
        rr = http.post(f"{BACKEND}/request_access_simple/{pat_code}",
            json={"doctor_code":doc_code,"doctor_public_pem":doc_pub_pem,
                  "encrypted_doctor_profile_b64":enc_b64}, headers=bh(), timeout=8)
        rd = rr.json()
        req_id = rd.get("request_id") or (rd.get("request") or {}).get("request_id")
        if not req_id:
            ar = http.get(f"{BACKEND}/active_requests", headers=bh(), timeout=6).json()
            found = next((x for x in ar if x.get("profile_code")==pat_code
                          and x.get("doctor_code")==doc_code and x.get("status")=="pending"), None)
            req_id = found["request_id"] if found else None
        if not req_id: return jsonify({"error":"Could not create request"}), 500
        ra = http.post(f"{BACKEND}/approve_request",
            json={"request_id":req_id,"doctor_code":doc_code,"patient_code":pat_code,
                  "wrapped_key":wrapped_T,"encrypted_kdata_with_temp":enc_kdata,
                  "temp_key_expires_at":expires}, headers=bh(), timeout=8)
        if not ra.ok: return jsonify({"error":ra.text}), ra.status_code
    except Exception as e: return jsonify({"error":str(e)}), 502
    return jsonify({"status":"ok","expires_at":expires})

# ── DOCTOR NOTES (patient view) ────────────────────────────────────────────

def _save_notes_locally(patient_code, notes):
    """Persist doctor notes into the patient's local user_data.json."""
    uf = user_json(patient_code)
    if not os.path.exists(uf):
        return   # no local profile yet — nothing to update
    try:
        with open(uf) as f:
            local = json.load(f)
        local["doctor_notes"] = notes
        local["doctor_notes_synced_at"] = datetime.now(timezone.utc).isoformat()
        with open(uf, "w") as f:
            json.dump(local, f, indent=2)
    except Exception as e:
        print(f"[warn] could not save notes locally: {e}")

@app.route("/api/doctor_notes/<patient_code>")
@login_required(role="patient")
def api_patient_notes(patient_code):
    """Fetch doctor notes from server and cache them in local user_data.json."""
    try:
        r = http.get(f"{BACKEND}/doctor_notes/patient/{patient_code}",
                     headers=bh(), timeout=8)
        data  = r.json() if r.ok else {}
        notes = data.get("notes", []) if isinstance(data, dict) else []
        # Write-through to local device
        _save_notes_locally(patient_code, notes)
        return jsonify(notes), r.status_code
    except Exception as e:
        # Fallback: try to serve cached notes from local file
        uf = user_json(patient_code)
        if os.path.exists(uf):
            try:
                with open(uf) as f:
                    local = json.load(f)
                cached = local.get("doctor_notes", [])
                if cached:
                    return jsonify(cached), 200
            except Exception:
                pass
        return jsonify({"error": str(e)}), 502

@app.route("/api/note_images/<filename>")
@login_required(role="patient")
def api_note_image(filename):
    """Proxy note images from the backend server."""
    try:
        r = http.get(f"{BACKEND}/note_images/{filename}",
                     headers={"X-API-Key": api_key()}, timeout=10, stream=True)
        if not r.ok:
            return jsonify({"error": "image not found"}), 404
        return Response(r.content, content_type=r.headers.get("Content-Type", "image/jpeg"))
    except Exception as e:
        return jsonify({"error": str(e)}), 502

@app.route("/api/patient/appointment-request", methods=["POST"])
@login_required(role="patient")
def proxy_appointment_request():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        r = http.post(f"{BACKEND}/api/patient/appointment-request", json=request.get_json(force=True), headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error": str(e)}), 502

@app.route("/api/patient/appointment-requests", methods=["GET"])
@login_required(role="patient")
def proxy_patient_appointments():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        r = http.get(f"{BACKEND}/api/patient/appointment-requests", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e: return jsonify({"error": str(e)}), 502

@app.route("/api/patient/barcode", methods=["GET"])
@login_required(role="patient")
def proxy_patient_barcode():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        r = http.get(f"{BACKEND}/api/patient/barcode", headers=bh(token), timeout=8)
        return Response(r.content, content_type=r.headers.get("Content-Type", "image/png"))
    except Exception as e: return jsonify({"error": str(e)}), 502

@app.route("/api/patient/qr", methods=["GET"])
@login_required(role="patient")
def proxy_patient_qr():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        r = http.get(f"{BACKEND}/api/patient/qr", headers=bh(token), timeout=8)
        return Response(r.content, content_type=r.headers.get("Content-Type", "image/png"))
    except Exception as e: return jsonify({"error": str(e)}), 502

# ── EMR MODULE PROXY ROUTES  (patient portal → backend /emr/*) ─────────────

@app.route("/api/emr/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
@login_required(role="patient")
def emr_proxy(subpath):
    """Generic proxy for all /emr/* endpoints on the backend."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    headers = bh(token)
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
    print("  Patient Portal → http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)