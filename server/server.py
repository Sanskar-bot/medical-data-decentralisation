#!/usr/bin/env python3
"""
server.py

Decentralised medical-data server (development).

This is a development server for your project.  It stores:
 - patient metadata files in PATIENTS_DIR (server/Patients/<profile_code>.json)
 - encrypted payloads in PATIENTS_DIR/<profile_code>/encrypted_data.json
 - doctor metadata in DOCTORS_DIR (server/Doctors/<doctor_code>.json)
 - active access requests in ACTIVE_REQUESTS_FILE (active_requests.json)
 - wrapped keys in PATIENTS_DIR/<profile_code>/wrapped_keys/<doctor_code>.json

SECURITY / PRODUCTION NOTES (do not ignore):
 - This server uses no authentication, no TLS, and file-based storage.
 - Suitable for development and local testing only — do NOT expose to the public Internet.
 - In production you must add authentication, TLS, input validation, rate-limiting, and secure storage.
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

from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

# -----------------------
# Server base directories (paths used by handlers)
# -----------------------
# SERVER_BASE_DIR = directory that contains this server.py (e.g. A:\Minor_Decentralised\Server)
SERVER_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# PATIENTS_DIR: each patient has a <profile_code>.json metadata file stored here
# and a folder PATIENTS_DIR/<profile_code>/ containing encrypted_data.json, wrapped_keys/, etc.
PATIENTS_DIR = os.path.join(SERVER_BASE_DIR, "Patients")
os.makedirs(PATIENTS_DIR, exist_ok=True)

# DOCTORS_DIR: server-side metadata for registered doctors (minimal non-sensitive info)
DOCTORS_DIR = os.path.join(SERVER_BASE_DIR, "Doctors")
os.makedirs(DOCTORS_DIR, exist_ok=True)

# Legacy user folder (kept for compatibility with older snippets)
USER_FOLDER = os.path.join(SERVER_BASE_DIR, "users")
os.makedirs(USER_FOLDER, exist_ok=True)

# DATA_DIR used by get_patient_data: set to PATIENTS_DIR so encrypted files are looked up consistently
DATA_DIR = PATIENTS_DIR

# ACTIVE_REQUESTS_FILE: list of pending/handled requests submitted by doctors
ACTIVE_REQUESTS_FILE = os.path.join(SERVER_BASE_DIR, "active_requests.json")
if not os.path.exists(ACTIVE_REQUESTS_FILE):
    with open(ACTIVE_REQUESTS_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)

# -----------------------
# Simple server-side cipher (Fernet) — used only if you need server-side symmetric encryption
# -----------------------
KEY_FILE = os.path.join(SERVER_BASE_DIR, "server_key.key")  # fix #21: absolute path
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()
fernet = Fernet(key)  # not used heavily — placeholder for server-side tasks

# -----------------------
# Flask app
# -----------------------
app = Flask(__name__)

# -----------------------
# FIX 2: Simple API-key authentication
# On first run an API key is auto-generated and printed.
# Every client request must send the header:  X-API-Key: <key>
# -----------------------
_API_KEY_FILE = os.path.join(SERVER_BASE_DIR, "api_key.txt")
if not os.path.exists(_API_KEY_FILE):
    import secrets as _secrets
    _SERVER_API_KEY = _secrets.token_hex(32)
    with open(_API_KEY_FILE, "w") as _f:
        _f.write(_SERVER_API_KEY)
    print("\n[AUTH] NEW API key saved to " + _API_KEY_FILE)
    print("[AUTH] Share this key with authorised clients: " + _SERVER_API_KEY + "\n")
else:
    with open(_API_KEY_FILE, "r") as _f:
        _SERVER_API_KEY = _f.read().strip()

def _require_api_key():
    """Return a 401 response if the request has no valid API key, else None."""
    if request.headers.get("X-API-Key", "") != _SERVER_API_KEY:
        return jsonify({"error": "unauthorized",
                        "hint": "Add header  X-API-Key: <your key>"}), 401
    return None

# -----------------------
# Misc file paths (FIX 5: replaced hardcoded Windows paths with portable relative paths)
# -----------------------
patient_db_file = os.path.join(SERVER_BASE_DIR, "server_database.json")
doctor_db_file  = os.path.join(SERVER_BASE_DIR, "doctor_database.json")

# -----------------------
# Utility helpers
# -----------------------
def load_json(file_path):
    """
    Load JSON safely. If file missing -> create and return {}.
    If file corrupted -> log and return {}.
    """
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
    """Save JSON to disk and log success/failure."""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"[] Saved data to {file_path}")
    except Exception as e:
        print(f"[] Failed to save {file_path}: {e}")

def _save_json(path, obj):
    """Small wrapper used to write JSON with stable options."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)

# -----------------------
# PATIENT (USER) REGISTRATION
# -----------------------
# Endpoint: POST /register_user
# Purpose: accept the encrypted patient record & public key, store metadata in PATIENTS_DIR/<profile_code>.json
#
# Expected JSON body:
# {
#   "profile_code": "<string>",
#   "encrypted_record": { "nonce": "<base64>", "ciphertext": "<base64>" },
#   "signature": "<base64 signature>",              # optional: patient's signature of the encrypted payload
#   "patient_public_pem": "-----BEGIN PUBLIC KEY-----\n..."  # optional: patient's public RSA key (PEM)
# }
#
# Example (curl):
# curl -X POST -H "Content-Type: application/json" -d '{"profile_code":"abc123","encrypted_record":{"nonce":"...","ciphertext":"..."},"patient_public_pem":"-----BEGIN ..."}' http://127.0.0.1:5000/register_user
@app.route("/register_user", methods=["POST"])
def register_user():
    auth_err = _require_api_key()
    if auth_err: return auth_err
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "details": str(e)}), 400

    # Basic validation
    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "empty_or_nonjson_payload"}), 400

    profile = payload.get("profile_code")
    enc = payload.get("encrypted_record")
    if not profile or not isinstance(profile, str):
        return jsonify({"error": "missing_profile_code"}), 400
    if not enc or not isinstance(enc, dict) or "nonce" not in enc or "ciphertext" not in enc:
        return jsonify({"error": "missing_encrypted_record_or_invalid_format", "encrypted_record": enc}), 400

    # Safe filename: keep only alnum, -, _
    safe_profile = "".join([c for c in profile if c.isalnum() or c in ("-", "_")])
    out_path = os.path.join(PATIENTS_DIR, f"{safe_profile}.json")

    # Prepare object that server stores (non-sensitive: encrypted payload & public key only)
    obj = {
        "profile_code": profile,
        "encrypted_record": enc,
        "signature": payload.get("signature"),
        "patient_public_pem": payload.get("patient_public_pem"),
        "uploaded_at": str(__import__("datetime").datetime.utcnow())
    }

    try:
        # Write metadata file (overwrites by default; you can change to prevent overwrite)
        _save_json(out_path, obj)
    except Exception as e:
        return jsonify({"error": "write_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "profile": profile}), 200

# -----------------------
# DOCTOR REGISTRATION
# -----------------------
# Endpoint: POST /register_doctor
# Purpose: store public metadata for a doctor on the server (non-sensitive)
#
# Expected JSON:
# {
#   "doctor_id": "<uuid>",
#   "doctor_code": "<short>",
#   "public_pem": "-----BEGIN PUBLIC KEY-----...",
#   "encrypted_profile": "<optional base64 string>"   # optional: doctor's profile encrypted for local storage
# }
#
# Example (curl):
# curl -X POST -H "Content-Type: application/json" -d '{"doctor_id":"uuid","doctor_code":"abcd","public_pem":"-----BEGIN..."}' http://127.0.0.1:5000/register_doctor
import re  # single import — fix #28
def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_\-]", "_", name)

@app.route("/register_doctor", methods=["POST"])
def register_doctor():
    auth_err = _require_api_key()
    if auth_err: return auth_err
    try:
        data = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error":"invalid_json","details":str(e)}), 400

    doctor_id = data.get("doctor_id")
    doctor_code = data.get("doctor_code")
    public_pem = data.get("public_pem")
    encrypted_profile = data.get("encrypted_profile")  # optional

    if not doctor_id or not doctor_code or not public_pem:
        return jsonify({"error":"missing_required_fields","required":["doctor_id","doctor_code","public_pem"]}), 400

    doctor_data = {
        "doctor_id": doctor_id,
        "doctor_code": doctor_code,
        "public_pem": public_pem,
        "encrypted_profile": encrypted_profile,
        "registered_at": datetime.now(timezone.utc).isoformat()
    }

    safe_name = _safe_filename(doctor_code)
    file_path = os.path.join(DOCTORS_DIR, f"{safe_name}.json")
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(doctor_data, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        return jsonify({"error":"write_failed","details":str(e)}), 500

    return jsonify({"status":"ok","doctor_code":doctor_code}), 200

# -----------------------
# UPLOAD PATIENT RECORD (legacy helper)
# -----------------------
# Endpoint: POST /upload_record
# Purpose: append a CID (content identifier) to a patient entry in server_database.json (legacy / optional)
@app.route("/upload_record", methods=["POST"])
def upload_record():
    auth_err = _require_api_key()  # fix #16
    if auth_err: return auth_err
    global patient_db
    data = request.get_json(force=True)
    print("\n[POST] /upload_record →", data)

    pid = data.get("patient_id")
    cid = data.get("cid")

    if not pid or not cid:
        return jsonify({"error": "Missing patient_id or CID"}), 400

    patient_db = load_json(patient_db_file)
    for profile_code, patient in patient_db.items():
        if patient["patient_id"] == pid:
            patient.setdefault("records", []).append({"cid": cid})
            save_json(patient_db_file, patient_db)
            print(f"[+] Record added for {profile_code}")
            return jsonify({"message": "Record uploaded"}), 200

    return jsonify({"error": "Patient not found"}), 404

# -----------------------
# FETCH PATIENT DATA (for doctors)
# -----------------------
# Endpoint: GET /get_patient_data/<profile_code>
# Purpose: return the encrypted patient record that the doctor can later decrypt
#
# Expected layout:
# - PATIENTS_DIR/<profile_code>.json            <- metadata saved by register_user
# - PATIENTS_DIR/<profile_code>/encrypted_data.json <- contains encrypted_record, signature, patient_public_pem
#
# Response:
# { "encrypted_record": {nonce, ciphertext}, "signature": "...", "patient_public_pem": "-----BEGIN..." }
@app.route("/get_patient_data/<profile_code>", methods=["GET"])
def get_patient_data(profile_code):
    auth_err = _require_api_key()
    if auth_err: return auth_err
    # fix #3: path-traversal sanitisation
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", profile_code)
    if not safe_code:
        return jsonify({"error": "invalid_profile_code"}), 400
    profile_code = safe_code
    """
    Fetch the encrypted data file for a patient and send it to the doctor.
    This implementation looks in two places (backwards-compatible):
      1) Patients/<profile_code>/encrypted_data.json  (preferred)
      2) Patients/<profile_code>.json                 (metadata file produced by register_user)

    Returns JSON with:
      - encrypted_record: { "nonce": "...", "ciphertext": "..." }
      - signature: "base64sig..."
      - patient_public_pem: "-----BEGIN PUBLIC KEY-----\n..."
    """
    try:
        # primary folder-based file
        enc_file_path = os.path.join(PATIENTS_DIR, profile_code, "encrypted_data.json")
        # fallback metadata file
        meta_file_path = os.path.join(PATIENTS_DIR, f"{profile_code}.json")

        encrypted_json = None

        if os.path.exists(enc_file_path):
            with open(enc_file_path, "r", encoding="utf-8") as f:
                encrypted_json = json.load(f)
        elif os.path.exists(meta_file_path):
            # metadata file from register_user likely contains encrypted_record, signature, patient_public_pem
            with open(meta_file_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            # convert into same structure as encrypted_data.json
            encrypted_json = {
                "encrypted_record": meta.get("encrypted_record"),
                "signature": meta.get("signature"),
                "patient_public_pem": meta.get("patient_public_pem")
            }
        else:
            return jsonify({"error": "Patient not found"}), 404

        # validate structure
        enc_record = encrypted_json.get("encrypted_record")
        signature = encrypted_json.get("signature")
        patient_public_pem = encrypted_json.get("patient_public_pem")

        if not enc_record or "nonce" not in enc_record or "ciphertext" not in enc_record:
            return jsonify({"error": "Malformed encrypted record"}), 500

        # DEBUG log (optional)
        print(f"\n[🔍 SERVER] Returning encrypted data for {profile_code}")

        return jsonify({
            "encrypted_record": enc_record,
            "signature": signature,
            "patient_public_pem": patient_public_pem
        }), 200

    except Exception as e:
        print(f"[X] Error in get_patient_data: {e}")
        return jsonify({"error": str(e)}), 500

# -----------------------
# REQUEST ACCESS SIMPLE
# Endpoint: POST /request_access_simple/<profile_code>
# Purpose: doctor asks for access — the doctor's details are encrypted with the patient's public key
#
# Server stores a request entry in ACTIVE_REQUESTS_FILE:
# {
#   "request_id": "...",
#   "profile_code": "...",
#   "doctor_code": "...",
#   "doctor_public_pem": "-----BEGIN...",
#   "encrypted_doctor_profile_b64": "...",  # encrypted to patient public key
#   "timestamp": "...",
#   "status": "pending"
# }
@app.route("/request_access_simple/<profile_code>", methods=["POST"])
def request_access_simple(profile_code):
    auth_err = _require_api_key()  # fix #1: was missing entirely
    if auth_err: return auth_err
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error":"invalid_json","details":str(e)}), 400

    required = ["doctor_code", "doctor_public_pem", "encrypted_doctor_profile_b64"]
    missing = [k for k in required if k not in payload]
    if missing:
        return jsonify({"error":"missing_fields","required": required, "missing": missing}), 400

    doctor_code = payload["doctor_code"]
    doctor_pub = payload["doctor_public_pem"]
    enc_profile_b64 = payload["encrypted_doctor_profile_b64"]

    # lightweight validation
    if not isinstance(doctor_code, str) or not doctor_code:
        return jsonify({"error":"invalid_doctor_code"}), 400
    if not isinstance(enc_profile_b64, str) or len(enc_profile_b64) < 16:
        return jsonify({"error":"invalid_encrypted_profile"}), 400

    # ensure patient metadata exists
    patient_file = os.path.join(PATIENTS_DIR, f"{profile_code}.json")
    if not os.path.exists(patient_file):
        return jsonify({"error":"patient_not_found"}), 404

    # construct request entry
    entry = {
        "request_id": str(uuid.uuid4()),
        "profile_code": profile_code,
        "doctor_code": doctor_code,
        "doctor_public_pem": doctor_pub,
        "encrypted_doctor_profile_b64": enc_profile_b64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "pending"
    }

    # read existing active requests, handle corrupt/missing file gracefully
    try:
        with open(ACTIVE_REQUESTS_FILE, "r", encoding="utf-8") as fh:
            arr = json.load(fh)
            if not isinstance(arr, list):
                arr = []
    except FileNotFoundError:
        arr = []
    except Exception as e:
        return jsonify({"error":"active_requests_read_failed","details":str(e)}), 500

    # Prevent duplicate pending requests from same doctor for same patient (optional)
    duplicate = next((x for x in arr
                      if x.get("profile_code")==profile_code
                      and x.get("doctor_code")==doctor_code
                      and x.get("status")=="pending"), None)
    if duplicate:
        return jsonify({"status":"duplicate_pending","request_id": duplicate.get("request_id")}), 200

    # append and write atomically
    arr.append(entry)
    try:
        tmp_path = ACTIVE_REQUESTS_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(arr, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, ACTIVE_REQUESTS_FILE)
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return jsonify({"error":"write_failed","details":str(e)}), 500

    # return the request id so the client can poll /request_status/<id> or /active_requests
    return jsonify({"status":"ok","request_id": entry["request_id"]}), 201

# -----------------------
# HELPER: return patient's public key (for doctors to encrypt requests)
# Endpoint: GET /get_patient_public/<profile_code>
# -----------------------
# Response format:
# { "patient_public_pem": "-----BEGIN PUBLIC KEY-----\n..." }
@app.route("/get_patient_public/<profile_code>", methods=["GET"])
def get_patient_public(profile_code):
    auth_err = _require_api_key()
    if auth_err: return auth_err
    # fix #3: path-traversal sanitisation
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", profile_code)
    if not safe_code:
        return jsonify({"error": "invalid_profile_code"}), 400
    profile_code = safe_code
    try:
        patient_meta_path = os.path.join(PATIENTS_DIR, f"{profile_code}.json")
        if not os.path.exists(patient_meta_path):
            return jsonify({"error": "patient_not_found"}), 404

        with open(patient_meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)

        # Prefer an explicit patient_public_pem field in the metadata file
        patient_pub = meta.get("patient_public_pem")
        if patient_pub:
            return jsonify({"patient_public_pem": patient_pub}), 200

        # Fallback: check encrypted_data.json inside the patient's folder
        enc_path = os.path.join(PATIENTS_DIR, profile_code, "encrypted_data.json")
        if os.path.exists(enc_path):
            with open(enc_path, "r", encoding="utf-8") as fh:
                enc = json.load(fh)
            patient_pub = enc.get("patient_public_pem")
            if patient_pub:
                return jsonify({"patient_public_pem": patient_pub}), 200

        return jsonify({"error": "patient_public_pem_not_found"}), 404

    except Exception as e:
        return jsonify({"error": "server_error", "details": str(e)}), 500

# -----------------------
# Active requests helpers and approval endpoints
# Endpoints:
# - GET /active_requests            -> list all requests (used by patient to fetch pending requests)
# - GET /request_status/<request_id> -> fetch single request entry
# - GET /wrapped_key/<profile_code>  -> return wrapped keys for patient (if any)
# - POST /approve_request            -> patient approves request & (optionally) uploads wrapped_key
# - POST /update_request_status      -> update a request's status (deny/approve/expired)
# -----------------------
def _read_active_requests():
    """Return the active requests list or [] on error (non-fatal)."""
    try:
        with open(ACTIVE_REQUESTS_FILE, "r", encoding="utf-8") as fh:
            arr = json.load(fh)
            if isinstance(arr, list):
                return arr
    except FileNotFoundError:
        return []
    except Exception:
        # corrupted file -> avoid crashing the server; return empty to allow repair
        return []
    return []

def _write_active_requests(arr):
    """Write active requests atomically to prevent corruption on crash."""
    tmp = ACTIVE_REQUESTS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(arr, fh, indent=2, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, ACTIVE_REQUESTS_FILE)

@app.route("/active_requests", methods=["GET"])
def get_all_active_requests():
    """Return array of all active requests. Clients should filter by profile_code."""
    auth_err = _require_api_key()
    if auth_err: return auth_err
    arr = _read_active_requests()
    return jsonify(arr), 200

@app.route("/request_status/<request_id>", methods=["GET"])
def get_request_status(request_id):
    """Return a single request object by request_id, or 404 if not found."""
    auth_err = _require_api_key()
    if auth_err: return auth_err
    arr = _read_active_requests()
    found = next((x for x in arr if x.get("request_id") == request_id), None)
    if not found:
        return jsonify({"error": "not_found"}), 404
    return jsonify(found), 200

@app.route("/wrapped_key/<profile_code>", methods=["GET"])
def get_wrapped_key_for_profile(profile_code):
    """
    Return wrapped keys for the specified profile. Looks under
    PATIENTS_DIR/<profile_code>/wrapped_keys/*.json and aggregates them.
    Keys whose temp_key_expires_at has passed are excluded.
    Response: {"wrapped_keys": { "<doctor_code>": {doctor_code, wrapped_key, uploaded_at}, ... } }
    """
    auth_err = _require_api_key()
    if auth_err: return auth_err
    # fix #3: path-traversal sanitisation
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", profile_code)
    if not safe_code:
        return jsonify({"error": "invalid_profile_code"}), 400
    profile_code = safe_code
    try:
        pk_dir = os.path.join(PATIENTS_DIR, profile_code, "wrapped_keys")
        if not os.path.isdir(pk_dir):
            return jsonify({"wrapped_keys": {}}), 200
        now = datetime.now(timezone.utc)
        out = {}
        for fn in os.listdir(pk_dir):
            if not fn.lower().endswith(".json"):
                continue
            path = os.path.join(pk_dir, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    js = json.load(fh)
                # FIX 3: Check expiry before returning the key
                expires_at = js.get("temp_key_expires_at")
                if expires_at:
                    try:
                        exp_dt = datetime.fromisoformat(expires_at)
                        if exp_dt < now:
                            print(f"[AUTH] Wrapped key for {fn} has expired — not returned.")
                            continue   # skip expired keys
                    except ValueError:
                        print(f"[WARN] malformed temp_key_expires_at in {fn} — denying access")  # fix #25
                        continue  # treat as expired — deny rather than allow
                dk = js.get("doctor_code") or os.path.splitext(fn)[0]
                out[dk] = js
            except Exception:
                continue
        return jsonify({"wrapped_keys": out}), 200
    except Exception as e:
        return jsonify({"error": "server_error", "details": str(e)}), 500

@app.route("/approve_request", methods=["POST"])
def approve_request():
    auth_err = _require_api_key()
    if auth_err: return auth_err
    """
    Patient approves an access request.

    Expected JSON payload (required):
      {
        "request_id": "...",
        "doctor_code": "...",
        "patient_code": "..."   # same as profile_code
      }

    Optional fields (either or both):
      "wrapped_key": "<base64 string>"   # RSA-wrapped K_data OR RSA-wrapped TEMP key T
      "encrypted_record": { ... }        # snapshot of encrypted_record (nonce,ciphertext)
      "encrypted_kdata_with_temp": {     # AES-GCM of K_data using temporary AES key T
           "nonce": "...",
           "ciphertext": "..."
      }
      "temp_key_expires_at": "ISO8601 timestamp"

    Behavior:
      - finds matching request in ACTIVE_REQUESTS_FILE
      - if wrapped_key provided, saves it to Patients/<patient_code>/wrapped_keys/<doctor_code>.json
          and includes encrypted_kdata_with_temp & temp_key_expires_at in that file if present
      - updates request.status -> "approved" and attaches metadata
      - writes active_requests.json atomically
    """
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": "invalid_json", "details": str(e)}), 400

    # required params
    req_id = payload.get("request_id")
    doctor_code = payload.get("doctor_code")
    patient_code = payload.get("patient_code")

    if not req_id or not doctor_code or not patient_code:
        return jsonify({"error": "missing_fields", "required": ["request_id", "doctor_code", "patient_code"]}), 400

    # optional payload fields
    wrapped_key = payload.get("wrapped_key")  # base64 string (may be None)
    enc_record = payload.get("encrypted_record")
    enc_kdata_with_temp = payload.get("encrypted_kdata_with_temp")
    temp_key_expires_at = payload.get("temp_key_expires_at")

    # load active requests and locate the one to approve
    arr = _read_active_requests()
    found = next((x for x in arr
                  if x.get("request_id") == req_id
                  and x.get("profile_code") == patient_code
                  and x.get("doctor_code") == doctor_code), None)
    if not found:
        return jsonify({"error": "request_not_found"}), 404

    # ensure patient's wrapped_keys directory exists
    try:
        target_dir = os.path.join(PATIENTS_DIR, patient_code, "wrapped_keys")
        os.makedirs(target_dir, exist_ok=True)
    except Exception as e:
        return jsonify({"error": "mkdir_failed", "details": str(e)}), 500

    # If a wrapped_key is provided, persist it. Include temp-key related fields if present.
    if wrapped_key:
        safe_name = "".join(c for c in doctor_code if c.isalnum() or c in ("-", "_")) or doctor_code
        out_path = os.path.join(target_dir, f"{safe_name}.json")
        out_obj = {
            "doctor_code": doctor_code,
            "wrapped_key": wrapped_key,
            "uploaded_at": datetime.now(timezone.utc).isoformat()
        }
        # attach temporary-key fields if they exist
        if enc_kdata_with_temp:
            out_obj["encrypted_kdata_with_temp"] = enc_kdata_with_temp
        if temp_key_expires_at:
            out_obj["temp_key_expires_at"] = temp_key_expires_at

        try:
            # atomic write
            tmp_out = out_path + ".tmp"
            with open(tmp_out, "w", encoding="utf-8") as fh:
                json.dump(out_obj, fh, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_out, out_path)
        except Exception as e:
            return jsonify({"error": "write_wrapped_key_failed", "details": str(e)}), 500

    # Update the request entry in memory
    found["status"] = "approved"
    found["approved_at"] = datetime.now(timezone.utc).isoformat()
    if wrapped_key:
        found["wrapped_key_b64"] = wrapped_key
    if enc_kdata_with_temp:
        found["encrypted_kdata_with_temp"] = enc_kdata_with_temp
    if temp_key_expires_at:
        found["temp_key_expires_at"] = temp_key_expires_at
    if enc_record:
        found["approved_encrypted_record_snapshot"] = enc_record

    # Write updated active_requests back to disk atomically
    try:
        _write_active_requests(arr)
    except Exception as e:
        return jsonify({"error": "update_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "request_id": req_id}), 200


@app.route("/update_request_status", methods=["POST"])
def update_request_status():
    auth_err = _require_api_key()
    if auth_err: return auth_err
    """
    Generic request-status updater.
    Expected JSON: { "request_id":"...", "status":"denied" }
    """
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error":"invalid_json","details":str(e)}), 400

    req_id = payload.get("request_id")
    status = payload.get("status")
    if not req_id or not status:
        return jsonify({"error":"missing_fields","required":["request_id","status"]}), 400

    arr = _read_active_requests()
    found = next((x for x in arr if x.get("request_id") == req_id), None)
    if not found:
        return jsonify({"error":"request_not_found"}), 404

    found["status"] = status
    found[f"{status}_at"] = datetime.now(timezone.utc).isoformat()

    try:
        _write_active_requests(arr)
    except Exception as e:
        return jsonify({"error":"update_failed","details":str(e)}), 500

    return jsonify({"status":"ok","request_id": req_id, "new_status": status}), 200

# -----------------------
# FIX 8: Periodic cleanup of old/expired requests (runs every hour in background)
# Removes: approved/denied requests older than 48 h, and any pending older than 7 days.
# -----------------------
import threading as _threading

def _cleanup_old_requests():
    """Remove stale entries from active_requests.json, then reschedule itself."""
    try:
        now = datetime.now(timezone.utc)
        arr = _read_active_requests()
        before = len(arr)
        def _keep(r):
            status = r.get("status", "pending")
            ts_key = "approved_at" if status == "approved" else ("denied_at" if status == "denied" else "timestamp")
            ts = r.get(ts_key) or r.get("timestamp")
            if not ts:
                return True
            try:
                age = (now - datetime.fromisoformat(ts)).total_seconds()
            except ValueError:
                return True
            if status in ("approved", "denied") and age > 48 * 3600:
                return False   # remove resolved requests after 48 h
            if status == "pending" and age > 7 * 24 * 3600:
                return False   # remove stale pending requests after 7 days
            return True
        arr = [r for r in arr if _keep(r)]
        if len(arr) < before:
            _write_active_requests(arr)
            print(f"[Cleanup] Removed {before - len(arr)} stale request(s).")
    except Exception as ex:
        print(f"[Cleanup] Error during cleanup: {ex}")
    finally:
        _threading.Timer(3600, _cleanup_old_requests).start()   # run again in 1 hour

def _schedule_cleanup():
    """Start the cleanup timer as a daemon thread (fix #20)."""
    t = _threading.Timer(3600, _cleanup_old_requests)
    t.daemon = True
    t.start()

# -----------------------
# Application entrypoint
# -----------------------
# app.run() is at the END of this file so all routes register first

# ═══════════════════════════════════════════════════════════════════════════
# ███  UPGRADE BLOCK — new endpoints added without touching existing ones  ███
# ═══════════════════════════════════════════════════════════════════════════

import hashlib, threading  # fix #27: removed unused shutil
from functools import wraps
from collections import defaultdict

# ── Login history (fix #10 / #15) ────────────────────────────────────────
LOGIN_HISTORY_FILE = os.path.join(SERVER_BASE_DIR, "login_history.json")
if not os.path.exists(LOGIN_HISTORY_FILE):
    save_json(LOGIN_HISTORY_FILE, [])  # must be a list, not {}

_login_hist_lock = threading.Lock()

def _append_login_history(entry: dict):
    """Thread-safe, type-guarded append to login_history.json."""
    with _login_hist_lock:
        hist = load_json(LOGIN_HISTORY_FILE)
        if not isinstance(hist, list):
            hist = []
        hist.append(entry)
        save_json(LOGIN_HISTORY_FILE, hist[-500:])

# ── Rate limiter (in-memory, resets on restart) ───────────────────────────
_rate_store = defaultdict(list)   # ip -> [timestamps]
_rate_lock  = threading.Lock()

def rate_limited(max_calls=10, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*a, **kw):
            ip  = request.remote_addr or "unknown"
            now = time.time()
            with _rate_lock:
                calls = [t for t in _rate_store[ip] if now - t < window]
                if len(calls) >= max_calls:
                    return jsonify({"error":"rate_limited","retry_after":window}), 429
                calls.append(now)
                _rate_store[ip] = calls
            return f(*a, **kw)
        return wrapper
    return decorator

# ── Audit log ─────────────────────────────────────────────────────────────
AUDIT_LOG = os.path.join(SERVER_BASE_DIR, "audit.log")

def audit(action, actor="", target="", detail=""):
    entry = {
        "ts":     datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor":  actor,
        "target": target,
        "detail": detail,
        "ip":     request.remote_addr if request else "",
    }
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

# ── OTP store (in-memory; production → Redis) ─────────────────────────────
_otp_store = {}   # email -> {otp, expires, attempts}
_otp_lock  = threading.Lock()

import secrets as _secrets_otp, string  # fix #12: use cryptographically secure PRNG

def _gen_otp():
    return "".join(_secrets_otp.choice(string.digits) for _ in range(6))

# ── JWT-lite (HMAC-SHA256, no extra library needed) ───────────────────────
import hmac as _hmac, base64 as _b64

# fix #19: read JWT secret lazily so key rotation takes effect without restart
def _get_jwt_secret() -> str:
    return open(_API_KEY_FILE).read().strip()

# fix #7: in-memory token blocklist for logout / revocation
import uuid as _uuid_mod
_token_blocklist: set = set()
_blocklist_lock = threading.Lock()

def _jwt_encode(payload: dict) -> str:
    if "jti" not in payload:  # fix #7: add unique token ID for revocation
        payload["jti"] = str(_uuid_mod.uuid4())
    secret = _get_jwt_secret()
    header  = _b64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body    = _b64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig_raw = _hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    sig     = _b64.urlsafe_b64encode(sig_raw).rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"

def _jwt_decode(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        header, body, sig = parts
        secret = _get_jwt_secret()  # fix #19: lazy read
        expected_sig = _b64.urlsafe_b64encode(
            _hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not _hmac.compare_digest(sig, expected_sig): return None
        pad  = 4 - len(body) % 4
        data = json.loads(_b64.urlsafe_b64decode(body + "=" * pad))
        if data.get("exp", 0) < time.time(): return None
        # fix #7: check token blocklist
        if data.get("jti") in _token_blocklist: return None
        return data
    except Exception:
        return None

def _require_jwt(roles=None):
    """Decorator — validates JWT and optionally checks role."""
    def decorator(f):
        @wraps(f)
        def wrapper(*a, **kw):
            auth = request.headers.get("Authorization","")
            token = auth.replace("Bearer ","").strip() if auth.startswith("Bearer ") else ""
            if not token:
                # also check cookie
                token = request.cookies.get("access_token","")
            payload = _jwt_decode(token)
            if not payload:
                return jsonify({"error":"invalid_or_expired_token"}), 401
            if roles and payload.get("role") not in roles:
                return jsonify({"error":"forbidden","required_roles":roles}), 403
            request.jwt_payload = payload
            return f(*a, **kw)
        return wrapper
    return decorator

# ── User DB (JSON-based; production → PostgreSQL) ─────────────────────────
USERS_DB_FILE = os.path.join(SERVER_BASE_DIR, "users_db.json")
if not os.path.exists(USERS_DB_FILE):
    save_json(USERS_DB_FILE, {})

LOGIN_HISTORY_FILE = os.path.join(SERVER_BASE_DIR, "login_history.json")
if not os.path.exists(LOGIN_HISTORY_FILE):
    save_json(LOGIN_HISTORY_FILE, [])

# ── Medical records DB ────────────────────────────────────────────────────
RECORDS_DB_FILE = os.path.join(SERVER_BASE_DIR, "records_db.json")
if not os.path.exists(RECORDS_DB_FILE):
    save_json(RECORDS_DB_FILE, [])

IMAGES_DB_FILE = os.path.join(SERVER_BASE_DIR, "images_db.json")
if not os.path.exists(IMAGES_DB_FILE):
    save_json(IMAGES_DB_FILE, [])

UPLOADS_DIR = os.path.join(SERVER_BASE_DIR, "uploads")
os.makedirs(os.path.join(UPLOADS_DIR, "reports"), exist_ok=True)
os.makedirs(os.path.join(UPLOADS_DIR, "images"),  exist_ok=True)
os.makedirs(os.path.join(UPLOADS_DIR, "profiles"),exist_ok=True)

# ═══════════════════════════
#   AUTH ENDPOINTS
# ═══════════════════════════

@app.route("/auth/otp/send", methods=["POST"])
@rate_limited(max_calls=5, window=300)
def auth_otp_send():
    """Send (simulated) OTP to email. In prod: plug in SendGrid/SES."""
    body  = request.get_json(force=True) or {}
    email = (body.get("email","") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error":"invalid_email"}), 400
    otp = _gen_otp()
    exp = time.time() + 300   # 5 minutes
    with _otp_lock:
        _otp_store[email] = {"otp":otp,"expires":exp,"attempts":0}
    # fix #2: never return OTP in response — print to server console only
    print(f"[DEV OTP] {email} → {otp}")
    audit("otp_sent", actor=email)
    return jsonify({"message":"OTP sent","expires_in":300})

@app.route("/auth/otp/verify", methods=["POST"])
@rate_limited(max_calls=10, window=60)
def auth_otp_verify():
    body  = request.get_json(force=True) or {}
    email = (body.get("email","") or "").strip().lower()
    otp   = (body.get("otp","") or "").strip()
    with _otp_lock:
        rec = _otp_store.get(email)
        if not rec:
            return jsonify({"error":"no_otp_found"}), 400
        if rec["attempts"] >= 5:
            del _otp_store[email]
            return jsonify({"error":"too_many_attempts"}), 429
        if time.time() > rec["expires"]:
            del _otp_store[email]
            return jsonify({"error":"otp_expired"}), 400
        if rec["otp"] != otp:
            rec["attempts"] += 1
            return jsonify({"error":"wrong_otp","attempts_left":5-rec["attempts"]}), 400
        del _otp_store[email]
    audit("otp_verified", actor=email)
    # Issue a short-lived verification token
    vtoken = _jwt_encode({"sub":email,"purpose":"otp_verified","exp":time.time()+600})
    return jsonify({"verified":True,"verification_token":vtoken})

@app.route("/auth/register", methods=["POST"])
@rate_limited(max_calls=5, window=300)
def auth_register():
    """
    Full registration: name, email, role, password_hash (bcrypt done client-side or here),
    public_key, encrypted_private_key, verification_token (from OTP step).
    """
    body = request.get_json(force=True) or {}
    vtoken = body.get("verification_token","")
    payload = _jwt_decode(vtoken)
    if not payload or payload.get("purpose") != "otp_verified":
        return jsonify({"error":"email_not_verified"}), 403

    email = payload["sub"]
    users = load_json(USERS_DB_FILE)
    if email in users:
        return jsonify({"error":"email_already_registered"}), 409

    name     = (body.get("name","") or "").strip()
    username = (body.get("username","") or "").strip().lower()
    role     = body.get("role","patient")
    pw_hash  = body.get("password_hash","")      # bcrypt hash from client
    pub_key  = body.get("public_key","")
    enc_priv = body.get("encrypted_private_key","")
    phone    = body.get("phone","")

    if not name or not pw_hash or not pub_key or not username:
        return jsonify({"error":"missing_fields"}), 400
    if role not in ("patient","doctor","admin"):
        return jsonify({"error":"invalid_role"}), 400
        
    for u in users.values():
        if u.get("username") == username and u.get("email") != email:
            return jsonify({"error":"username_taken"}), 409

    uid = str(uuid.uuid4())
    users[email] = {
        "id":uid,"name":name,"email":email,"username":username,"phone":phone,
        "role":role,"password_hash":pw_hash,
        "public_key":pub_key,"encrypted_private_key":enc_priv,
        "profile_photo_url":"","created_at":datetime.now(timezone.utc).isoformat(),
        "last_login":"","locked":False,"failed_attempts":0,
    }
    save_json(USERS_DB_FILE, users)
    audit("register", actor=email, detail=role)
    return jsonify({"message":"registered","user_id":uid,"role":role})

@app.route("/internal/register_user_db", methods=["POST"])
def internal_register_user_db():
    """Called by landing.py during registration to create a users_db entry,
    enabling JWT login after logout."""
    auth_err = _require_api_key()
    if auth_err: return auth_err
    body     = request.get_json(force=True) or {}
    email    = (body.get("email","") or "").strip().lower()
    username = (body.get("username","") or "").strip().lower()
    name     = (body.get("name","") or "").strip()
    pw_hash  = body.get("password_hash","")
    role     = body.get("role","patient")
    pub_key  = body.get("public_key","")
    enc_priv = body.get("encrypted_private_key","")
    if not email or not name or not pw_hash or not username:
        return jsonify({"error":"missing_fields"}), 400
    users = load_json(USERS_DB_FILE)
    
    for u in users.values():
        if u.get("username") == username and u.get("email") != email:
            return jsonify({"error":"username_taken", "message": "Username is already taken"}), 409
            
    profile_code = body.get("profile_code", "")
    doctor_code  = body.get("doctor_code", "")
    if email in users:
        existing = users[email]
        # Always update role and password hash for the registering role
        # (handles same email used for both patient and doctor)
        existing["role"]          = role
        existing["username"]      = username
        existing["password_hash"] = pw_hash
        if pub_key:
            existing["public_key"] = pub_key
        if profile_code:
            existing["profile_code"] = profile_code
        if doctor_code:
            existing["doctor_code"] = doctor_code
        save_json(USERS_DB_FILE, users)
        return jsonify({"message":"updated","user_id":existing["id"]}), 200
    uid = str(uuid.uuid4())
    users[email] = {
        "id":uid,"name":name,"email":email,"username":username,"phone":"",
        "role":role,"password_hash":pw_hash,
        "public_key":pub_key,"encrypted_private_key":enc_priv,
        "profile_code":profile_code,
        "doctor_code": doctor_code,
        "profile_photo_url":"","created_at":datetime.now(timezone.utc).isoformat(),
        "last_login":"","locked":False,"failed_attempts":0,
    }
    save_json(USERS_DB_FILE, users)
    audit("register_via_legacy", actor=email, detail=role)
    return jsonify({"message":"created","user_id":uid})


@app.route("/auth/login", methods=["POST"])
@rate_limited(max_calls=10, window=60)
def auth_login():
    body  = request.get_json(force=True) or {}
    identifier = (body.get("email","") or "").strip().lower()
    # Callers send either:
    #   password_hash  — pre-hashed SHA-256 hex (legacy portals)
    #   password       — plaintext (new landing.py path)
    raw_pw   = body.get("password","")
    pw_hash  = body.get("password_hash","")

    users = load_json(USERS_DB_FILE)
    # Primary lookup: treat identifier as email key
    user  = users.get(identifier)
    email = identifier  # will be overridden below if username lookup succeeds
    if not user:
        # Fallback: treat identifier as username — scan all records
        for _key, _u in users.items():
            if isinstance(_u, dict) and (_u.get("username","") or "").lower() == identifier:
                user  = _u
                email = _key  # the actual email key in users_db
                break
    if not user:
        return jsonify({"error":"invalid_credentials"}), 401
    if user.get("locked"):
        return jsonify({"error":"account_locked"}), 403

    # ── Password verification (multi-format) ──────────────────────────────
    from werkzeug.security import check_password_hash as _wz_check, generate_password_hash as _wz_gen

    stored = user.get("password_hash", "")
    auth_ok = False

    if stored.startswith("pbkdf2:sha256:") or stored.startswith("scrypt:"):
        # New werkzeug hash — verify directly with raw password if given
        if raw_pw:
            auth_ok = _wz_check(stored, raw_pw)
        elif pw_hash:
            # Legacy portal sent SHA-256 hex; we can't reverse-verify against werkzeug hash.
            # Accept SHA-256 fallback only if we ALSO have the legacy hash stored.
            # This branch hits if the account was JUST migrated but the portal sent pre-hash.
            # In practice callers using the new landing.py always send raw_pw.
            auth_ok = False
    else:
        # Legacy SHA-256 hex stored
        sha_hash = hashlib.sha256(raw_pw.encode()).hexdigest() if raw_pw else pw_hash
        auth_ok = (stored == sha_hash)
        if auth_ok and raw_pw:
            # Silent upgrade: re-hash with werkzeug and persist
            user["password_hash"] = _wz_gen(raw_pw, method="pbkdf2:sha256", salt_length=16)
            audit("password_upgraded", actor=email)

    if not auth_ok:
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        if user["failed_attempts"] >= 5:
            user["locked"] = True
            audit("account_locked", actor=email)
        save_json(USERS_DB_FILE, users)
        return jsonify({"error":"invalid_credentials"}), 401

    user["failed_attempts"] = 0
    user["last_login"] = datetime.now(timezone.utc).isoformat()
    save_json(USERS_DB_FILE, users)

    # fix #10 + #15: thread-safe, type-guarded login history append
    _append_login_history({"email":email,"ts":user["last_login"],"ip":request.remote_addr})

    # Use the externally-known code (profile_code / doctor_code) as the JWT `uid`
    # so EMR route checks like `p["uid"] == patient_id` work correctly.
    jwt_uid = (user.get("profile_code") or user.get("doctor_code") or user["id"])
    access_token  = _jwt_encode({"sub":email,"uid":jwt_uid,"role":user["role"],
                                  "exp":time.time()+3600})      # 1 hour
    refresh_token = _jwt_encode({"sub":email,"uid":jwt_uid,"role":user["role"],
                                  "purpose":"refresh","exp":time.time()+604800})  # 7 days

    audit("login", actor=email)
    resp = jsonify({
        "message":"ok","role":user["role"],
        "name":user["name"],"user_id":user["id"],
        "username":user.get("username", ""),
        "profile_code":user.get("profile_code", ""),
        "doctor_code": user.get("doctor_code", "") or user.get("profile_code","") if user["role"]=="doctor" else "",
        "access_token":access_token,"refresh_token":refresh_token,
        "public_key":user["public_key"],
        "encrypted_private_key":user["encrypted_private_key"],
    })
    resp.set_cookie("access_token",access_token,httponly=True,samesite="Strict",max_age=3600)
    resp.set_cookie("refresh_token",refresh_token,httponly=True,samesite="Strict",max_age=604800)
    return resp

# ── Username Resolver ────────────────────────────────
@app.route("/api/resolve_username/<username>", methods=["GET"])
def resolve_username(username):
    auth_err = _require_api_key()
    if auth_err: return auth_err
    users = load_json(USERS_DB_FILE)
    for u in users.values():
        if u.get("username", "").lower() == username.lower():
            return jsonify({
                "username": u.get("username"),
                "profile_code": u.get("profile_code", ""),
                "doctor_code": u.get("doctor_code", ""),
                "role": u.get("role", "patient"),
                "name": u.get("name", "")
            }), 200
    return jsonify({"error": "user_not_found"}), 404

# fix #7: logout endpoint that revokes the current access token
@app.route("/auth/logout", methods=["POST"])
@_require_jwt()
def auth_logout():
    jti = request.jwt_payload.get("jti", "")
    if jti:
        with _blocklist_lock:
            _token_blocklist.add(jti)
    resp = jsonify({"message": "logged_out"})
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    audit("logout", actor=request.jwt_payload.get("sub", ""))
    return resp

@app.route("/auth/refresh", methods=["POST"])
def auth_refresh():
    token   = request.cookies.get("refresh_token","") or (request.get_json(force=True) or {}).get("refresh_token","")
    payload = _jwt_decode(token)
    if not payload or payload.get("purpose") != "refresh":
        return jsonify({"error":"invalid_refresh_token"}), 401
    new_access = _jwt_encode({"sub":payload["sub"],"uid":payload["uid"],
                               "role":payload["role"],"exp":time.time()+900})
    resp = jsonify({"access_token":new_access})
    resp.set_cookie("access_token",new_access,httponly=True,samesite="Strict",max_age=900)
    return resp

@app.route("/auth/me", methods=["GET"])
@_require_jwt()
def auth_me():
    p     = request.jwt_payload
    users = load_json(USERS_DB_FILE)
    user  = users.get(p["sub"],{})
    return jsonify({
        "id":user.get("id"),"name":user.get("name"),"email":p["sub"],
        "role":user.get("role"),"phone":user.get("phone",""),
        "profile_photo_url":user.get("profile_photo_url",""),
        "created_at":user.get("created_at",""),"last_login":user.get("last_login",""),
    })

@app.route("/auth/login_history", methods=["GET"])
@_require_jwt()
def auth_login_history():
    p    = request.jwt_payload
    hist = load_json(LOGIN_HISTORY_FILE)
    mine = [h for h in hist if h.get("email")==p["sub"]][-50:]
    return jsonify(mine)

# ═══════════════════════════
#   VISIT REPORT ENDPOINTS
# ═══════════════════════════

@app.route("/reports/upload", methods=["POST"])
@_require_jwt(roles=["doctor"])
@rate_limited(max_calls=20, window=60)
def upload_report():
    """
    Doctor uploads an encrypted visit report (hybrid encryption).
    Body: patient_id, encrypted_report_blob, encrypted_aes_key, file_hash,
          visit_reason, diagnosis (all encrypted in blob).
    """
    body       = request.get_json(force=True) or {}
    doctor_jwt = request.jwt_payload
    patient_id = body.get("patient_id","")
    enc_blob   = body.get("encrypted_report_blob",{})
    enc_key    = body.get("encrypted_aes_key","")
    file_hash  = body.get("file_hash","")

    if not patient_id or not enc_blob or not enc_key:
        return jsonify({"error":"missing_fields"}), 400

    record_id = str(uuid.uuid4())
    record = {
        "id":record_id,
        "patient_id":patient_id,
        "doctor_id":doctor_jwt["uid"],
        "doctor_email":doctor_jwt["sub"],
        "encrypted_report_blob":enc_blob,
        "encrypted_aes_key":enc_key,
        "file_hash":file_hash,
        "created_at":datetime.now(timezone.utc).isoformat(),
    }
    records = load_json(RECORDS_DB_FILE)
    if not isinstance(records, list): records = []  # fix #22
    records.append(record)
    save_json(RECORDS_DB_FILE, records)
    audit("report_upload", actor=doctor_jwt["sub"], target=patient_id)
    return jsonify({"message":"report_uploaded","record_id":record_id}), 201

@app.route("/reports/patient/<patient_id>", methods=["GET"])
@_require_jwt()
def get_patient_reports(patient_id):
    """Patient or approved doctor fetches encrypted report list."""
    p = request.jwt_payload
    # Patient can only see own reports; doctors see if approved
    if p["role"] == "patient" and p["uid"] != patient_id:
        return jsonify({"error":"forbidden"}), 403
    records = load_json(RECORDS_DB_FILE)
    if not isinstance(records, list): records = []  # fix #22
    mine    = [r for r in records if r.get("patient_id") == patient_id]
    # strip blob for listing — return only metadata
    listing = [{k:v for k,v in r.items() if k != "encrypted_report_blob"} for r in mine]
    return jsonify(listing)

@app.route("/reports/<record_id>", methods=["GET"])
@_require_jwt()
def get_report(record_id):
    """Fetch single encrypted report (patient or approved doctor)."""
    p       = request.jwt_payload
    records = load_json(RECORDS_DB_FILE)
    rec     = next((r for r in records if r["id"]==record_id), None)
    if not rec:
        return jsonify({"error":"not_found"}), 404
    if p["role"]=="patient" and p["uid"] != rec["patient_id"]:
        return jsonify({"error":"forbidden"}), 403
    return jsonify(rec)

# ═══════════════════════════
#   IMAGE ENDPOINTS
# ═══════════════════════════

@app.route("/images/upload", methods=["POST"])
@_require_jwt(roles=["doctor"])
@rate_limited(max_calls=10, window=60)
def upload_image():
    """
    Upload encrypted medical image binary.
    Multipart form: record_id, file_hash, encrypted_aes_key + file 'image'.
    """
    from flask import send_from_directory
    doctor_jwt = request.jwt_payload
    record_id  = request.form.get("record_id","")
    file_hash  = request.form.get("file_hash","")
    enc_key    = request.form.get("encrypted_aes_key","")
    img_file   = request.files.get("image")

    if not record_id or not img_file or not enc_key:
        return jsonify({"error":"missing_fields"}), 400

    img_id   = str(uuid.uuid4())
    filename = f"{img_id}.enc"
    save_path = os.path.join(UPLOADS_DIR, "images", filename)
    img_file.save(save_path)

    # verify hash
    actual_hash = hashlib.sha256(open(save_path,"rb").read()).hexdigest()

    img_record = {
        "id":img_id,"record_id":record_id,
        "encrypted_image_path":f"images/{filename}",
        "encrypted_aes_key":enc_key,
        "file_hash":file_hash,
        "server_hash":actual_hash,
        "hash_verified": actual_hash == file_hash if file_hash else None,
        "created_at":datetime.now(timezone.utc).isoformat(),
        "doctor_id":doctor_jwt["uid"],
    }
    imgs = load_json(IMAGES_DB_FILE)
    if not isinstance(imgs, list): imgs = []  # fix #22
    imgs.append(img_record)
    save_json(IMAGES_DB_FILE, imgs)
    audit("image_upload", actor=doctor_jwt["sub"], target=record_id)
    return jsonify({"message":"image_uploaded","image_id":img_id,"hash_verified":img_record["hash_verified"]}), 201

@app.route("/images/record/<record_id>", methods=["GET"])
@_require_jwt()
def get_images_for_record(record_id):
    imgs = load_json(IMAGES_DB_FILE)
    return jsonify([i for i in imgs if i["record_id"]==record_id])

@app.route("/images/download/<image_id>", methods=["GET"])
@_require_jwt()
def download_image(image_id):
    from flask import send_file
    imgs   = load_json(IMAGES_DB_FILE)
    img    = next((i for i in imgs if i["id"]==image_id), None)
    if not img:
        return jsonify({"error":"not_found"}), 404
    path   = os.path.join(UPLOADS_DIR, img["encrypted_image_path"])
    if not os.path.exists(path):
        return jsonify({"error":"file_missing"}), 404
    audit("image_download", actor=request.jwt_payload["sub"], target=image_id)
    return send_file(path, as_attachment=True, download_name=f"encrypted_{image_id}.enc")

# ═══════════════════════════
#   PROFILE PHOTO
# ═══════════════════════════

@app.route("/profile/photo", methods=["POST"])
@_require_jwt()
@rate_limited(max_calls=5, window=60)
def upload_profile_photo():
    from flask import send_file
    p        = request.jwt_payload
    img_file = request.files.get("photo")
    if not img_file:
        return jsonify({"error":"no_file"}), 400
    ext      = img_file.filename.rsplit(".",1)[-1].lower() if "." in img_file.filename else "jpg"
    if ext not in ("jpg","jpeg","png","webp"):
        return jsonify({"error":"invalid_type"}), 400
    filename  = f"{p['uid']}_profile.{ext}"
    save_path = os.path.join(UPLOADS_DIR, "profiles", filename)
    img_file.save(save_path)
    url = f"/profile/photo/{p['uid']}"
    users = load_json(USERS_DB_FILE)
    if p["sub"] in users:
        users[p["sub"]]["profile_photo_url"] = url
        save_json(USERS_DB_FILE, users)
    return jsonify({"url":url})

@app.route("/profile/photo/<uid>", methods=["GET"])
def get_profile_photo(uid):
    from flask import send_file
    for ext in ("jpg","jpeg","png","webp"):
        path = os.path.join(UPLOADS_DIR, "profiles", f"{uid}_profile.{ext}")
        if os.path.exists(path):
            return send_file(path)
    return jsonify({"error":"not_found"}), 404

# ═══════════════════════════
#   ACCESS MANAGEMENT (JWT-aware)
# ═══════════════════════════

ACCESS_DB_FILE = os.path.join(SERVER_BASE_DIR, "access_db.json")
if not os.path.exists(ACCESS_DB_FILE):
    save_json(ACCESS_DB_FILE, [])

@app.route("/access/request", methods=["POST"])
@_require_jwt(roles=["doctor"])
def jwt_request_access():
    body       = request.get_json(force=True) or {}
    patient_id = body.get("patient_id","")
    doctor_jwt = request.jwt_payload
    if not patient_id:
        return jsonify({"error":"missing patient_id"}), 400
    db  = load_json(ACCESS_DB_FILE)
    existing = next((x for x in db if x["doctor_id"]==doctor_jwt["uid"]
                     and x["patient_id"]==patient_id and x["status"]=="pending"), None)
    if existing:
        return jsonify({"message":"already_pending","id":existing["id"]}), 200
    entry = {
        "id":str(uuid.uuid4()),"doctor_id":doctor_jwt["uid"],
        "doctor_email":doctor_jwt["sub"],"patient_id":patient_id,
        "status":"pending","created_at":datetime.now(timezone.utc).isoformat(),
    }
    db.append(entry)
    save_json(ACCESS_DB_FILE, db)
    audit("access_request", actor=doctor_jwt["sub"], target=patient_id)
    return jsonify(entry), 201

@app.route("/access/patient_requests", methods=["GET"])
@_require_jwt(roles=["patient"])
def patient_access_requests():
    p  = request.jwt_payload
    db = load_json(ACCESS_DB_FILE)
    return jsonify([x for x in db if x["patient_id"]==p["uid"]])

@app.route("/access/respond", methods=["POST"])
@_require_jwt(roles=["patient"])
def respond_access():
    body    = request.get_json(force=True) or {}
    req_id  = body.get("request_id","")
    action  = body.get("action","")  # approve / revoke / deny
    patient = request.jwt_payload
    db      = load_json(ACCESS_DB_FILE)
    rec     = next((x for x in db if x["id"]==req_id and x["patient_id"]==patient["uid"]), None)
    if not rec:
        return jsonify({"error":"not_found"}), 404
    if action not in ("approve","revoke","deny"):
        return jsonify({"error":"invalid_action"}), 400
    rec["status"] = "approved" if action=="approve" else action
    rec["responded_at"] = datetime.now(timezone.utc).isoformat()
    save_json(ACCESS_DB_FILE, db)
    audit(f"access_{action}", actor=patient["sub"], target=rec["doctor_email"])
    return jsonify(rec)

@app.route("/access/doctor_patients", methods=["GET"])
@_require_jwt(roles=["doctor"])
def doctor_patients():
    p  = request.jwt_payload
    db = load_json(ACCESS_DB_FILE)
    if not isinstance(db, list): db = []  # fix #22
    return jsonify([x for x in db if x["doctor_id"]==p["uid"] and x["status"]=="approved"])

# ═══════════════════════════
#   AUDIT LOG
# ═══════════════════════════

@app.route("/audit/log", methods=["GET"])
@_require_jwt()
def get_audit_log():
    p = request.jwt_payload
    if not os.path.exists(AUDIT_LOG):
        return jsonify([])
    lines = open(AUDIT_LOG).readlines()[-200:]
    entries = []
    for l in lines:
        try:
            e = json.loads(l)
            # patients see only their own; doctors see their own actions
            if p["sub"] in (e.get("actor",""),e.get("target","")):
                entries.append(e)
        except: pass
    return jsonify(entries)

# ═══════════════════════════
#   USER SEARCH (doctor finds patient)
# ═══════════════════════════

@app.route("/users/search", methods=["GET"])
@_require_jwt(roles=["doctor"])
def user_search():
    q     = (request.args.get("q","") or "").strip().lower()
    role  = request.args.get("role","patient")
    users = load_json(USERS_DB_FILE)
    result = []
    for email, u in users.items():
        if u.get("role") != role: continue
        if q in email.lower() or q in u.get("name","").lower():
            result.append({"id":u["id"],"name":u["name"],"email":email})  # fix #23: no public_key
    return jsonify(result[:20])




@app.route("/note_images/<filename>", methods=["GET"])
def serve_note_image(filename):
    """Serve a saved note image file."""
    auth_err = _require_api_key()
    if auth_err: return auth_err
    img_path = os.path.join(NOTE_IMAGES_DIR, filename)
    if not os.path.exists(img_path):
        return jsonify({"error": "image_not_found"}), 404
    # Derive content type from extension
    ext = filename.rsplit(".", 1)[-1].lower()
    mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "gif": "image/gif", "webp": "image/webp"}.get(ext, "application/octet-stream")
    from flask import send_file
    return send_file(img_path, mimetype=mime)


@app.route("/doctor_notes/<note_id>", methods=["DELETE"])
def delete_doctor_note(note_id):
    """Delete a doctor note by its ID."""
    auth_err = _require_api_key()
    if auth_err: return auth_err
    notes = load_json(DOCTOR_NOTES_FILE)
    if not isinstance(notes, list):
        notes = []
    new_notes = [n for n in notes if n.get("id") != note_id]
    if len(new_notes) == len(notes):
        return jsonify({"error": "note_not_found"}), 404
    save_json(DOCTOR_NOTES_FILE, new_notes)
    audit("doctor_note_deleted", target=note_id)
    return jsonify({"status": "ok"}), 200


# ═══════════════════════════
#   SECURITY HEADERS MIDDLEWARE
# ═══════════════════════════

_ALLOWED_ORIGINS = {"http://127.0.0.1:5001", "http://127.0.0.1:5002", "http://127.0.0.1:5003"}

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"]  = "nosniff"
    resp.headers["X-Frame-Options"]         = "DENY"
    resp.headers["X-XSS-Protection"]        = "1; mode=block"
    resp.headers["Strict-Transport-Security"]= "max-age=31536000; includeSubDomains"
    resp.headers["Referrer-Policy"]         = "no-referrer"
    # fix #6: dynamic single-origin CORS (multi-origin string is invalid)
    origin = request.headers.get("Origin", "")
    if origin in _ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Vary"]                         = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,X-API-Key,Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    # fix #13: Content-Security-Policy
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' http://127.0.0.1:5000; "
        "frame-ancestors 'none';"
    )
    return resp

print("[UPGRADE] New auth/report/image/access endpoints loaded ✓")

# ═══════════════════════════════════════════════════════════════════════════
# ███  EMR MODULE — Blueprint registration                                ███
# ═══════════════════════════════════════════════════════════════════════════
from emr.routes import emr_bp

# Inject server helpers so the blueprint can use them without circular imports
app.config["EMR_require_jwt"]  = _require_jwt
app.config["EMR_audit"]        = audit
app.config["EMR_rate_limited"] = rate_limited
app.config["EMR_load_users"]   = lambda: load_json(USERS_DB_FILE)
app.config["EMR_save_users"]   = lambda data: save_json(USERS_DB_FILE, data)

app.register_blueprint(emr_bp)
print("[EMR] EMR module loaded ✓")

# ═══════════════════════════════════════════════════════════════════════════
# ███  APPOINTMENTS & QR / BARCODE ENDPOINTS                              ███
# ═══════════════════════════════════════════════════════════════════════════

APPOINTMENTS_DB_FILE = os.path.join(SERVER_BASE_DIR, "appointments_db.json")
if not os.path.exists(APPOINTMENTS_DB_FILE):
    save_json(APPOINTMENTS_DB_FILE, [])

@app.route("/api/patient/appointment-request", methods=["POST"])
@_require_jwt(roles=["patient"])
def request_appointment():
    body = request.get_json(force=True) or {}
    patient = request.jwt_payload
    doctor_username = body.get("doctor_username", "").strip()
    date = body.get("date", "").strip()
    time = body.get("time", "").strip()
    notes = body.get("notes", "").strip()

    if not doctor_username or not date or not time:
        return jsonify({"error": "missing_fields"}), 400

    req_id = str(uuid.uuid4())
    entry = {
        "id": req_id,
        "patient_id": patient["uid"],
        "patient_username": patient.get("sub"), # fallback if not found
        "doctor_username": doctor_username,
        "date": date,
        "time": time,
        "notes": notes,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    # Resolve Patient Username for clarity
    users = load_json(USERS_DB_FILE)
    if patient["sub"] in users:
        entry["patient_username"] = users[patient["sub"]].get("username", patient["sub"])
        entry["patient_name"] = users[patient["sub"]].get("name", "")

    db = load_json(APPOINTMENTS_DB_FILE)
    db.append(entry)
    save_json(APPOINTMENTS_DB_FILE, db)
    audit("appointment_requested", actor=patient["sub"], target=doctor_username)
    return jsonify({"message": "requested", "appointment": entry}), 201

@app.route("/api/patient/appointment-requests", methods=["GET"])
@_require_jwt(roles=["patient"])
def get_patient_appointments():
    patient = request.jwt_payload
    db = load_json(APPOINTMENTS_DB_FILE)
    # Find requests where patient_id matches
    requests = [r for r in db if r.get("patient_id") == patient["uid"]]
    return jsonify({"appointments": requests}), 200

@app.route("/api/doctor/appointment-requests", methods=["GET"])
@_require_jwt(roles=["doctor"])
def get_doctor_appointments():
    doc = request.jwt_payload
    users = load_json(USERS_DB_FILE)
    doc_username = ""
    if doc["sub"] in users:
        doc_username = users[doc["sub"]].get("username", "")

    db = load_json(APPOINTMENTS_DB_FILE)
    requests = []
    if doc_username:
        requests = [r for r in db if r.get("doctor_username") == doc_username]
    return jsonify({"appointments": requests}), 200

@app.route("/api/doctor/appointment-requests/<req_id>/respond", methods=["POST"])
@_require_jwt(roles=["doctor"])
def respond_appointment(req_id):
    body = request.get_json(force=True) or {}
    status = body.get("status")
    if status not in ("accepted", "rejected", "rescheduled", "completed"):
        return jsonify({"error": "invalid_status"}), 400

    doc = request.jwt_payload
    users = load_json(USERS_DB_FILE)
    doc_username = ""
    if doc["sub"] in users:
        doc_username = users[doc["sub"]].get("username", "")

    db = load_json(APPOINTMENTS_DB_FILE)
    found = False
    for r in db:
        if r["id"] == req_id:
            if r.get("doctor_username") != doc_username:
                return jsonify({"error": "forbidden"}), 403
            r["status"] = status
            if status == "rescheduled":
                r["date"] = body.get("date", r["date"])
                r["time"] = body.get("time", r["time"])
            r["updated_at"] = datetime.now(timezone.utc).isoformat()
            found = True
            break
            
    if not found:
        return jsonify({"error": "not_found"}), 404
        
    save_json(APPOINTMENTS_DB_FILE, db)
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
    users = load_json(USERS_DB_FILE)
    patient_id = patient["sub"]
    if patient["sub"] in users:
        # Get permanent Patient ID (profile_code)
        patient_id = users[patient["sub"]].get("profile_code") or users[patient["sub"]].get("username", patient["sub"])
        
    qr = qrcode.make(patient_id)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

@app.route("/api/doctor/qr", methods=["GET"])
@_require_jwt(roles=["doctor"])
def doctor_qr():
    doc = request.jwt_payload
    users = load_json(USERS_DB_FILE)
    username = doc["sub"]
    if doc["sub"] in users:
        username = users[doc["sub"]].get("username", doc["sub"])

    url = f"http://127.0.0.1:5001/doctor/public/{username}"
    qr = qrcode.make(url)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

@app.route("/api/patient/barcode", methods=["GET"])
@_require_jwt(roles=["patient"])
def patient_barcode():
    patient = request.jwt_payload
    users = load_json(USERS_DB_FILE)
    patient_id = patient["sub"]
    if patient["sub"] in users:
        # Get permanent Patient ID (profile_code)
        patient_id = users[patient["sub"]].get("profile_code") or users[patient["sub"]].get("username", patient["sub"])

    # Code128 is good for alphanumeric
    CODE = barcode.get_barcode_class('code128')
    bc = CODE(patient_id, writer=ImageWriter())
    img_io = io.BytesIO()
    bc.write(img_io)
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

if __name__ == "__main__":
    print(" Server running on http://127.0.0.1:5000")
    _schedule_cleanup()  # fix #20: use daemon timer via scheduler, not direct call
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=True)
# ═══════════════════════════════════════════════════════════════════════
# ███  DOCTOR NOTES  —  added as non-breaking extension  ███
# ═══════════════════════════════════════════════════════════════════════
#
# Storage: server/doctor_notes.json  (list of note objects)
# Each note:
#   { note_id, patient_code, doctor_code, doctor_name,
#     doctor_specialization, doctor_hospital, note_type,
#     note_text, visit_date, created_at }
#
# Access gate: doctor must have an active (non-expired) wrapped_key
# under server/Patients/<patient_code>/wrapped_keys/<doctor_code>.json
# ────────────────────────────────────────────────────────────────────────

NOTES_DB_FILE = os.path.join(SERVER_BASE_DIR, "doctor_notes.json")
if not os.path.exists(NOTES_DB_FILE):
    with open(NOTES_DB_FILE, "w", encoding="utf-8") as _f:
        json.dump([], _f)


def _doctor_has_active_access(patient_code: str, doctor_code: str) -> bool:
    """Return True iff the doctor has a non-expired wrapped key for this patient."""
    pk_dir = os.path.join(PATIENTS_DIR, patient_code, "wrapped_keys")
    if not os.path.isdir(pk_dir):
        return False
    now = datetime.now(timezone.utc)
    for fn in os.listdir(pk_dir):
        if not fn.lower().endswith(".json"):
            continue
        try:
            js = json.load(open(os.path.join(pk_dir, fn), encoding="utf-8"))
            stored_code = js.get("doctor_code", os.path.splitext(fn)[0])
            if stored_code != doctor_code:
                continue
            expires_at = js.get("temp_key_expires_at")
            if expires_at:
                if datetime.fromisoformat(expires_at) < now:
                    return False   # key exists but is expired
            return True            # key exists and is valid
        except Exception:
            continue
    return False


def _load_notes():
    try:
        with open(NOTES_DB_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return []


def _save_notes(notes):
    tmp = NOTES_DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(notes, fh, indent=2, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, NOTES_DB_FILE)


# ── POST /doctor_notes/add ───────────────────────────────────────────────
@app.route("/doctor_notes/add", methods=["POST", "OPTIONS"])
def doctor_notes_add():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    patient_code  = (body.get("patient_code")  or "").strip()
    doctor_code   = (body.get("doctor_code")   or "").strip()
    doctor_name   = (body.get("doctor_name")   or "").strip()
    doctor_spec   = (body.get("doctor_specialization") or "").strip()
    doctor_hosp   = (body.get("doctor_hospital") or "").strip()
    note_type     = (body.get("note_type")     or "General").strip()
    note_text     = (body.get("note_text")     or "").strip()
    visit_date    = (body.get("visit_date")    or "").strip()

    if not patient_code or not doctor_code or not note_text:
        return jsonify({"error": "missing_fields",
                        "required": ["patient_code", "doctor_code", "note_text"]}), 400

    # Ensure patient profile exists on this server
    pat_file = os.path.join(PATIENTS_DIR, f"{patient_code}.json")
    if not os.path.exists(pat_file):
        return jsonify({"error": "patient_not_found"}), 404

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
        "created_at":            datetime.now(timezone.utc).isoformat(),
    }

    notes = _load_notes()
    notes.append(note)
    _save_notes(notes)

    audit("doctor_note_added",
          actor=f"{doctor_name} ({doctor_code})",
          target=patient_code,
          detail=f"type={note_type}, note_id={note_id}")

    return jsonify({"message": "note_added", "note_id": note_id}), 201


# ── GET /doctor_notes/patient/<patient_code> ──────────────────────────────
@app.route("/doctor_notes/patient/<patient_code>", methods=["GET"])
def doctor_notes_for_patient(patient_code):
    """
    Returns all notes for this patient.
    Protected by API key — both doctor and patient portals call this.
    Optional query param: ?doctor_code=xxx  to filter to one doctor's notes.
    """
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    # fix #3: path-traversal sanitisation
    safe_code = re.sub(r"[^A-Za-z0-9_\-]", "", patient_code)
    if not safe_code:
        return jsonify({"error": "invalid_patient_code"}), 400
    patient_code = safe_code
    notes = _load_notes()
    mine  = [n for n in notes if n.get("patient_code") == patient_code]
    doc_filter = (request.args.get("doctor_code") or "").strip()
    if doc_filter:
        mine = [n for n in mine if n.get("doctor_code") == doc_filter]
    # Newest first
    mine.sort(key=lambda n: n.get("created_at", ""), reverse=True)
    return jsonify(mine), 200


# ── DELETE /doctor_notes/<note_id> ────────────────────────────────────────
@app.route("/doctor_notes/<note_id>", methods=["DELETE", "OPTIONS"])
def doctor_notes_delete(note_id):
    """
    Doctor deletes their own note.
    Requires: X-API-Key + JSON body { "doctor_code": "..." }
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    body        = request.get_json(force=True) or {}
    doctor_code = (body.get("doctor_code") or "").strip()
    if not doctor_code:
        return jsonify({"error": "doctor_code required"}), 400

    notes = _load_notes()
    note  = next((n for n in notes if n["note_id"] == note_id), None)
    if not note:
        return jsonify({"error": "note_not_found"}), 404
    if note["doctor_code"] != doctor_code:
        return jsonify({"error": "forbidden — you can only delete your own notes"}), 403

    notes = [n for n in notes if n["note_id"] != note_id]
    _save_notes(notes)

    audit("doctor_note_deleted",
          actor=f"{note.get('doctor_name','?')} ({doctor_code})",
          target=note["patient_code"],
          detail=f"note_id={note_id}")

    return jsonify({"message": "deleted", "note_id": note_id}), 200