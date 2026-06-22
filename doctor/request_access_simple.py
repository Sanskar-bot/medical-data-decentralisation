# doctor/request_access_simple.py
import os
import sys
import json
import time
import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# FIX 6: Removed duplicate rsa_load_public import
from common.crypto_utils import rsa_wrap_key, rsa_load_public, rsa_load_private

SERVER = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")

# FIX 9: Default timeout changed from 0 (infinite) to 600 seconds (10 minutes)
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "6"))     # seconds
POLL_TIMEOUT  = int(os.environ.get("POLL_TIMEOUT", "600"))      # seconds; was 0 (infinite loop)


def find_doctor_folder_by_code(doctor_code):
    """Automatically locate doctor folder using doctor_code only."""
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Doctors")
    if not os.path.isdir(base):
        return None
    for folder in os.listdir(base):
        folder_path = os.path.join(base, folder)
        if os.path.isdir(folder_path):
            meta_path = os.path.join(folder_path, "doctor_data.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if meta.get("doctor_code") == doctor_code:
                        return folder_path
                except Exception:
                    pass
    return None


def load_local_doctor(folder):
    meta_path = os.path.join(folder, "doctor_data.json")
    pub_path = os.path.join(folder, "doctor_public.pem")
    if not os.path.exists(meta_path) or not os.path.exists(pub_path):
        raise FileNotFoundError("doctor_data.json or doctor_public.pem missing.")

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    with open(pub_path, "rb") as f:
        pub_pem = f.read().decode("utf-8")
    return meta, pub_pem


def post_request(profile_code, doctor_code, doctor_pub_pem, encrypted_doctor_profile_b64):
    payload = {
        "doctor_code": doctor_code,
        "doctor_public_pem": doctor_pub_pem,
        "encrypted_doctor_profile_b64": encrypted_doctor_profile_b64
    }
    r = requests.post(f"{SERVER.rstrip('/')}/request_access_simple/{profile_code}", json=payload, timeout=10)
    try:
        j = r.json()
    except Exception:
        j = None
    return r.status_code, r.text, j


def fetch_all_active_requests():
    try:
        r = requests.get(f"{SERVER.rstrip('/')}/active_requests", timeout=10)
    except Exception as e:
        print("Network error fetching active_requests:", e)
        return None
    if r.status_code != 200:
        # if server returns not found, we'll return None
        return None
    try:
        return r.json()
    except Exception:
        return None


def fetch_request_status_by_id(request_id):
    # optional endpoint: /request_status/<id> (server may not implement)
    try:
        r = requests.get(f"{SERVER.rstrip('/')}/request_status/{request_id}", timeout=10)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except Exception:
        return None


def poll_for_update(request_id, max_wait=POLL_TIMEOUT, interval=POLL_INTERVAL):
    """
    Polls server until request status != 'pending' or until timeout.
    Returns the request entry (dict) when status changes, or None on timeout/error.
    """
    start = time.time()
    backoff = interval
    print(f"[Poll] waiting for request {request_id} to be updated (interval={interval}s, timeout={max_wait}s) ...")
    while True:
        # if server supports small per-request status endpoint, prefer it
        status_obj = fetch_request_status_by_id(request_id)
        if status_obj and isinstance(status_obj, dict) and status_obj.get("request_id") == request_id:
            status = status_obj.get("status")
            if status and status.lower() != "pending":
                return status_obj

        # fallback: fetch all active requests and search
        arr = fetch_all_active_requests()
        if isinstance(arr, list):
            found = next((x for x in arr if x.get("request_id") == request_id), None)
            if found:
                status = found.get("status")
                if status and status.lower() != "pending":
                    return found

        # FIX 9: Timeout with a clear, helpful message instead of hanging forever
        if max_wait and (time.time() - start) >= max_wait:
            print(f"[Poll] No response from patient after {max_wait}s.")
            print("[Poll] The patient may not be online. Run this script again later to check.")
            return None

        try:
            time.sleep(backoff)
        except KeyboardInterrupt:
            print("\n[Poll] Interrupted by user (Ctrl+C). Exiting poll.")
            return None

        # gentle incremental backoff up to 60s
        backoff = min(backoff * 1.2, 60.0)


def request_access(profile_code, doctor_code):
    folder = find_doctor_folder_by_code(doctor_code)
    if not folder:
        print("❌ No doctor folder found for doctor_code:", doctor_code)
        return

    meta, doctor_pub_pem = load_local_doctor(folder)

    # prepare doctor profile JSON
    doctor_profile = {
        "doctor_id": meta.get("doctor_id"),
        "doctor_code": meta.get("doctor_code"),
        "name": meta.get("name"),
        "hospital": meta.get("hospital"),
        "specialization": meta.get("specialization"),
        "email": meta.get("email")
    }
    doctor_bytes = json.dumps(doctor_profile, separators=(",", ":")).encode("utf-8")

    # fetch patient's public key
    r = requests.get(f"{SERVER.rstrip('/')}/get_patient_public/{profile_code}", timeout=10)
    if r.status_code != 200:
        print("❌ Failed to fetch patient public key:", r.status_code, r.text)
        return

    patient_pub_pem = r.json().get("patient_public_pem")
    if not patient_pub_pem:
        print("❌ Server returned no patient_public_pem")
        return

    # --- load patient public PEM into a key object, then RSA-OAEP encrypt ---
    try:
        patient_pub_obj = rsa_load_public(patient_pub_pem.encode("utf-8"))
    except Exception as e:
        print("❌ Failed to parse patient public PEM:", e)
        return

    try:
        encrypted_doctor_profile_b64 = rsa_wrap_key(patient_pub_obj, doctor_bytes)
    except Exception as e:
        print("❌ Encryption failed:", e)
        return

    # send access request
    code, text, j = post_request(profile_code, doctor_code, doctor_pub_pem, encrypted_doctor_profile_b64)
    print("Server response:", code, text)
    if not j:
        print("No JSON response from server; cannot get request_id to poll. Exiting.")
        return

    request_id = j.get("request_id") or j.get("request", {}).get("request_id") or j.get("id")
    if not request_id:
        print("Server did not return a request_id. Exiting.")
        return

    print(f"[Info] Created request_id: {request_id} — now polling for update ...")

    # Poll until approved/denied/timeout
    result = poll_for_update(request_id)
    if not result:
        print("[Info] No update received (timeout or error).")
        return

    # result is the request entry (dict) with updated status
    status = result.get("status")
    print(f"[Info] Request {request_id} status changed to: {status}")

    # if server stored wrapped_key in the request entry, show it
    wrapped_key = result.get("wrapped_key") or result.get("wrappedKey") or result.get("wrapped_key_b64")
    if wrapped_key:
        print("[Info] wrapped_key available in server record (base64). Doctor will use this to decrypt patient data.")
    else:
        # optional: server may have stored wrapped key at another path; try an endpoint
        try:
            rget = requests.get(f"{SERVER.rstrip('/')}/wrapped_key/{result.get('profile_code')}", timeout=10)
            if rget.status_code == 200:
                wk = rget.json().get("wrapped_key")
                if wk:
                    print("[Info] Wrapped key fetched from /wrapped_key/: present (base64).")
                else:
                    print("[Info] No wrapped key found at /wrapped_key/ endpoint.")
            else:
                print("[Info] /wrapped_key/ endpoint returned:", rget.status_code)
        except Exception:
            pass

    # Final note
    if status and status.lower() == "approved":
        print("[Success] Your request was approved. The doctor can now fetch the wrapped key and decrypt the data.")
    else:
        print("[Done] Request finished with status:", status)


if __name__ == "__main__":
    profile_code = input("Enter patient profile code: ").strip()
    doctor_code = input("Enter your doctor_code: ").strip()
    request_access(profile_code, doctor_code)
