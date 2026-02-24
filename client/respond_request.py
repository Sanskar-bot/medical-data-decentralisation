# client/respond_request.py
"""
Patient-side request responder (updated to use temporary AES key sharing and
automatic unwrapping of local K_data).

Flow:
 - Ask patient profile_code
 - GET /active_requests from server, filter for this profile_code & pending status
 - Load patient private key (folder)
 - Decrypt each request's encrypted_doctor_profile_b64 using patient's private key
 - Show doctor details, ask Approve / Deny
 - On Approve:
     * If client/Users/<profile>/user_data.json has key_protection:
         - Ask local password ONCE, derive KEK and unwrap K_data (reused for session)
     * Use share_kdata_via_temp_key (if available) OR fallback to rsa_wrap_key(K_data)
     * Securely zero K_data from memory after use
 - On Deny: POST /update_request_status with status "denied"
"""
import os
import sys
import json
import requests
import getpass
from base64 import b64decode

# ensure project root on sys.path so common can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.crypto_utils import (
    rsa_load_private,
    rsa_unwrap_key,
    rsa_load_public,
    rsa_wrap_key,
    derive_kek_from_password,
    unwrap_key_with_kek,
    aesgcm_encrypt,  # used if temp-key helper expects it
)

# try to import the temporary-key helper; if missing, we'll fallback
try:
    from share_details import share_kdata_via_temp_key
    _HAS_SHARE_DETAILS = True
except Exception:
    _HAS_SHARE_DETAILS = False

SERVER = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")
TEMP_KEY_TTL_SECONDS = 24 * 3600  # 24 hours default


def fetch_active_requests():
    """Return list of all active requests from server (or raise)."""
    r = requests.get(f"{SERVER.rstrip('/')}/active_requests", timeout=10)
    r.raise_for_status()
    return r.json()


def load_patient_private(folder_or_pem):
    """Load patient private key object. Accepts folder or file path."""
    if os.path.isdir(folder_or_pem):
        folder = folder_or_pem
        raw_pem = os.path.join(folder, "patient_private.pem")
        wrapped_b64 = os.path.join(folder, "patient_private_wrapped.b64")
        keyprot = os.path.join(folder, "key_protection.json")

        if os.path.exists(raw_pem):
            with open(raw_pem, "rb") as f:
                return rsa_load_private(f.read())

        # handle wrapped private PEM
        if os.path.exists(wrapped_b64):
            # prefer explicit key_protection.json; if not, try user_data.json
            if os.path.exists(keyprot):
                with open(keyprot, "r", encoding="utf-8") as f:
                    kp = json.load(f)
                salt_b64 = kp.get("salt_b64") or kp.get("salt")
            else:
                ud = os.path.join(folder, "user_data.json")
                if os.path.exists(ud):
                    with open(ud, "r", encoding="utf-8") as f:
                        udj = json.load(f)
                    kp = udj.get("key_protection") or {}
                    salt_b64 = kp.get("salt_b64") or kp.get("salt")
                else:
                    raise FileNotFoundError("No key_protection.json or user_data.json to get salt for wrapped private key.")

            with open(wrapped_b64, "r", encoding="utf-8") as f:
                wrapped = f.read().strip()
            if not salt_b64:
                raise ValueError("salt_b64 missing; cannot derive KEK.")
            salt = b64decode(salt_b64)
            pw = getpass.getpass("Enter local password to unwrap your private key: ")
            kek, _ = derive_kek_from_password(pw, salt=salt)
            priv_pem_bytes = unwrap_key_with_kek(kek, wrapped)
            return rsa_load_private(priv_pem_bytes)

        raise FileNotFoundError("No patient_private.pem or wrapped private key found in folder.")

    # file path is a wrapped file
    if os.path.basename(folder_or_pem).endswith(".b64"):
        wrapped_path = folder_or_pem
        keyprot = os.path.join(os.path.dirname(wrapped_path), "key_protection.json")
        if not os.path.exists(keyprot):
            raise FileNotFoundError("key_protection.json missing next to wrapped private key.")
        with open(keyprot, "r", encoding="utf-8") as f:
            kp = json.load(f)
        salt_b64 = kp.get("salt_b64") or kp.get("salt")
        salt = b64decode(salt_b64)
        pw = getpass.getpass("Enter local password to unwrap your private key: ")
        kek, _ = derive_kek_from_password(pw, salt=salt)
        with open(wrapped_path, "r", encoding="utf-8") as f:
            wrapped = f.read().strip()
        priv_pem_bytes = unwrap_key_with_kek(kek, wrapped)
        return rsa_load_private(priv_pem_bytes)

    # assume raw PEM file
    with open(folder_or_pem, "rb") as f:
        return rsa_load_private(f.read())


def load_local_user_json(profile_code):
    """
    Robustly load client/Users/<profile_code>/user_data.json.

    Uses the script's directory (based on __file__) so it works regardless of current working directory.
    Returns the parsed JSON dict or None if not found / unreadable.
    """
    # base folder where this script lives, e.g. A:\Minor_Decentralised\client
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # construct absolute path to user_data.json
    path = os.path.join(script_dir, "Users", profile_code, "user_data.json")

    # debug/log so you can confirm path resolution in runtime
    print(f"[DEBUG] Checking for local user_data.json at: {path}")

    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to read local user_data.json: {e}")
        return None



def unwrap_local_K_data_from_local_json_once(local_json):
    """
    Ask user password once and unwrap K_data from local_json['key_protection'].
    Returns K_data bytes on success or None.
    """
    kp = local_json.get("key_protection")
    if not kp:
        return None
    wrapped_k = kp.get("wrapped_k") or kp.get("wrapped_k_b64") or kp.get("wrappedK") or kp.get("wrapped")
    salt_b64 = kp.get("salt_b64") or kp.get("salt")
    if not wrapped_k or not salt_b64:
        return None
    salt = b64decode(salt_b64)
    # ask password once
    pw = getpass.getpass("Enter local password to unwrap your AES data key (K_data): ")
    kek, _ = derive_kek_from_password(pw, salt=salt)
    try:
        K_data = unwrap_key_with_kek(kek, wrapped_k)
        return K_data
    except Exception as e:
        print("Failed to unwrap wrapped_k — wrong password or corrupted data:", e)
        return None


def approve_on_server(request_entry, wrapped_key_b64, enc_record_obj):
    """Call POST /approve_request with required payload."""
    payload = {
        "request_id": request_entry.get("request_id"),
        "doctor_code": request_entry.get("doctor_code"),
        "patient_code": request_entry.get("profile_code"),
        "wrapped_key": wrapped_key_b64,
        "encrypted_record": enc_record_obj
    }
    r = requests.post(f"{SERVER.rstrip('/')}/approve_request", json=payload, timeout=10)
    return r


def update_request_status_on_server(request_id, status):
    try:
        r = requests.post(f"{SERVER.rstrip('/')}/update_request_status", json={"request_id": request_id, "status": status}, timeout=10)
        return r
    except Exception as e:
        print("Warning: failed to update request status on server:", e)
        return None


def _zero_and_del_bytes(b):
    # FIX 10: Convert to bytearray first so the memory overwrite actually works.
    # Python's immutable bytes objects cannot be zeroed in-place; bytearray can.
    try:
        if isinstance(b, (bytes, bytearray)):
            ba = bytearray(b)
            for i in range(len(ba)):
                ba[i] = 0
            del ba
    except Exception:
        pass
    try:
        del b
    except Exception:
        pass


def _create_temp_key_and_payload(profile_code, request_entry, doctor_pub_pem, K_data_bytes, ttl_seconds=TEMP_KEY_TTL_SECONDS):
    """
    Create temporary AES key T, encrypt K_data with T using AES-GCM,
    wrap T with doctor's RSA public key, and build approval payload dict.
    """
    # 1) create temp key T (AES-256)
    T = os.urandom(32)

    # 2) encrypt K_data with T using aesgcm_encrypt helper (should return {"nonce", "ciphertext"})
    enc_kdata = aesgcm_encrypt(T, K_data_bytes)

    # 3) parse doctor's public PEM and RSA-wrap T
    doc_pub_obj = rsa_load_public(doctor_pub_pem.encode("utf-8"))
    wrapped_temp_b64 = rsa_wrap_key(doc_pub_obj, T)  # base64 string

    # 4) expiry timestamp
    from datetime import datetime, timezone, timedelta
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()

    # 5) assemble payload for /approve_request
    payload = {
        "request_id": request_entry.get("request_id"),
        "doctor_code": request_entry.get("doctor_code"),
        "patient_code": request_entry.get("profile_code"),
        "wrapped_key": wrapped_temp_b64,
        "encrypted_kdata_with_temp": enc_kdata,
        "temp_key_expires_at": expires_at,
    }
    return payload


def main():
    profile_code = input("Enter your patient profile_code: ").strip()
    if not profile_code:
        print("profile_code required."); return

    # fetch active requests
    try:
        all_reqs = fetch_active_requests()
    except Exception as e:
        print("Failed to fetch active requests from server:", e); return

    # filter for this profile and pending
    pending = [r for r in all_reqs if r.get("profile_code") == profile_code and r.get("status") == "pending"]
    if not pending:
        print("No pending requests for profile:", profile_code); return

    # ALWAYS auto-locate the patient folder (relative to script)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    key_input = os.path.join(base_dir, "Users", profile_code)
    print(f"[INFO] Using patient folder: {key_input}")

    try:
        patient_priv = load_patient_private(key_input)
    except Exception as e:
        print("Failed to load patient private key:", e); return

    # attempt to load local user_data.json (may be None)
    local_json = load_local_user_json(profile_code)

    # If local_json has key_protection, ask password once to unwrap K_data for this session
    session_K_data = None
    if local_json:
        try:
            session_K_data = unwrap_local_K_data_from_local_json_once(local_json)
            if session_K_data:
                print("[INFO] Successfully unwrapped local K_data for this session.")
            else:
                print("[INFO] Could not unwrap local K_data automatically (will prompt per-request if needed).")
        except Exception as e:
            print("Warning: error while attempting to auto-unwrap K_data:", e)
            session_K_data = None

    # process each pending request
    for entry in pending:
        print("\n--- Request ID:", entry.get("request_id"), "---")
        enc_b64 = entry.get("encrypted_doctor_profile_b64") or entry.get("encrypted_doctor_profile")
        if not enc_b64:
            print("No encrypted doctor profile present. Skipping."); continue

        # decrypt doctor profile
        try:
            decrypted = rsa_unwrap_key(patient_priv, enc_b64)  # bytes
            doc_profile = json.loads(decrypted.decode("utf-8"))
            print("Doctor profile (decrypted):")
            print(json.dumps(doc_profile, indent=2, ensure_ascii=False))
        except Exception as e:
            print("Failed to decrypt doctor profile:", e)
            continue

        # Ask patient decision
        choice = input("Approve this doctor? (y/N): ").strip().lower()
        if choice not in ("y", "yes"):
            print("Denying request.")
            update_request_status_on_server(entry.get("request_id"), "denied")
            continue

        # APPROVE: obtain K_data (prefer session_K_data)
        K_data = None
        if session_K_data:
            K_data = session_K_data  # reuse session key (do NOT zero until after final use)
        else:
            # if local_json exists but we didn't unwrap successfully earlier, try now
            if local_json:
                try:
                    K_data = unwrap_local_K_data_from_local_json_once(local_json)
                except Exception:
                    K_data = None

        # if still no K_data, prompt the user for a raw K_data file (manual)
        if not K_data:
            print("Warning: K_data not available locally.")
            want_manual = input("Do you have K_data bytes in a file you want to provide now? (y/N): ").strip().lower()
            if want_manual in ("y", "yes"):
                kpath = input("Path to a file containing raw K_data bytes: ").strip()
                try:
                    with open(kpath, "rb") as f:
                        K_data = f.read()
                except Exception as e:
                    print("Failed to read provided K_data file:", e)
                    K_data = None

        if not K_data:
            # No K_data — still allow patient to approve but doctor will not receive wrapped key
            print("No K_data available. You may still mark approved but doctor will not receive wrapped key. Skipping wrapping step.")
            enc_record_obj = local_json.get("encrypted_record") if local_json else None
            try:
                resp = approve_on_server(entry, None, enc_record_obj)
            except Exception as e:
                print("Network error while approving:", e)
                continue
            if resp is None:
                print("Network error while approving.")
            else:
                print("Server responded:", resp.status_code, resp.text)
                update_request_status_on_server(entry.get("request_id"), "approved")
            continue

        # We have K_data and doctor's public key -> process sharing
        doctor_pub_pem = entry.get("doctor_public_pem")
        if not doctor_pub_pem:
            print("Doctor public key missing in request. Cannot wrap K_data.")
            # zero if this was a one-off K_data from file
            if session_K_data is None:
                _zero_and_del_bytes(K_data)
            continue

        # FIRST: try share via temporary key flow if helper present
        did_share = False
        if _HAS_SHARE_DETAILS:
            try:
                patient_folder_full = os.path.join(base_dir, "Users", profile_code)
                resp = share_kdata_via_temp_key(
                    profile_code=profile_code,
                    request_id=entry.get("request_id"),
                    doctor_code=entry.get("doctor_code"),
                    doctor_public_pem=doctor_pub_pem,
                    patient_folder=patient_folder_full,
                    server_base=SERVER,
                    ttl_seconds=TEMP_KEY_TTL_SECONDS
                )
                if resp is not None and resp.status_code in (200, 201):
                    print("Approved and shared K_data via temporary key (server responded):", resp.status_code, resp.text)
                    update_request_status_on_server(entry.get("request_id"), "approved")
                    did_share = True
                else:
                    print("Temporary-key share failed or server returned error. Falling back to direct wrap.")
            except Exception as e:
                print("Temporary-key share encountered error — falling back to direct wrap:", e)

        # If temporary sharing failed or not available, fallback to wrapping permanent K_data for doctor
        if not did_share:
            try:
                doc_pub_obj = rsa_load_public(doctor_pub_pem.encode("utf-8"))
            except Exception as e:
                print("Failed to parse doctor's public PEM:", e)
                # zero if K_data was one-off
                if session_K_data is None:
                    _zero_and_del_bytes(K_data)
                continue

            try:
                wrapped_key_b64 = rsa_wrap_key(doc_pub_obj, K_data)
            except Exception as e:
                print("Failed to wrap K_data for doctor:", e)
                if session_K_data is None:
                    _zero_and_del_bytes(K_data)
                continue

            enc_record_obj = local_json.get("encrypted_record") if local_json else None

            try:
                resp = approve_on_server(entry, wrapped_key_b64, enc_record_obj)
            except Exception as e:
                print("Network error uploading approval:", e)
                if session_K_data is None:
                    _zero_and_del_bytes(K_data)
                continue

            if resp is not None and resp.status_code in (200, 201):
                print("Approved and uploaded wrapped key to server.")
                update_request_status_on_server(entry.get("request_id"), "approved")
            else:
                print("Server returned error on approve:", None if resp is None else (resp.status_code, resp.text))
                # proceed but do not mark approved locally

        # zero one-time K_data if it wasn't the session key
        if session_K_data is None:
            _zero_and_del_bytes(K_data)

    # finally: zero session_K_data if present
    if session_K_data:
        _zero_and_del_bytes(session_K_data)
        session_K_data = None

    print("Done processing requests.")


if __name__ == "__main__":
    main()
