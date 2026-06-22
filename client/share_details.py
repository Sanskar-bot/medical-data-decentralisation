# client/share_details.py
"""
share_details.py

Create a temporary AES key (T), encrypt the patient's AES data key (K_data) with T,
wrap T with the doctor's RSA public key, and upload the approval payload to the server.

Usage (example - call from respond_request.py after patient approves):
    from share_details import share_kdata_via_temp_key
    share_kdata_via_temp_key(
        profile_code="nurpsuyJ",
        request_id="....",
        doctor_code="201d1a57",
        doctor_public_pem=doctor_pub_pem,   # string PEM or path to PEM file
        patient_folder=None,                # optional, defaults to client/Users/<profile_code>
        server_base="http://127.0.0.1:5000",
        ttl_seconds=86400                   # default 24 hours
    )

Notes:
- Relies on functions from common.crypto_utils:
  rsa_load_public, rsa_wrap_key, aesgcm_encrypt, rsa_load_private (if needed), derive_kek_from_password, unwrap_key_with_kek
- The server's /approve_request endpoint expects the "wrapped_key" field and will save wrapped_key & mark request approved.
- This module does not automatically remove expired temp keys on the server — that's a separate cleanup task.
"""

import os
import json
import time
from datetime import datetime, timezone, timedelta
import requests
from base64 import b64decode, b64encode

# ensure project root is importable when called from different cwd
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.crypto_utils import (
    rsa_load_public,
    rsa_wrap_key,        # wraps bytes -> base64 string
    aesgcm_encrypt,      # (key_bytes, plaintext_bytes) -> {"nonce":..., "ciphertext":...}
    derive_kek_from_password,
    unwrap_key_with_kek,
)

# Helper: load patient's K_data from local user_data.json (unwrap if needed)
def _load_local_k_data(profile_code, patient_folder=None):
    """
    Returns K_data bytes or raises an exception.
    Looks for client/Users/<profile_code>/user_data.json and key_protection.
    """
    if not patient_folder:
        base = os.path.dirname(os.path.abspath(__file__))  # client/
        patient_folder = os.path.join(base, "Users", profile_code)

    ud_path = os.path.join(patient_folder, "user_data.json")
    if not os.path.exists(ud_path):
        raise FileNotFoundError(f"user_data.json not found at {ud_path}")

    with open(ud_path, "r", encoding="utf-8") as fh:
        ud = json.load(fh)

    kp = ud.get("key_protection")
    # If key_protection contains wrapped_k, we must ask for password or expect wrapped_k to be present
    if kp and kp.get("wrapped_k"):
        # derive KEK from user password (we *must* ask user for the password here)
        pw = input("Enter local password to unwrap your AES data key (K_data): ").strip()
        if not pw:
            raise ValueError("Password required to unwrap K_data.")
        salt_b64 = kp.get("salt_b64")
        if not salt_b64:
            raise ValueError("key_protection present but salt_b64 missing.")
        salt = b64decode(salt_b64)
        kek, _ = derive_kek_from_password(pw, salt=salt)
        wrapped_k_b64 = kp["wrapped_k"]
        K_data = unwrap_key_with_kek(kek, wrapped_k_b64)
        if not isinstance(K_data, (bytes, bytearray)):
            raise ValueError("Unwrapped K_data is not bytes.")
        return K_data

    # fallback: if user_data contains k_data_b64 (not recommended) or raw k_data (rare)
    if ud.get("k_data_b64"):
        return b64decode(ud["k_data_b64"])

    # No local key stored in user_data.json
    raise FileNotFoundError("K_data not found in user_data.json (no key_protection or k_data_b64).")

def _load_doctor_pub(doctor_public_pem_or_path):
    """Accept either a PEM string or a path to a PEM file. Return a public key object (rsa_load_public compatible)."""
    if isinstance(doctor_public_pem_or_path, str) and doctor_public_pem_or_path.strip().startswith("-----BEGIN"):
        pem = doctor_public_pem_or_path
    elif isinstance(doctor_public_pem_or_path, str) and os.path.exists(doctor_public_pem_or_path):
        with open(doctor_public_pem_or_path, "r", encoding="utf-8") as fh:
            pem = fh.read()
    else:
        raise ValueError("doctor_public_pem must be a PEM string or a path to a PEM file.")
    return rsa_load_public(pem.encode("utf-8"))

def share_kdata_via_temp_key(
    profile_code: str,
    request_id: str,
    doctor_code: str,
    doctor_public_pem,           # PEM string or path to PEM file
    patient_folder: str = None,  # optional path to client/Users/<profile_code>
    server_base: str = "http://127.0.0.1:5000",
    ttl_seconds: int = 86400     # temporary AES key validity (default 24 hours)
):
    """
    Create a temporary AES key T, encrypt K_data with T (AES-GCM), wrap T with doctor's RSA public key,
    and POST to server /approve_request with the wrapped temp key and encrypted K_data snapshot.
    Returns server response (requests.Response).
    """

    # 1) load patient's K_data (plaintext AES key)
    K_data = _load_local_k_data(profile_code, patient_folder=patient_folder)  # bytes

    # 2) generate temporary AES key T (32 bytes = AES-256)
    T = os.urandom(32)

    # 3) encrypt K_data with T using AES-GCM (aesgcm_encrypt returns base64-encoded nonce & ciphertext)
    enc_kdata = aesgcm_encrypt(T, K_data)  # expected: {"nonce": "b64...", "ciphertext": "b64..."}
    # enc_kdata now holds the AES-GCM encrypted K_data under temp key T

    # 4) load doctor's public key object and RSA-wrap T (result is base64 string)
    doctor_pub_obj = _load_doctor_pub(doctor_public_pem)
    wrapped_temp_b64 = rsa_wrap_key(doctor_pub_obj, T)  # base64 string

    # 5) prepare expiry timestamp
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()

    # 6) build payload expected by your /approve_request endpoint
    payload = {
        "request_id": request_id,
        "doctor_code": doctor_code,
        "patient_code": profile_code,
        # wrapped_key is what server expects to save for doctor to download later;
        # we place wrapped temp key here so doctor can unwrap T with RSA private -> get T
        "wrapped_key": wrapped_temp_b64,
        # encrypted_kdata_with_temp: patient K_data encrypted with temp AES (nonce + ciphertext)
        "encrypted_kdata_with_temp": enc_kdata,
        "temp_key_expires_at": expires_at,
        # Optionally include a small snapshot of encrypted patient record (or other metadata) - not required
        # "encrypted_record": { "nonce": "...", "ciphertext": "..." }
    }

    # 7) POST to server's approve_request endpoint
    url = server_base.rstrip("/") + "/approve_request"
    try:
        resp = requests.post(url, json=payload, timeout=15)
    except Exception as e:
        raise RuntimeError(f"Failed to contact server at {url}: {e}")

    # 8) return server response object for inspection by caller
    return resp

# If module run as script for quick manual test:
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Share K_data via a temporary AES key wrapped for a doctor.")
    parser.add_argument("profile_code")
    parser.add_argument("request_id")
    parser.add_argument("doctor_code")
    parser.add_argument("doctor_pub_pem_or_path",
                        help="doctor's public PEM string or path to PEM file (if it starts with '-----BEGIN' pass the string) ")
    parser.add_argument("--patient_folder", default=None)
    parser.add_argument("--server", default="http://127.0.0.1:5000")
    parser.add_argument("--ttl", type=int, default=86400, help="TTL seconds for temp key (default 86400 = 24h)")
    args = parser.parse_args()

    try:
        r = share_kdata_via_temp_key(
            profile_code=args.profile_code,
            request_id=args.request_id,
            doctor_code=args.doctor_code,
            doctor_public_pem=args.doctor_pub_pem_or_path,
            patient_folder=args.patient_folder,
            server_base=args.server,
            ttl_seconds=args.ttl
        )
        print("Server responded:", r.status_code, r.text)
    except Exception as exc:
        print("ERROR:", exc)
