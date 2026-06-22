# doctor/fetch_patient.py
"""
Doctor-side fetch & decrypt script.

Usage:
  python doctor/fetch_patient.py

The script will:
 - load the doctor's private key (raw PEM or wrapped base64 + key_protection.json)
 - fetch encrypted patient record and wrapped data key from server
 - unwrap the data key using the doctor's private key
 - verify patient's signature
 - decrypt and print the patient record
"""

import sys
import os
import json
import requests
import getpass
from base64 import b64decode

# --- fix Python path so common/ can be imported regardless of working dir ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# --- crypto helpers (from your project) ---
from common.crypto_utils import (
    rsa_load_private,
    rsa_unwrap_key,
    rsa_load_public,
    rsa_verify,
    aesgcm_decrypt,
    derive_kek_from_password,
    unwrap_key_with_kek,
)

SERVER_BASE = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")


def load_doctor_private(key_path):
    """
    Accept either:
      - path to a raw private PEM (doctor_private.pem)
      - path to a folder containing doctor_private_wrapped.b64 and key_protection.json
      - path directly to doctor_private_wrapped.b64
    Returns a private key object usable by rsa_unwrap_key / rsa_load_private.
    """
    # If user passed folder, try to locate files inside it
    if os.path.isdir(key_path):
        folder = key_path
        wrapped_path = os.path.join(folder, "doctor_private_wrapped.b64")
        key_prot_path = os.path.join(folder, "key_protection.json")
        raw_priv_path = os.path.join(folder, "doctor_private.pem")
        if os.path.exists(raw_priv_path):
            with open(raw_priv_path, "rb") as f:
                return rsa_load_private(f.read())
        if os.path.exists(wrapped_path) and os.path.exists(key_prot_path):
            with open(wrapped_path, "r", encoding="utf-8") as f:
                wrapped_b64 = f.read().strip()
            with open(key_prot_path, "r", encoding="utf-8") as f:
                kp = json.load(f)
            salt_b64 = kp.get("salt_b64")
            if not salt_b64:
                raise ValueError("key_protection.json missing salt_b64")
            salt = b64decode(salt_b64)
            pw = getpass.getpass("Enter local password to unwrap your private key: ")
            kek, _ = derive_kek_from_password(pw, salt=salt)
            priv_pem = unwrap_key_with_kek(kek, wrapped_b64)
            return rsa_load_private(priv_pem)
        raise FileNotFoundError("No private key file found in folder. Expect doctor_private.pem or wrapped files.")
    else:
        # if path is a file
        if key_path.endswith(".b64") or os.path.basename(key_path).startswith("doctor_private_wrapped"):
            # assume wrapped base64 file; look for key_protection in same folder
            wrapped_path = key_path
            folder = os.path.dirname(wrapped_path)
            key_prot_path = os.path.join(folder, "key_protection.json")
            if not os.path.exists(key_prot_path):
                raise FileNotFoundError("key_protection.json missing next to wrapped private key")
            with open(wrapped_path, "r", encoding="utf-8") as f:
                wrapped_b64 = f.read().strip()
            with open(key_prot_path, "r", encoding="utf-8") as f:
                kp = json.load(f)
            salt_b64 = kp.get("salt_b64")
            salt = b64decode(salt_b64)
            pw = getpass.getpass("Enter local password to unwrap your private key: ")
            kek, _ = derive_kek_from_password(pw, salt=salt)
            priv_pem = unwrap_key_with_kek(kek, wrapped_b64)
            return rsa_load_private(priv_pem)
        else:
            # assume raw PEM
            with open(key_path, "rb") as f:
                return rsa_load_private(f.read())


def main():
    profile_code = input("Enter patient profile_code: ").strip()
    if not profile_code:
        print("profile_code required.")
        return

    doctor_key_input = input("Path to your doctor private PEM or doctor folder (or wrapped file): ").strip()
    if not doctor_key_input:
        print("Private key path required.")
        return

    # load doctor private key (supports wrapped or raw)
    try:
        priv = load_doctor_private(doctor_key_input)
    except Exception as e:
        print("Failed to load doctor private key:", str(e))
        return

    # 1) fetch encrypted record + signature
    try:
        r = requests.get(f"{SERVER_BASE.rstrip('/')}/get_patient_data/{profile_code}", timeout=10)
    except Exception as e:
        print("Network error fetching patient data:", e)
        return
    if r.status_code != 200:
        print("Server returned error fetching patient data:", r.status_code, r.text)
        return
    try:
        data = r.json()
    except Exception as e:
        print("Invalid JSON from server:", e)
        return

    enc = data.get("encrypted_record")
    signature = data.get("signature")
    patient_pub_pem = data.get("patient_public_pem")
    if not enc or "nonce" not in enc or "ciphertext" not in enc:
        print("Encrypted record missing or malformed in server response.")
        return

    # 2) download wrapped key for this doctor
    try:
        r2 = requests.get(f"{SERVER_BASE.rstrip('/')}/wrapped_key/{profile_code}", timeout=10)
    except Exception as e:
        print("Network error fetching wrapped key:", e)
        return
    if r2.status_code != 200:
        print("Server returned error fetching wrapped key:", r2.status_code, r2.text)
        return
    try:
        wrapped_key_b64 = r2.json().get("wrapped_key")
    except Exception as e:
        print("Invalid JSON from wrapped_key endpoint:", e)
        return

    if not wrapped_key_b64:
        print("No wrapped key available for you (not approved or expired).")
        return

    # 3) unwrap symmetric key with doctor's private RSA key
    try:
        K_data = rsa_unwrap_key(priv, wrapped_key_b64)
    except Exception as e:
        print("Failed to unwrap data key with your private key (wrong key or corrupted wrapped key):", e)
        return

    # 4) verify signature (patient_public_pem required)
    if not patient_pub_pem:
        print("Patient public key missing from server response; cannot verify signature.")
    else:
        try:
            patient_pub = rsa_load_public(patient_pub_pem.encode())
            verified = rsa_verify(patient_pub, (enc["nonce"] + "|" + enc["ciphertext"]).encode(), signature)
            print("Signature valid:", verified)
            if not verified:
                print("Warning: signature verification failed. Do NOT trust the decrypted data.")
                return
        except Exception as e:
            print("Signature verification failed:", e)
            return

    # 5) decrypt
    try:
        plaintext = aesgcm_decrypt(K_data, enc["nonce"], enc["ciphertext"])
        print("\nDecrypted patient record:\n")
        try:
            # pretty print JSON if possible
            parsed = json.loads(plaintext.decode("utf-8"))
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
        except Exception:
            print(plaintext.decode("utf-8", errors="replace"))
    except Exception as e:
        print("AES-GCM decryption failed:", e)
        return


if __name__ == "__main__":
    main()
