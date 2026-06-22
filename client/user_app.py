# client/register_patient.py
"""
Interactive patient registration script.

- Prompts patient for details (name, age, email, notes).
- Generates RSA key pair for patient (saved to client/Users/<profile_code>/).
- Generates AES-GCM data key (K_data) and encrypts the patient JSON record.
- Signs the ciphertext using patient's private RSA key.
- Optionally wraps K_data locally with a password-derived KEK (recommended).
- Saves local file client/Users/<profile_code>/user_data.json (NO plaintext K_data if password used).
- Uploads only: profile_code, encrypted_record, signature, patient_public_pem to server.
"""

import os
import json
import sys
import getpass
import requests
from base64 import b64encode

# ensure project root is on sys.path so `common` package can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Local imports - make sure common/crypto_utils.py exists (from previous upgrade)
from common.crypto_utils import (
    generate_rsa_keypair,
    rsa_serialize_private,
    rsa_serialize_public,
    generate_aes_key,
    aesgcm_encrypt,
    rsa_sign,
    derive_kek_from_password,
    wrap_key_with_kek,
)

# ---- CONFIG ----
SERVER_BASE = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")  # change as needed

# base dir = folder where this file lives: A:\Minor_Decentralised\client
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# USERS_DIR = A:\Minor_Decentralised\client\Users
USERS_DIR = os.path.join(BASE_DIR, "Users")

# ---- Helpers ----
def save_pem(path: str, data_bytes: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data_bytes)

def safe_mkdir(path: str):
    os.makedirs(path, exist_ok=True)

def prompt_patient_details():
    print("=== Patient Registration ===")
    name = input("Full name: ").strip()
    while not name:
        print("Name cannot be empty.")
        name = input("Full name: ").strip()

    age_text = input("Age (leave blank if you prefer not to say): ").strip()
    age = None
    if age_text:
        try:
            age = int(age_text)
        except ValueError:
            print("Invalid age; storing as text.")
            age = age_text

    email = input("Email (optional): ").strip()
    notes = input("Optional short notes (medical conditions / summary) (optional): ").strip()
    return {"name": name, "age": age, "email": email, "notes": notes}

def generate_profile_code() -> str:
    # human-readable short code: base64 of 6 random bytes with URL-safe characters
    return b64encode(os.urandom(6)).decode().replace("=", "").replace("/", "_")

# ---- Main flow ----
def main():
    # 1) collect patient details
    patient_obj = prompt_patient_details()
    patient_plain = json.dumps(patient_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    # 2) generate RSA key pair for patient
    print("\nGenerating RSA key pair for patient (2048-bit) ...")
    priv, pub = generate_rsa_keypair(key_size=2048)
    priv_pem = rsa_serialize_private(priv, password=None)  # optionally add password param
    pub_pem = rsa_serialize_public(pub)

    # 3) generate AES-GCM data key (K_data) and encrypt patient record
    print("Generating AES-GCM (256-bit) data key and encrypting patient record ...")
    K_data = generate_aes_key()
    enc = aesgcm_encrypt(K_data, patient_plain)
    nonce_b64 = enc["nonce"]
    ciphertext_b64 = enc["ciphertext"]

    # 4) sign ciphertext (nonce|ciphertext) with patient's private key
    to_sign = (nonce_b64 + "|" + ciphertext_b64).encode("utf-8")
    signature_b64 = rsa_sign(priv, to_sign)

    # 5) decide whether to password-protect K_data locally
    print("\nYou should protect your local data encryption key with a password (recommended).")
    use_pw = input("Would you like to protect the data key with a password? (Y/n): ").strip().lower()
    key_protection = None
    if use_pw in ("", "y", "yes"):
        # read password securely twice
        while True:
            password = getpass.getpass("Choose a local password to protect your data key: ")
            if not password:
                print("Password cannot be empty. If you don't want a password, run again and choose 'n'.")
                continue
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print("Passwords do not match. Try again.")
                continue
            break
        # derive KEK and wrap K_data
        kek, salt = derive_kek_from_password(password)
        wrapped_k_b64 = wrap_key_with_kek(kek, K_data)
        key_protection = {"wrapped_k": wrapped_k_b64, "salt_b64": b64encode(salt).decode()}
        print("Data key protected locally with password-derived key.")
    else:
        # if user opts out, warn them and proceed (K_data lives only in memory until we exit)
        print("WARNING: You chose NOT to protect the data key. If you do not store K_data elsewhere securely, you will not be able to re-wrap for doctors later unless you keep the private key and K_data in memory/backup.")
        key_protection = None

    # 6) create profile directory and save local files
    profile_code = generate_profile_code()
    profile_dir = os.path.join(USERS_DIR, profile_code)
    safe_mkdir(profile_dir)
    print(f"[DEBUG] Saving local patient data to: {profile_dir}")

    # save private/public keys
    priv_path = os.path.join(profile_dir, "patient_private.pem")
    pub_path = os.path.join(profile_dir, "patient_public.pem")
    save_pem(priv_path, priv_pem)
    save_pem(pub_path, pub_pem)

    # save user_data.json (include full plaintext patient details locally)
    local_json = {
        "profile_code": profile_code,
        # FULL PLAINTEXT PATIENT DETAILS (LOCAL ONLY)
        "patient_details": patient_obj,
        "patient_public_pem": pub_pem.decode("utf-8"),
        "encrypted_record": {"nonce": nonce_b64, "ciphertext": ciphertext_b64},
        "signature": signature_b64,
        "key_protection": key_protection  # may be None
        # note: DO NOT include K_data as plaintext here
    }

    user_data_path = os.path.join(profile_dir, "user_data.json")
    with open(user_data_path, "w", encoding="utf-8") as f:
        json.dump(local_json, f, indent=2, ensure_ascii=False)

    # 7) upload metadata and encrypted record to server
    print("\nUploading encrypted record and public key to server ...")
    payload = {
        "profile_code": profile_code,
        "encrypted_record": local_json["encrypted_record"],
        "signature": signature_b64,
        "patient_public_pem": local_json["patient_public_pem"]
    }
    try:
        resp = requests.post(SERVER_BASE.rstrip("/") + "/register_user", json=payload, timeout=10)
        if resp.status_code == 200:
            print("Server responded OK.")
        else:
            print(f"Server responded with status {resp.status_code}: {resp.text}")
    except Exception as e:
        print("Warning: failed to upload to server:", str(e))
        print("You can retry upload later. The encrypted record and public key are saved locally.")

    # 8) final message with guidance
    print("\n=== Registration complete ===")
    print("Profile code:", profile_code)
    print("Local files saved to:", profile_dir)
    if key_protection:
        print("- Your AES data key is protected locally with a password you chose.")
    else:
        print("- You did not password-protect the AES data key. Keep your private key (patient_private.pem) safe; it is required to prove ownership and may be required for recovery operations.")
    print("\nImportant next steps:")
    print(f" - Back up the folder {profile_dir} securely (private key + key protection).")
    print(" - Do NOT share patient_private.pem with anyone.")
    print(" - To allow a doctor to access your data, use client/approve_request.py to wrap the data key for the doctor's public key and upload the wrapped key.")
    print("\nIf you want, run this script again to register another patient profile.\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
