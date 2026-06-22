# doctor/register_doctor.py
"""
Doctor registration script that:
 - stores doctor details locally in plaintext (doctor/Doctors/<doctor_id>/doctor_data.json)
 - stores keys locally (private wrapped or plaintext, public PEM)
 - encrypts the doctor's profile locally (RSA-OAEP) and sends only the encrypted_profile + public_pem to the server
 - server stores the encrypted blob (server cannot read plaintext)
"""

import os
import sys
import json
import uuid
import getpass
import requests
from base64 import b64encode

# ensure project root is on sys.path so `common` package can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.crypto_utils import (
    generate_rsa_keypair,
    rsa_serialize_private,
    rsa_serialize_public,
    derive_kek_from_password,
    wrap_key_with_kek,
    rsa_wrap_key,
)

# CONFIG
SERVER_URL = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")


def prompt_doctor_details():
    print("\n=== Doctor Registration ===")
    name = input("Full name: ").strip()
    while not name:
        print("Name cannot be empty.")
        name = input("Full name: ").strip()

    hospital = input("Hospital/Clinic name (optional): ").strip()
    specialization = input("Specialization (optional): ").strip()
    email = input("Email (optional): ").strip()
    return {"name": name, "hospital": hospital, "specialization": specialization, "email": email}


def main():
    details = prompt_doctor_details()

    # Generate RSA keypair
    print("\nGenerating RSA key pair (2048-bit) ...")
    priv, pub = generate_rsa_keypair(key_size=2048)
    priv_pem = rsa_serialize_private(priv, password=None)  # bytes (unencrypted PEM)
    pub_pem = rsa_serialize_public(pub)  # bytes

    # IDs
    doctor_id = str(uuid.uuid4())
    doctor_code = doctor_id[:8]

    # Base folder (where this script lives)
    base_dir = os.path.dirname(os.path.abspath(__file__))  # A:\Minor_Decentralised\doctor
    doctors_dir = os.path.join(base_dir, "Doctors")
    os.makedirs(doctors_dir, exist_ok=True)

    # Doctor folder
    doctor_folder = os.path.join(doctors_dir, doctor_id)
    os.makedirs(doctor_folder, exist_ok=True)
    print(f"[INFO] Local doctor folder: {doctor_folder}")

    # Option: protect private PEM with a password (wrap the private PEM bytes using KEK)
    protect = input("Protect private key with a local password? (Y/n): ").strip().lower()
    key_protection_info = None

    if protect in ("", "y", "yes"):
        while True:
            pw = getpass.getpass("Choose a local password to protect your private key: ")
            if not pw:
                print("Password cannot be empty.")
                continue
            pw2 = getpass.getpass("Confirm password: ")
            if pw != pw2:
                print("Passwords do not match. Try again.")
                continue
            break
        kek, salt = derive_kek_from_password(pw)
        wrapped = wrap_key_with_kek(kek, priv_pem)  # wrap the **private PEM bytes**
        # Store wrapped private key file and salt locally
        with open(os.path.join(doctor_folder, "doctor_private_wrapped.b64"), "w", encoding="utf-8") as f:
            f.write(wrapped)
        key_protection_info = {"wrapped_private_b64": wrapped, "salt_b64": b64encode(salt).decode()}
        # Do NOT write raw priv_pem to disk in this case
        print("[INFO] Private key wrapped with password and saved locally (doctor_private_wrapped.b64).")
    else:
        # Save raw private PEM (not recommended unless you secure the folder)
        with open(os.path.join(doctor_folder, "doctor_private.pem"), "wb") as f:
            f.write(priv_pem)
        print("[WARN] Private key saved unencrypted at doctor_private.pem (keep secure).")

    # always save public key
    with open(os.path.join(doctor_folder, "doctor_public.pem"), "wb") as f:
        f.write(pub_pem)

    # Save local plaintext doctor metadata (so doctor has local copy)
    local_data = {
        "doctor_id": doctor_id,
        "doctor_code": doctor_code,
        "name": details["name"],
        "hospital": details["hospital"],
        "specialization": details["specialization"],
        "email": details["email"],
        # DO NOT store private key here
    }
    with open(os.path.join(doctor_folder, "doctor_data.json"), "w", encoding="utf-8") as f:
        json.dump(local_data, f, indent=2, ensure_ascii=False)

    # Save key protection metadata if used (optional separate file)
    if key_protection_info:
        with open(os.path.join(doctor_folder, "key_protection.json"), "w", encoding="utf-8") as f:
            json.dump(key_protection_info, f, indent=2, ensure_ascii=False)

    print("\n[INFO] Local doctor data stored.")
    print("IMPORTANT: keep the doctor folder secure and do not commit private key files to version control.")

    # -----------------------
    # Prepare encrypted_profile (encrypt plaintext profile with doctor's public key)
    # -----------------------
    profile_plain = {
        "name": details["name"],
        "hospital": details["hospital"],
        "specialization": details["specialization"],
        "email": details["email"]
    }
    profile_bytes = json.dumps(profile_plain, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    # RSA-OAEP encrypt profile bytes with doctor's PUBLIC key so only doctor can decrypt with private key
    try:
        encrypted_profile_b64 = rsa_wrap_key(pub, profile_bytes)  # returns base64 string
    except Exception as e:
        print("[ERROR] Failed to encrypt profile locally:", e)
        encrypted_profile_b64 = None

    # Build payload — include encrypted_profile (server stores it) but do NOT include plaintext fields
    payload = {
        "doctor_id": doctor_id,
        "doctor_code": doctor_code,
        "public_pem": pub_pem.decode("utf-8"),
        "encrypted_profile": encrypted_profile_b64
    }

    # Optionally add a non-identifying hint (uncomment if desired)
    # payload.update({"specialization_tag": details["specialization"][:20] if details["specialization"] else None})

    # Register on server
    try:
        resp = requests.post(f"{SERVER_URL.rstrip('/')}/register_doctor", json=payload, timeout=10)
        if resp.status_code == 200:
            print("[✔] Doctor registered successfully on server.")
        else:
            print(f"[❌] Server responded with status {resp.status_code}: {resp.text}")
    except Exception as e:
        print("[❌] Error connecting to server:", e)
        print("Local files were saved; you can retry server registration later.")

    print("\nDoctor ID:", doctor_id)
    print("Doctor Code:", doctor_code)
    print("\nDone.")


if __name__ == "__main__":
    main()
