# doctor/fetch_patient_data.py
"""Doctor script: fetch wrapped key, decrypt patient record, verify signature."""

import os, sys, json, requests, getpass
from base64 import b64decode

# ensure project root is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.crypto_utils import (
    rsa_load_private,
    rsa_unwrap_key,
    rsa_load_public,
    rsa_verify,
    aesgcm_decrypt
)

SERVER = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")

def auto_locate_doctor_folder(doctor_code):
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Doctors")
    if not os.path.isdir(base):
        return None
    for d in os.listdir(base):
        folder = os.path.join(base, d)
        meta = os.path.join(folder, "doctor_data.json")
        if os.path.exists(meta):
            try:
                with open(meta, "r", encoding="utf-8") as f:
                    j = json.load(f)
                if j.get("doctor_code") == doctor_code or j.get("doctor_id", "").startswith(doctor_code):
                    return folder
            except Exception:
                pass
    return None

def load_doctor_private_from_folder(folder):
    """Support raw PEM or wrapped private key with key_protection.json."""
    raw = os.path.join(folder, "doctor_private.pem")
    wrapped = os.path.join(folder, "doctor_private_wrapped.b64")
    keyprot = os.path.join(folder, "key_protection.json")
    if os.path.exists(raw):
        with open(raw, "rb") as f:
            return rsa_load_private(f.read())
    if os.path.exists(wrapped) and os.path.exists(keyprot):
        with open(wrapped, "r", encoding="utf-8") as f:
            wrapped_b64 = f.read().strip()
        with open(keyprot, "r", encoding="utf-8") as f:
            kp = json.load(f)
        salt_b64 = kp.get("salt_b64") or kp.get("salt")
        if not salt_b64:
            raise ValueError("salt_b64 missing in key_protection.json")
        salt = b64decode(salt_b64)
        pw = getpass.getpass("Enter local password to unwrap your doctor private key: ")
        # use derive_kek_from_password & unwrap_key_with_kek from common.crypto_utils if needed
        # we'll reuse rsa_load_private assuming unwrap helper returns raw PEM bytes, so call helper from common
        from common.crypto_utils import derive_kek_from_password, unwrap_key_with_kek
        kek, _ = derive_kek_from_password(pw, salt=salt)
        priv_pem = unwrap_key_with_kek(kek, wrapped_b64)
        return rsa_load_private(priv_pem)
    raise FileNotFoundError("No doctor private key found in folder (doctor_private.pem or wrapped pair).")

def fetch_encrypted_data(profile_code):
    url = f"{SERVER.rstrip('/')}/get_patient_data/{profile_code}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"Server returned error fetching patient data: {r.status_code} {r.text}")
    return r.json()

def fetch_wrapped_key(profile_code):
    url = f"{SERVER.rstrip('/')}/wrapped_key/{profile_code}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"Server returned error fetching wrapped key: {r.status_code} {r.text}")
    j = r.json()
    # wrapped_keys may be a map doctor_code->object; try to find our doctor code later
    return j

def main():
    print("\n=== Doctor: Fetch & Decrypt Patient Record ===\n")
    profile_code = input("Patient profile_code: ").strip()
    if not profile_code:
        print("profile_code required."); return

    pk_input = input("Path to your doctor private PEM or doctor folder (press Enter to use doctor/Doctors/<doctor_id>): ").strip()
    if not pk_input:
        code = input("No path provided. Enter your doctor_code to auto-locate local folder (or leave blank to abort): ").strip()
        if not code:
            print("Abort."); return
        folder = auto_locate_doctor_folder(code)
        if not folder:
            print("Could not locate doctor folder for code:", code); return
        print("[INFO] Auto-located doctor folder:", folder)
        key_path = folder
    else:
        key_path = pk_input

    # load doctor's private key
    try:
        if os.path.isdir(key_path):
            priv = load_doctor_private_from_folder(key_path)
        else:
            with open(key_path, "rb") as f:
                priv = rsa_load_private(f.read())
    except Exception as e:
        print("Failed to load doctor private key:", e); return

    # 1) get encrypted patient record
    try:
        enc_resp = fetch_encrypted_data(profile_code)
    except Exception as e:
        print(e); return

    enc = enc_resp.get("encrypted_record")
    signature = enc_resp.get("signature")
    patient_pub_pem = enc_resp.get("patient_public_pem")

    if not enc or "nonce" not in enc or "ciphertext" not in enc:
        print("Malformed encrypted_record from server"); return

    # 2) get wrapped key(s) for this profile
    try:
        wk_resp = fetch_wrapped_key(profile_code)
    except Exception as e:
        print(e); return

    # attempt to find wrapped_key file that corresponds to this doctor.
    # The server may return {"wrapped_keys": { "doctor_code": { ... } } } or {"wrapped_key": "..."}
    wrapped_key_b64 = None
    if isinstance(wk_resp, dict):
        # prefer direct wrapped_key field
        if "wrapped_key" in wk_resp:
            wrapped_key_b64 = wk_resp["wrapped_key"]
        else:
            wkmap = wk_resp.get("wrapped_keys") or wk_resp
            # try to find using doctor_code if available locally
            # extract doctor's code from local folder if we auto-located
            local_doc_code = None
            if os.path.isdir(key_path):
                md = os.path.join(key_path, "doctor_data.json")
                if os.path.exists(md):
                    try:
                        with open(md, "r", encoding='utf-8') as f:
                            j = json.load(f)
                        local_doc_code = j.get("doctor_code")
                    except Exception:
                        pass
            # pick matching entry if possible
            if isinstance(wkmap, dict):
                if local_doc_code and local_doc_code in wkmap:
                    wrapped_key_b64 = wkmap[local_doc_code].get("wrapped_key") if isinstance(wkmap[local_doc_code], dict) else wkmap[local_doc_code]
                else:
                    # pick any available wrapped key (if only one)
                    if len(wkmap) == 1:
                        first = next(iter(wkmap.values()))
                        wrapped_key_b64 = first.get("wrapped_key") if isinstance(first, dict) else first

    if not wrapped_key_b64:
        print("No wrapped key available for this doctor yet. Patient must approve first (or wrapped_key stored under patient's wrapped_keys).")
        return

    # 3) unwrap K_data with doctor's private RSA
    try:
        K_data = rsa_unwrap_key(priv, wrapped_key_b64)
    except Exception as e:
        print("Failed to unwrap data key with your private key (wrong key or corrupted wrapped key):", e)
        return

    # 4) verify patient's signature (if present)
    if patient_pub_pem:
        try:
            patient_pub = rsa_load_public(patient_pub_pem.encode())
            verified = rsa_verify(patient_pub, (enc["nonce"] + "|" + enc["ciphertext"]).encode(), signature)
            print("Signature valid:", verified)
            if not verified:
                print("Warning: signature verification failed. Aborting decryption.")
                return
        except Exception as e:
            print("Signature verification failed:", e)
            return
    else:
        print("No patient public key present; cannot verify signature.")

    # 5) decrypt AES-GCM encrypted patient record
    try:
        plaintext = aesgcm_decrypt(K_data, enc["nonce"], enc["ciphertext"])
        parsed = None
        try:
            parsed = json.loads(plaintext.decode("utf-8"))
            print("\nDecrypted patient record (JSON):\n")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
        except Exception:
            print("\nDecrypted patient record (raw):\n")
            print(plaintext.decode("utf-8", errors="replace"))
    except Exception as e:
        print("AES-GCM decryption failed:", e)
        return

if __name__ == "__main__":
    main()
