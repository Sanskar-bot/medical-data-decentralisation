# doctor/fetch_patient_data_debug.py
"""
Doctor debug fetch: fetch wrapped key, unwrap, then try multiple AES-GCM decryption strategies
to diagnose why aesgcm_decrypt() failed in your environment.
"""
import os, sys, json, requests, getpass, binascii
from base64 import b64decode, b64encode

# allow project imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.crypto_utils import (
    rsa_load_private,
    rsa_unwrap_key,
    rsa_load_public,
    rsa_verify,
    # try using project helper first; fallback to cryptography AESGCM if needed
    aesgcm_decrypt,
)

# fallback AESGCM (if cryptography available)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AESGCM = True
except Exception:
    _HAS_AESGCM = False

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
        from common.crypto_utils import derive_kek_from_password, unwrap_key_with_kek
        kek, _ = derive_kek_from_password(pw, salt=salt)
        priv_pem = unwrap_key_with_kek(kek, wrapped_b64)
        return rsa_load_private(priv_pem)
    raise FileNotFoundError("No doctor private key found in folder")


def get_encrypted_data(profile_code):
    r = requests.get(f"{SERVER.rstrip('/')}/get_patient_data/{profile_code}", timeout=10)
    r.raise_for_status()
    return r.json()


def get_wrapped_key(profile_code):
    r = requests.get(f"{SERVER.rstrip('/')}/wrapped_key/{profile_code}", timeout=10)
    r.raise_for_status()
    return r.json()


def try_decrypt_with_helper(K_data, nonce_in, ciphertext_in):
    """
    Try project helper aesgcm_decrypt with several input types.
    Return plaintext bytes on success, else raise last exception.
    """
    last_exc = None
    attempts = []

    # 1) if both appear to be base64 strings, b64decode them then call helper with bytes (if helper accepts bytes)
    try:
        nonce_bytes = b64decode(nonce_in) if isinstance(nonce_in, str) else nonce_in
        ct_bytes = b64decode(ciphertext_in) if isinstance(ciphertext_in, str) else ciphertext_in
        attempts.append(("b64decode -> helper", type(nonce_bytes), len(nonce_bytes), len(ct_bytes)))
        res = aesgcm_decrypt(K_data, b64encode(nonce_bytes).decode() if isinstance(nonce_in, str) else nonce_bytes, b64encode(ct_bytes).decode() if isinstance(ciphertext_in, str) else ct_bytes)
        return res
    except Exception as e:
        last_exc = e

    # 2) pass raw base64 strings directly (some helpers expect base64 strings)
    try:
        attempts.append(("pass base64 strings -> helper", type(nonce_in), type(ciphertext_in)))
        res = aesgcm_decrypt(K_data, nonce_in, ciphertext_in)
        return res
    except Exception as e:
        last_exc = e

    # 3) try helper with raw bytes (if helper expects bytes, not b64 strings)
    try:
        nonce_bytes = b64decode(nonce_in) if isinstance(nonce_in, str) else nonce_in
        ct_bytes = b64decode(ciphertext_in) if isinstance(ciphertext_in, str) else ciphertext_in
        attempts.append(("pass raw bytes -> helper", type(nonce_bytes), len(nonce_bytes), len(ct_bytes)))
        res = aesgcm_decrypt(K_data, nonce_bytes, ct_bytes)
        return res
    except Exception as e:
        last_exc = e

    # 4) direct AESGCM fallback (cryptography), if available
    if _HAS_AESGCM:
        try:
            # AESGCM expects 12-byte nonce and ciphertext (ct includes tag)
            nonce_bytes = b64decode(nonce_in) if isinstance(nonce_in, str) else nonce_in
            ct_bytes = b64decode(ciphertext_in) if isinstance(ciphertext_in, str) else ciphertext_in
            a = AESGCM(K_data)
            plaintext = a.decrypt(nonce_bytes, ct_bytes, None)
            return plaintext
        except Exception as e:
            last_exc = e

    # If we reached here, all attempts failed
    raise RuntimeError(f"All decryption attempts failed. Last error: {last_exc}")


def main():
    print("\n=== Doctor debug fetch & decrypt ===\n")
    profile_code = input("Patient profile_code: ").strip()
    if not profile_code:
        print("profile_code required."); return

    path = input("Path to your doctor private PEM or doctor folder (press Enter to auto-locate): ").strip()
    key_path = path
    if not path:
        code = input("Enter your doctor_code to auto-locate: ").strip()
        if not code:
            print("abort"); return
        folder = auto_locate_doctor_folder(code)
        if not folder:
            print("Could not locate doctor folder"); return
        print("[INFO] Auto-located doctor folder:", folder)
        key_path = folder

    # load doctor private
    try:
        if os.path.isdir(key_path):
            priv = load_doctor_private_from_folder(key_path)
        else:
            with open(key_path, "rb") as f:
                priv = rsa_load_private(f.read())
    except Exception as e:
        print("Failed to load doctor private key:", e); return

    # fetch encrypted data
    try:
        enc_resp = get_encrypted_data(profile_code)
    except Exception as e:
        print("Failed to fetch encrypted data:", e); return

    enc = enc_resp.get("encrypted_record")
    signature = enc_resp.get("signature")
    patient_pub_pem = enc_resp.get("patient_public_pem")

    print("\n[DEBUG] Encrypted record from server:")
    print(json.dumps(enc_resp, indent=2, ensure_ascii=False))

    # fetch wrapped key map
    try:
        wk = get_wrapped_key(profile_code)
    except Exception as e:
        print("Failed to fetch wrapped key:", e); return
    print("\n[DEBUG] Wrapped key response from server:")
    print(json.dumps(wk, indent=2, ensure_ascii=False))

    # pick a wrapped key if response is a map
    wrapped_key_b64 = None
    if isinstance(wk, dict):
        if "wrapped_key" in wk:
            wrapped_key_b64 = wk["wrapped_key"]
        else:
            wkmap = wk.get("wrapped_keys") or wk
            if isinstance(wkmap, dict):
                # try to pick the first entry
                if wkmap:
                    first = next(iter(wkmap.values()))
                    wrapped_key_b64 = first.get("wrapped_key") if isinstance(first, dict) else first
    if not wrapped_key_b64:
        print("No wrapped key found for this profile on server.")
        return

    print("\n[DEBUG] Wrapped key (len):", len(wrapped_key_b64))

    # unwrap to get K_data
    try:
        K_data = rsa_unwrap_key(priv, wrapped_key_b64)
    except Exception as e:
        print("Failed to unwrap K_data with your private key:", e)
        return

    print("[DEBUG] Unwrapped K_data type:", type(K_data), "len:", len(K_data) if isinstance(K_data, (bytes, bytearray)) else "N/A")
    try:
        print("[DEBUG] K_data (hex):", binascii.hexlify(K_data).decode())
    except Exception:
        pass

    # Try decryption with multiple strategies
    try:
        plaintext = try_decrypt_with_helper(K_data, enc.get("nonce"), enc.get("ciphertext"))
        try:
            parsed = json.loads(plaintext.decode("utf-8"))
            print("\n[OK] Decrypted JSON record:\n", json.dumps(parsed, indent=2, ensure_ascii=False))
        except Exception:
            print("\n[OK] Decrypted raw record:\n", plaintext.decode("utf-8", errors="replace"))
    except Exception as e:
        print("\n[ERROR] Decryption attempts failed:", e)
        print("Hints:")
        print(" - Confirm 'K_data' length is 32 bytes and is the same key the patient used to encrypt.")
        print(" - Confirm server 'encrypted_record' stores nonce & ciphertext as base64 (and ciphertext includes auth tag).")
        print(" - If patient used a custom aesgcm wrapper, check its exact input types/encoding.")
        return


if __name__ == "__main__":
    main()
