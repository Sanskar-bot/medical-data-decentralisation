# client/unwrap_and_decrypt.py
import os
import sys
import json
import getpass
from base64 import b64decode

# ensure project root is importable
THIS_DIR = os.path.dirname(os.path.abspath(__file__))          # .../client
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
sys.path.append(PROJECT_ROOT)

from common.crypto_utils import derive_kek_from_password, unwrap_key_with_kek, aesgcm_decrypt

def user_data_path(profile):
    # build absolute path relative to project root
    return os.path.join(PROJECT_ROOT, "client", "Users", profile, "user_data.json")

def _zero_and_del_bytes(b: bytes):
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

def main():
    profile = input("Enter profile_code (example: _2zJciwm): ").strip()
    if not profile:
        print("profile_code required.")
        return

    path = user_data_path(profile)
    if not os.path.exists(path):
        print("user_data.json not found at", path)
        return

    with open(path, "r", encoding="utf-8") as f:
        j = json.load(f)

    kp = j.get("key_protection")
    if not kp:
        print("key_protection not present in user_data.json — no wrapped_k to unwrap.")
        return

    wrapped_k = kp.get("wrapped_k") or kp.get("wrapped_k_b64")
    salt_b64 = kp.get("salt_b64") or kp.get("salt")
    if not wrapped_k or not salt_b64:
        print("wrapped_k or salt missing in key_protection.")
        return

    pw = getpass.getpass("Enter the local password used to protect the data key: ")
    salt = b64decode(salt_b64)
    kek, _ = derive_kek_from_password(pw, salt=salt)

    try:
        K_data = unwrap_key_with_kek(kek, wrapped_k)   # plaintext AES key bytes
    except Exception as e:
        print("Failed to unwrap wrapped_k — wrong password or corrupted data:", e)
        return

    print("Unwrapped K_data length (bytes):", len(K_data))

    enc = j.get("encrypted_record")
    if not enc or "nonce" not in enc or "ciphertext" not in enc:
        print("No encrypted_record present to decrypt.")
        _zero_and_del_bytes(K_data)
        return

    try:
        plaintext = aesgcm_decrypt(K_data, enc["nonce"], enc["ciphertext"])
    except Exception as e:
        print("AES-GCM decryption failed:", e)
        _zero_and_del_bytes(K_data)
        return

    try:
        parsed = json.loads(plaintext.decode("utf-8"))
        print("\nDecrypted patient record (JSON):\n", json.dumps(parsed, indent=2, ensure_ascii=False))
    except Exception:
        print("\nDecrypted patient record (raw):\n", plaintext.decode("utf-8", errors="replace"))

    # zero K_data
    _zero_and_del_bytes(K_data)

if __name__ == "__main__":
    main()
