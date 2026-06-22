# doctor/diag_decrypt.py
# Diagnostic AES-GCM decrypt helper (doctor side)
# Usage: python diag_decrypt.py
import sys, json
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def try_decrypt(k_bytes, nonce_b64, ct_b64):
    try:
        nonce = b64decode(nonce_b64)
    except Exception as e:
        print("[ERROR] nonce base64 decode failed:", e); return
    try:
        ct = b64decode(ct_b64)
    except Exception as e:
        print("[ERROR] ciphertext base64 decode failed:", e); return

    print("[INFO] key len:", len(k_bytes))
    print("[INFO] nonce len:", len(nonce))
    print("[INFO] ciphertext len (including tag?):", len(ct))
    # heuristics: AES-GCM default tag=16 bytes
    if len(ct) >= 16:
        print("[INFO] assuming last 16 bytes are the auth tag.")
    else:
        print("[WARN] ciphertext too short to contain typical 16-byte tag.")

    aesgcm = AESGCM(k_bytes)
    try:
        # AESGCM expects ciphertext + tag combined in 'ct'
        pt = aesgcm.decrypt(nonce, ct, associated_data=None)
        print("\n[OK] Decryption succeeded. Plaintext (utf-8):\n")
        try:
            print(pt.decode("utf-8"))
        except Exception:
            print(repr(pt))
        return True
    except Exception as e:
        print("\n[FAIL] AESGCM.decrypt failed:", e)
        return False

def main():
    print("Diagnostic AES-GCM decrypt helper")
    k_hex = input("Enter K_data hex (doctor unwrapped key) or path to a file with raw bytes: ").strip()
    if k_hex.endswith(".bin") or (len(k_hex) > 0 and any(c for c in k_hex if c in "/\\")):
        # assume path to raw file
        with open(k_hex,"rb") as f:
            k_bytes = f.read()
    else:
        # parse hex (if looks like hex) or base64
        if all(c in "0123456789abcdefABCDEF" for c in k_hex) and len(k_hex) % 2 == 0:
            k_bytes = bytes.fromhex(k_hex)
        else:
            try:
                k_bytes = b64decode(k_hex)
            except Exception:
                print("[ERROR] Unable to parse provided key string (not hex, not file, not base64).")
                return

    nonce_b64 = input("Enter nonce (base64) from server: ").strip()
    ct_b64 = input("Enter ciphertext (base64) from server: ").strip()

    ok = try_decrypt(k_bytes, nonce_b64, ct_b64)
    if not ok:
        # helpful extra checks
        print("\n[DEBUG HINTS]")
        print("- Confirm the patient encrypted with AES-GCM using the SAME K_data.")
        print("- Confirm server stored ciphertext as base64 of (ciphertext || auth_tag).")
        print("- If patient stored 'ciphertext' and 'tag' separately, supply ciphertext||tag concatenation here.")
        print("- Ensure there were no accidental newlines, truncation, or JSON re-encoding issues.")
        print("- If patient used a custom wrapper, check whether they hex-encoded bytes before base64 or vice-versa.")
    print("Done.")

if __name__ == '__main__':
    main()

