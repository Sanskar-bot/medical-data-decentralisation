# A:\Minor_Decentralised\server\generate_key.py
from cryptography.fernet import Fernet
import os

key_path = r"A:\Minor_Decentralised\server\fernet.key"

if not os.path.exists(key_path):
    key = Fernet.generate_key()
    with open(key_path, "wb") as f:
        f.write(key)
    print(f"[✔] Fernet key created at: {key_path}")
else:
    print("[ℹ] Fernet key already exists.")
