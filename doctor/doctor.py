import requests, json, os, sys, uuid, getpass
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# FIX 1: Corrected function names (was serialize_private_key / serialize_public_key)
from common.crypto_utils import (
    generate_rsa_keypair,
    rsa_serialize_private,
    rsa_serialize_public,
    derive_kek_from_password,
    wrap_key_with_kek,
)
from base64 import b64encode

SERVER_URL = "http://127.0.0.1:5000"

# ====== Step 1: Ask doctor details ======
print("\n=== Doctor Registration ===")
name = input("Enter your full name: ")
age = input("Enter your age: ")
specialization = input("Enter your specialization: ")
qualification = input("Enter your qualification: ")
experience = input("Enter your years of experience: ")

# FIX 4: Ask for a password to protect the private key before saving
print("\nChoose a password to protect your private key (you will need this every time you log in):")
while True:
    password = getpass.getpass("Password: ")
    confirm  = getpass.getpass("Confirm password: ")
    if password and password == confirm:
        break
    print("Passwords did not match or were empty. Try again.")

# ====== Step 2: Generate RSA keys ======
priv, pub = generate_rsa_keypair()
doctor_id = str(uuid.uuid4())
doctor_code = doctor_id[:8]

# ====== Step 3: Save locally ======
doctor_folder = os.path.join(os.path.dirname(__file__), "Doctors", doctor_code)
os.makedirs(doctor_folder, exist_ok=True)

# FIX 4: Encrypt private key with password-derived KEK before saving
kek, salt = derive_kek_from_password(password)
priv_pem_bytes = rsa_serialize_private(priv)          # raw PEM bytes
wrapped_priv   = wrap_key_with_kek(kek, priv_pem_bytes)  # AES-GCM encrypted

with open(os.path.join(doctor_folder, "doctor_private_wrapped.b64"), "w") as f:
    f.write(wrapped_priv)
with open(os.path.join(doctor_folder, "key_protection.json"), "w") as f:
    json.dump({"salt_b64": b64encode(salt).decode()}, f, indent=2)
with open(os.path.join(doctor_folder, "doctor_public.pem"), "wb") as f:
    f.write(rsa_serialize_public(pub))

# Store personal info locally ONLY (never sent to server — FIX 7)
local_data = {
    "doctor_id": doctor_id,
    "doctor_code": doctor_code,
    "name": name,
    "age": age,
    "specialization": specialization,
    "qualification": qualification,
    "experience": experience
}
with open(os.path.join(doctor_folder, "doctor_data.json"), "w") as f:
    json.dump(local_data, f, indent=4)

print(f"\nDoctor ID: {doctor_id}")
print(f"Doctor Code: {doctor_code}")
print("[OK] Private key encrypted and saved. Your personal details stay on this machine only.")

# ====== Step 4: Register doctor on server ======
# FIX 7: Only send public key + IDs — no personal info to server
register_payload = {
    "doctor_id":   doctor_id,
    "doctor_code": doctor_code,
    "public_pem":  rsa_serialize_public(pub).decode(),
}

try:
    resp = requests.post(f"{SERVER_URL}/register_doctor", json=register_payload)
    if resp.status_code == 200:
        print("[done] Doctor registered successfully with server.")
    else:
        print("[not done] Registration failed:", resp.text)
except Exception as e:
    print("Error connecting to server:", e)
