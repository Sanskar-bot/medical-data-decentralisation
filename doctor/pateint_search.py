# A:\Minor_Decentralised\doctor\patient_fetch.py

import os

# === Paths ===
SERVER_USER_FOLDER = r"A:\Minor_Decentralised\server\users"

print("\n=== Patient Record Verification ===")
patient_code = input("Enter patient profile code: ").strip()

if not patient_code:
    print("[⚠] No patient code entered.")
    exit(1)

# === Check if patient file exists ===
file_path = os.path.join(SERVER_USER_FOLDER, f"{patient_code}.json")

if os.path.exists(file_path):
    print(f"[✔] Patient record with code '{patient_code}' exists on the server.")
else:
    print(f"[❌] No record found for patient code: {patient_code}")
