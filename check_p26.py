srv = open('server/server.py').read()

# P26 STEP 1 (register_user)
s1 = '''    safe_profile = "".join([c for c in profile if c.isalnum() or c in ("-", "_")])

    obj = {'''

# P26 STEP 2 (register_doctor)
s2 = '''    if not doctor_id or not doctor_code or not public_pem:
        return jsonify({"error": "missing_required_fields",
                        "required": ["doctor_id", "doctor_code", "public_pem"]}), 400'''

for i, s in enumerate([s1, s2], 1):
    print(f"STEP{i} COUNT={srv.count(s)}")
