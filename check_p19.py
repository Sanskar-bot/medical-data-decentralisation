content = open('server/emr/routes.py').read()

s1 = '''    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    # Patient can only view own prescriptions
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403'''

s2 = '''    # Patient can only fetch own prescriptions
    patient_code = p.get("profile_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != rx["patient_id"]:
        return jsonify({"error": "forbidden"}), 403'''

s3 = '''    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    # Patient can only view own lab reports
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403'''

s4 = '''    patient_code = p.get("profile_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != report["patient_id"]:
        return jsonify({"error": "forbidden"}), 403'''

for i, s in enumerate([s1, s2, s3, s4], 1):
    print(f"STEP{i} COUNT={content.count(s)}")
