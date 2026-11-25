content = open('server/emr/routes.py').read()

# P20 STEP 1
s1 = '''def list_patient_appointments(patient_id):
    p = request.jwt_payload
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403'''

# P20 STEP 2 (list_patient_conditions)
s2 = '''    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403
    status_filter = request.args.get("status") or None'''

# P20 STEP 3 (list_patient_encounters)
s3 = '''    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403
    encs = store.encounters_for_patient(patient_id)'''

# P20 STEP 4 (get_encounter)
s4 = '''    patient_code = p.get("profile_code") or p.get("uid", "")
    doctor_id    = p.get("doctor_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != enc["patient_id"]:
        return jsonify({"error": "forbidden"}), 403
    if p.get("role") == "doctor" and doctor_id != enc["doctor_id"]:
        return jsonify({"error": "forbidden"}), 403
    _audit("emr_encounter_read", actor=p.get("uid") or p.get("sub", ""),'''

# P20 STEP 5 (get_encounter_bundle)
s5 = '''    patient_code = p.get("profile_code") or p.get("uid", "")
    doctor_id    = p.get("doctor_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != enc["patient_id"]:
        return jsonify({"error": "forbidden"}), 403
    if p.get("role") == "doctor" and doctor_id != enc["doctor_id"]:
        return jsonify({"error": "forbidden"}), 403
    bundle = store.get_encounter_bundle(encounter_id)'''

for i, s in enumerate([s1, s2, s3, s4, s5], 1):
    print(f"STEP{i} COUNT={content.count(s)}")
