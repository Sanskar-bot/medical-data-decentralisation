content = open('server/emr/routes.py').read()

# P22 snippets
snippets = [
    # STEP 1 (update_appointment)
    '''    # Only the assigned doctor or admin can update
    if jwt_p.get("role") == "doctor" and existing["doctor_id"] != jwt_p.get("uid"):
        return jsonify({"error": "forbidden"}), 403''',

    # STEP 2 (delete_appointment)
    '''    if jwt_p.get("role") == "doctor" and existing["doctor_id"] != jwt_p.get("uid"):
        return jsonify({"error": "forbidden"}), 403

    store.delete_appointment(appointment_id)''',

    # STEP 3 (update_condition)
    '''    # Only the recording doctor or admin can update
    if jwt_p.get("role") == "doctor":
        recorder = existing["recorded_by"]
        doctor_id = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
        if recorder != doctor_id:
            return jsonify({"error": "forbidden"}), 403''',

    # STEP 4 (update_encounter)
    '''    # Only the encounter's doctor or admin can update
    if jwt_p.get("role") == "doctor":
        doctor_id = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
        if existing["doctor_id"] != doctor_id:
            return jsonify({"error": "forbidden"}), 403''',
]

for i, s in enumerate(snippets, 1):
    print(f"STEP{i} COUNT={content.count(s)}")
