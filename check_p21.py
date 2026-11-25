content = open('server/emr/routes.py').read()

# P21 snippets
snippets = [
    # STEP 1
    '''def create_appointment():
    body = request.get_json(silent=True) or {}
    jwt_p = request.jwt_payload

    # Auto-fill doctor_id from JWT if not provided
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("uid", "")''',

    # STEP 2 (create_prescription)
    '''    # Use doctor_code claim (not uid which is now UUID)
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
    body["doctor_email"] = jwt_p.get("sub", "")
    if not body.get("doctor_name"):
        body["doctor_name"] = ""  # Will be filled by caller if available''',

    # STEP 3 (create_lab_report)
    '''    # Use doctor_code claim (not uid which is now UUID)
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
    body["doctor_email"] = jwt_p.get("sub", "")
    if not body.get("doctor_name"):
        body["doctor_name"] = ""

''',
    # STEP 4 (create_vitals)
    '''    if jwt_p.get("role") == "doctor" and not _doctor_has_patient_access(jwt_p, body["patient_id"], raw_patient_id):
        return jsonify({"error": "forbidden"}), 403
    if not body.get("recorded_by"):
        body["recorded_by"] = _recorded_by_from_jwt(jwt_p)''',

    # STEP 5 (create_condition)
    '''    # Auto-fill recorded_by from JWT, matching how create_prescription fills doctor_id
    if not body.get("recorded_by"):
        body["recorded_by"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
    if not body.get("patient_id"):
        return jsonify({"error": "patient_id is required"}), 400''',

    # STEP 6 (create_encounter)
    '''    # Auto-fill doctor_id from JWT
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")

    errors = models.validate_encounter(body)''',
]

for i, s in enumerate(snippets, 1):
    print(f"STEP{i} COUNT={content.count(s)}")
