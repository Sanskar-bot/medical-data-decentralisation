content = open('server/server.py').read()

s1 = '''            role = jwt_payload.get("role", "")
            uid  = jwt_payload.get("uid", "")
            if role == "patient" and uid != patient_code:
                return jsonify({"error": "forbidden"}), 403
            if role == "doctor" and not _doctor_has_active_access(patient_code, uid):'''

s2 = '''            caller_uid = jwt_payload.get("uid", "")
            role = jwt_payload.get("role", "")
            if role == "patient" and caller_uid != uid:
                return jsonify({"error": "forbidden"}), 403
            if role == "doctor" and not _doctor_has_active_access(uid, caller_uid):
                return jsonify({"error": "forbidden"}), 403'''

s3 = '''    if note_id_from_file:
        note = _db_get_note(note_id_from_file)
        if note:
            auth_hdr = request.headers.get("Authorization", "")
            token = auth_hdr.replace("Bearer ", "").strip() if auth_hdr.startswith("Bearer ") else ""
            if not token:
                token = request.cookies.get("access_token", "")
            if token:
                jwt_payload = _jwt_decode(token)
                if jwt_payload:
                    caller_uid = jwt_payload.get("uid", "")
                    if (caller_uid != note.get("patient_code") and
                            caller_uid != note.get("doctor_code")):
                        return jsonify({"error": "forbidden"}), 403
                else:
                    return jsonify({"error": "invalid_or_expired_token"}), 401
            else:
                return jsonify({"error": "missing_token"}), 401'''

for i, s in enumerate([s1, s2, s3], 1):
    print(f"STEP{i} COUNT={content.count(s)}")
