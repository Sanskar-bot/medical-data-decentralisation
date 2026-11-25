content = open('server/server.py').read()

# P23 STEP 1: insert _caller_payload above _caller_may_access_patient
s1 = '''def _caller_may_access_patient(profile_code: str) -> bool:
    """[C2] Thin wrapper: decode the caller's token and ask authz."""'''

# P23 STEP 2: approve_request second half
s2 = '''    # Verify request exists and matches
    found = _db_get_one_access_request(req_id)
    if not found or found.get("profile_code") != patient_code or found.get("doctor_code") != doctor_code:
        return jsonify({"error": "request_not_found"}), 404

    # Persist wrapped key to DB
    if wrapped_key:
        try:
            _db_upsert_wrapped_key(patient_code, doctor_code, {
                "wrapped_key": wrapped_key,
                "encrypted_kdata_with_temp": enc_kdata_with_temp,
                "temp_key_expires_at": temp_key_expires_at,
            })
        except Exception as e:
            return jsonify({"error": "write_wrapped_key_failed", "details": str(e)}), 500

    # Update request status
    updates = {
        "status": "approved",
        "approved_at": datetime.now(timezone.utc),
    }
    if wrapped_key:
        updates["wrapped_key"] = wrapped_key
    if enc_kdata_with_temp:
        updates["encrypted_kdata"] = json.dumps(enc_kdata_with_temp) \\
            if isinstance(enc_kdata_with_temp, dict) else enc_kdata_with_temp
    if temp_key_expires_at:
        try:
            updates["temp_key_expires_at"] = datetime.fromisoformat(temp_key_expires_at)
        except ValueError:
            pass

    try:
        _db_update_access_request(req_id, updates)
    except Exception as e:
        return jsonify({"error": "update_failed", "details": str(e)}), 500

    return jsonify({"status": "ok", "request_id": req_id}), 200'''

for i, s in enumerate([s1, s2], 1):
    print(f"STEP{i} COUNT={content.count(s)}")
