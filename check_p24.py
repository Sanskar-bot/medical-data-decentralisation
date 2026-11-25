content = open('server/server.py').read()

s1 = '''    found = _db_get_one_access_request(req_id)
    if not found:
        return jsonify({"error": "request_not_found"}), 404

    updates = {
        "status": status,
        f"{status}_at": datetime.now(timezone.utc),
    }'''

print(f"STEP1 COUNT={content.count(s1)}")
