srv = open('server/server.py').read()
pp = open('portals/patient_portal.py').read()

# P25 STEP 1
s1 = '''@app.route("/active_requests", methods=["GET"])
def get_all_active_requests():
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    arr = _db_get_access_requests()
    return jsonify(arr), 200


@app.route("/request_status/<request_id>", methods=["GET"])
def get_request_status(request_id):
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    found = _db_get_one_access_request(request_id)
    if not found:
        return jsonify({"error": "not_found"}), 404
    return jsonify(found), 200'''

# P25 STEP 2
s2 = '        r = http.get(f"{BACKEND}/active_requests", headers=bh(), timeout=8)'

# P25 STEP 3
s3 = '            ar = http.get(f"{BACKEND}/active_requests", headers=bh(), timeout=6).json()'

print(f"STEP1 COUNT={srv.count(s1)}")
print(f"STEP2 COUNT={pp.count(s2)}")
print(f"STEP3 COUNT={pp.count(s3)}")
