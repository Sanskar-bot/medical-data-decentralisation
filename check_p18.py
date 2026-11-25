content = open('server/emr/routes.py').read()

# STEP 1: _doctor_has_patient_access function start
s1 = '''def _doctor_has_patient_access(payload: dict, patient_id: str, raw_patient_id: str | None = None) -> bool:
    if payload.get("role") == "admin":
        return True
    if payload.get("role") != "doctor":
        return False'''

# STEP 2: get_patient_profile
s2 = '''    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    # Patient can only see own profile; doctors and admins can see any
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403'''

# STEP 3: upsert_patient_profile
s3 = '''    """Create or update a patient\'s extended EMR profile."""
    p = request.jwt_payload
    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403'''

# STEP 4: test_emr_api.py
test_content = open('tests/test_emr_api.py').read()
s4 = '''# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _init_dirs():'''

for i, (s, src) in enumerate([(s1, content), (s2, content), (s3, content), (s4, test_content)], 1):
    print(f"STEP{i} COUNT={src.count(s)}")
