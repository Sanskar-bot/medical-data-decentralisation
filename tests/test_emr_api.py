"""
tests/test_emr_api.py — Automated tests for the EMR module endpoints.

Uses Flask's test_client so no running server is needed.
Run with:  python -m pytest tests/test_emr_api.py -v
"""

import os
import sys
import json
import time
import pytest

# ── Ensure the project root is importable ─────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
# server/ must be importable too (for `from emr.routes import ...`)
SERVER_DIR = os.path.join(ROOT, "server")
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _init_dirs():
    """Ensure the server data directories exist before importing."""
    os.makedirs(os.path.join(ROOT, "server", "Patients"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "server", "Doctors"), exist_ok=True)
    # Ensure api_key.txt exists (needed by JWT)
    api_key_path = os.path.join(ROOT, "server", "api_key.txt")
    if not os.path.exists(api_key_path):
        import secrets
        with open(api_key_path, "w") as f:
            f.write(secrets.token_hex(32))


@pytest.fixture(scope="module")
def app():
    """Import and configure the Flask app for testing."""
    # Import after _init_dirs ensures api_key.txt exists
    sys.path.insert(0, SERVER_DIR)
    from server import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["SECRET_KEY"] = "test-secret"
    return flask_app


@pytest.fixture(scope="module")
def client(app):
    return app.test_client()


@pytest.fixture(scope="module")
def jwt_encode():
    """Get the server's _jwt_encode function."""
    from server import _jwt_encode
    return _jwt_encode


def _make_jwt(jwt_encode, role="doctor", uid="test-uid-001", email="test@medvault.dev"):
    """Create a valid JWT using the server's own _jwt_encode helper."""
    return jwt_encode({
        "sub": email,
        "uid": uid,
        "role": role,
        "name": "Test User",
        "exp": time.time() + 3600,  # 1 hour
    })


def _auth_headers(jwt_encode, role="doctor", uid="test-uid-001"):
    """Return Authorization header dict."""
    token = _make_jwt(jwt_encode, role=role, uid=uid)
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ── Cleanup emr_data between runs ────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_emr_data():
    """
    Clear EMR DB tables before each test to ensure test isolation.
    Previously deleted emr_data/*.json files; now truncates PostgreSQL tables.
    """
    import sys, os
    sys.path.insert(0, os.path.join(ROOT, "server"))
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, ".env"))
    from db import init_db, db_cursor
    try:
        init_db()
        with db_cursor() as cur:
            cur.execute("""
                TRUNCATE TABLE
                    emr_profiles, emr_appointments,
                    emr_prescriptions, emr_lab_reports
                RESTART IDENTITY CASCADE
            """)
    except Exception as e:
        print(f"[test cleanup] DB truncate failed: {e}")
    yield


# ═══════════════════════════════════════════════════════════════════════════════
#   PATIENT PROFILE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPatientProfile:
    def test_get_profile_not_found(self, client, jwt_encode):
        r = client.get("/emr/patient/NONEXISTENT/profile",
                       headers=_auth_headers(jwt_encode, role="patient", uid="NONEXISTENT"))
        assert r.status_code == 404

    def test_create_profile(self, client, jwt_encode):
        uid = "PAT-001"
        r = client.put(
            f"/emr/patient/{uid}/profile",
            headers=_auth_headers(jwt_encode, role="patient", uid=uid),
            json={
                "name": "Alice Test",
                "age": 30,
                "gender": "female",
                "blood_group": "A+",
                "medical_history": ["Asthma"],
                "allergies": ["Peanuts"],
            },
        )
        assert r.status_code == 201
        data = r.get_json()
        assert data["patient_id"] == uid
        assert data["blood_group"] == "A+"
        assert data["allergies"] == ["Peanuts"]

    def test_update_profile(self, client, jwt_encode):
        uid = "PAT-002"
        # Create
        client.put(f"/emr/patient/{uid}/profile",
                   headers=_auth_headers(jwt_encode, role="patient", uid=uid),
                   json={"name": "Bob", "age": 25})
        # Update
        r = client.put(f"/emr/patient/{uid}/profile",
                       headers=_auth_headers(jwt_encode, role="patient", uid=uid),
                       json={"age": 26, "allergies": ["Dust"]})
        assert r.status_code == 200
        data = r.get_json()
        assert data["age"] == 26
        assert data["allergies"] == ["Dust"]

    def test_patient_cannot_see_other_profile(self, client, jwt_encode):
        r = client.get("/emr/patient/OTHER/profile",
                       headers=_auth_headers(jwt_encode, role="patient", uid="ME"))
        assert r.status_code == 403

    def test_doctor_can_see_any_profile(self, client, jwt_encode):
        uid = "PAT-003"
        client.put(f"/emr/patient/{uid}/profile",
                   headers=_auth_headers(jwt_encode, role="doctor"),
                   json={"name": "Carol", "age": 40})
        r = client.get(f"/emr/patient/{uid}/profile",
                       headers=_auth_headers(jwt_encode, role="doctor"))
        assert r.status_code == 200

    def test_validation_bad_blood_group(self, client, jwt_encode):
        uid = "PAT-004"
        r = client.put(f"/emr/patient/{uid}/profile",
                       headers=_auth_headers(jwt_encode, role="patient", uid=uid),
                       json={"blood_group": "Z+"})
        assert r.status_code == 400
        assert "blood_group" in str(r.get_json())


# ═══════════════════════════════════════════════════════════════════════════════
#   APPOINTMENT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAppointments:
    def test_create_appointment(self, client, jwt_encode):
        r = client.post("/emr/appointments",
                        headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-001"),
                        json={
                            "patient_id": "PAT-001",
                            "doctor_id": "DOC-001",
                            "date_time": "2026-05-01T10:00:00+00:00",
                            "reason": "Annual checkup",
                        })
        assert r.status_code == 201
        data = r.get_json()
        assert data["status"] == "scheduled"
        assert "id" in data

    def test_patient_cannot_create_appointment(self, client, jwt_encode):
        r = client.post("/emr/appointments",
                        headers=_auth_headers(jwt_encode, role="patient", uid="PAT-001"),
                        json={
                            "patient_id": "PAT-001",
                            "doctor_id": "DOC-001",
                            "date_time": "2026-05-01T10:00:00+00:00",
                        })
        assert r.status_code == 403

    def test_list_patient_appointments(self, client, jwt_encode):
        # Create an appointment first
        client.post("/emr/appointments",
                    headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-001"),
                    json={
                        "patient_id": "PAT-010",
                        "date_time": "2026-06-01T09:00:00+00:00",
                        "reason": "Follow-up",
                    })
        r = client.get("/emr/appointments/patient/PAT-010",
                       headers=_auth_headers(jwt_encode, role="patient", uid="PAT-010"))
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_update_appointment_status(self, client, jwt_encode):
        # Create
        cr = client.post("/emr/appointments",
                         headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-002"),
                         json={
                             "patient_id": "PAT-020",
                             "date_time": "2026-07-01T14:00:00+00:00",
                         })
        appt_id = cr.get_json()["id"]
        # Update
        r = client.put(f"/emr/appointments/{appt_id}",
                       headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-002"),
                       json={"status": "completed"})
        assert r.status_code == 200
        assert r.get_json()["status"] == "completed"

    def test_delete_appointment(self, client, jwt_encode):
        cr = client.post("/emr/appointments",
                         headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-003"),
                         json={
                             "patient_id": "PAT-030",
                             "date_time": "2026-08-01T08:00:00+00:00",
                         })
        appt_id = cr.get_json()["id"]
        r = client.delete(f"/emr/appointments/{appt_id}",
                          headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-003"))
        assert r.status_code == 200

    def test_validation_missing_fields(self, client, jwt_encode):
        r = client.post("/emr/appointments",
                        headers=_auth_headers(jwt_encode, role="doctor"),
                        json={"patient_id": "PAT-001"})  # no date_time
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
#   PRESCRIPTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPrescriptions:
    def test_create_prescription(self, client, jwt_encode):
        r = client.post("/emr/prescriptions",
                        headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-001"),
                        json={
                            "patient_id": "PAT-001",
                            "diagnosis": "Seasonal allergy",
                            "medications": [
                                {"name": "Cetirizine", "dosage": "10mg", "frequency": "once daily", "duration": "14 days"},
                                {"name": "Fluticasone", "dosage": "50mcg", "frequency": "twice daily", "duration": "14 days"},
                            ],
                        })
        assert r.status_code == 201
        data = r.get_json()
        assert len(data["medications"]) == 2
        assert data["medications"][0]["name"] == "Cetirizine"

    def test_list_patient_prescriptions(self, client, jwt_encode):
        # seed
        client.post("/emr/prescriptions",
                    headers=_auth_headers(jwt_encode, role="doctor"),
                    json={
                        "patient_id": "PAT-RX",
                        "medications": [{"name": "Paracetamol", "dosage": "500mg"}],
                    })
        r = client.get("/emr/prescriptions/patient/PAT-RX",
                       headers=_auth_headers(jwt_encode, role="patient", uid="PAT-RX"))
        assert r.status_code == 200
        rxs = r.get_json()
        assert len(rxs) >= 1

    def test_get_single_prescription(self, client, jwt_encode):
        cr = client.post("/emr/prescriptions",
                         headers=_auth_headers(jwt_encode, role="doctor"),
                         json={
                             "patient_id": "PAT-RXSINGLE",
                             "medications": [{"name": "Ibuprofen"}],
                         })
        rx_id = cr.get_json()["id"]
        r = client.get(f"/emr/prescriptions/{rx_id}",
                       headers=_auth_headers(jwt_encode, role="patient", uid="PAT-RXSINGLE"))
        assert r.status_code == 200
        assert r.get_json()["id"] == rx_id

    def test_patient_cannot_create_prescription(self, client, jwt_encode):
        r = client.post("/emr/prescriptions",
                        headers=_auth_headers(jwt_encode, role="patient"),
                        json={
                            "patient_id": "PAT-001",
                            "medications": [{"name": "X"}],
                        })
        assert r.status_code == 403

    def test_validation_empty_medications(self, client, jwt_encode):
        r = client.post("/emr/prescriptions",
                        headers=_auth_headers(jwt_encode, role="doctor"),
                        json={"patient_id": "PAT-001", "medications": []})
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
#   LAB REPORT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestLabReports:
    def test_create_lab_report(self, client, jwt_encode):
        r = client.post("/emr/lab-reports",
                        headers=_auth_headers(jwt_encode, role="doctor"),
                        json={
                            "patient_id": "PAT-LAB1",
                            "report_type": "Blood Panel",
                            "results": {"hemoglobin": "14.5 g/dL", "WBC": "7000/uL"},
                        })
        assert r.status_code == 201
        data = r.get_json()
        assert data["report_type"] == "Blood Panel"

    def test_list_patient_lab_reports(self, client, jwt_encode):
        client.post("/emr/lab-reports",
                    headers=_auth_headers(jwt_encode, role="doctor"),
                    json={"patient_id": "PAT-LABL", "report_type": "Urinalysis"})
        r = client.get("/emr/lab-reports/patient/PAT-LABL",
                       headers=_auth_headers(jwt_encode, role="patient", uid="PAT-LABL"))
        assert r.status_code == 200
        assert len(r.get_json()) >= 1

    def test_get_single_lab_report(self, client, jwt_encode):
        cr = client.post("/emr/lab-reports",
                         headers=_auth_headers(jwt_encode, role="doctor"),
                         json={"patient_id": "PAT-LABS", "report_type": "X-Ray"})
        rid = cr.get_json()["id"]
        r = client.get(f"/emr/lab-reports/{rid}",
                       headers=_auth_headers(jwt_encode, role="patient", uid="PAT-LABS"))
        assert r.status_code == 200

    def test_patient_cannot_create_lab_report(self, client, jwt_encode):
        r = client.post("/emr/lab-reports",
                        headers=_auth_headers(jwt_encode, role="patient"),
                        json={"patient_id": "PAT-001", "report_type": "ECG"})
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
#   ADMIN ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdmin:
    def test_non_admin_cannot_access_users(self, client, jwt_encode):
        r = client.get("/emr/admin/users",
                       headers=_auth_headers(jwt_encode, role="doctor"))
        assert r.status_code == 403

    def test_non_admin_cannot_access_stats(self, client, jwt_encode):
        r = client.get("/emr/admin/stats",
                       headers=_auth_headers(jwt_encode, role="patient"))
        assert r.status_code == 403

    def test_admin_can_get_stats(self, client, jwt_encode):
        r = client.get("/emr/admin/stats",
                       headers=_auth_headers(jwt_encode, role="admin"))
        assert r.status_code == 200
        data = r.get_json()
        assert "total_users" in data
        assert "total_appointments" in data

    def test_admin_can_list_users(self, client, jwt_encode):
        r = client.get("/emr/admin/users",
                       headers=_auth_headers(jwt_encode, role="admin"))
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)
