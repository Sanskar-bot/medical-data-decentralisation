"""
tests/test_emr_api.py - Automated tests for the EMR module endpoints.

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
    Also resets the rate_limits table so tests don't see 429 from prior runs.
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
                    emr_prescriptions, emr_lab_reports,
                    vitals,
                    access_db,
                    access_requests, access_requests_archive,
                    rate_limits
                RESTART IDENTITY CASCADE;
            """)
    except Exception:
        pass


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

    def test_update_profile_merges_metadata_without_overwriting(self, client, jwt_encode):
        uid = "PAT-005"
        client.put(f"/emr/patient/{uid}/profile",
                   headers=_auth_headers(jwt_encode, role="patient", uid=uid),
                   json={"name": "Dina", "age": 31, "address": "12 Main St"})
        r = client.put(f"/emr/patient/{uid}/profile",
                       headers=_auth_headers(jwt_encode, role="patient", uid=uid),
                       json={"height": 170, "weight": 65, "smoking": "Never"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["patient_metadata"]["height"] == 170
        assert data["patient_metadata"]["weight"] == 65
        assert data["patient_metadata"]["smoking"] == "Never"
        assert data["patient_metadata"]["address"] == "12 Main St"

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
    def test_enrich_medication_parses_frequency_and_duration(self):
        from emr.models import _enrich_medication
        med = {"name": "Amoxicillin", "dosage": "500mg", "frequency": "twice daily", "duration": "7 days"}
        result = _enrich_medication(med)
        assert result["dosage_value"] == 500.0
        assert result["frequency_normalized"] == "twice_daily"
        assert result["times_per_day"] == 2.0
        assert result["duration_days"] == 7

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


class TestVitals:
    def _approve_access(self, doctor_id, patient_id):
        from db import db_cursor
        import uuid
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO access_db (id, doctor_id, doctor_email, patient_id, status, responded_at)
                VALUES (%s, %s, %s, %s, 'approved', now())
                ON CONFLICT (doctor_id, patient_id) DO UPDATE SET
                    status='approved',
                    responded_at=now()
            """, (str(uuid.uuid4()), doctor_id, f"{doctor_id.lower()}@test.local", patient_id))

    def test_create_vitals(self, client, jwt_encode):
        self._approve_access("DOC-VITALS", "PAT-VITALS")
        r = client.post("/emr/vitals",
                        headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-VITALS"),
                        json={
                            "patient_id": "PAT-VITALS",
                            "height_cm": 170,
                            "weight_kg": 65,
                            "bp_systolic": 120,
                            "bp_diastolic": 80,
                            "heart_rate_bpm": 72,
                        })
        assert r.status_code == 201
        data = r.get_json()
        assert data["patient_id"] == "PAT-VITALS"
        assert data["recorded_by"] == "DOC-VITALS"
        assert data["heart_rate_bpm"] == 72

    def test_list_patient_vitals_newest_first(self, client, jwt_encode):
        self._approve_access("DOC-VITALS", "PAT-VITALS-LIST")
        headers = _auth_headers(jwt_encode, role="doctor", uid="DOC-VITALS")
        client.post("/emr/vitals", headers=headers, json={
            "patient_id": "PAT-VITALS-LIST",
            "weight_kg": 60,
            "recorded_at": "2026-01-01T09:00:00+00:00",
        })
        client.post("/emr/vitals", headers=headers, json={
            "patient_id": "PAT-VITALS-LIST",
            "weight_kg": 62,
            "recorded_at": "2026-01-02T09:00:00+00:00",
        })
        r = client.get("/emr/vitals/patient/PAT-VITALS-LIST",
                       headers=_auth_headers(jwt_encode, role="patient", uid="PAT-VITALS-LIST"))
        assert r.status_code == 200
        rows = r.get_json()
        assert len(rows) == 2
        assert float(rows[0]["weight_kg"]) == 62.0
        assert float(rows[1]["weight_kg"]) == 60.0

    def test_patient_cannot_create_vitals_route(self, client, jwt_encode):
        r = client.post("/emr/vitals",
                        headers=_auth_headers(jwt_encode, role="patient", uid="PAT-VITALS"),
                        json={"patient_id": "PAT-VITALS", "heart_rate_bpm": 72})
        assert r.status_code == 403

    def test_doctor_without_access_cannot_read_vitals(self, client, jwt_encode):
        self._approve_access("DOC-AUTHORIZED", "PAT-VITALS-PRIVATE")
        client.post("/emr/vitals",
                    headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-AUTHORIZED"),
                    json={"patient_id": "PAT-VITALS-PRIVATE", "heart_rate_bpm": 72})

        r = client.get("/emr/vitals/patient/PAT-VITALS-PRIVATE",
                       headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-NO-ACCESS"))
        assert r.status_code == 403

    def test_doctor_without_access_cannot_create_vitals(self, client, jwt_encode):
        r = client.post("/emr/vitals",
                        headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-NO-ACCESS"),
                        json={"patient_id": "PAT-VITALS-NOACCESS", "heart_rate_bpm": 72})
        assert r.status_code == 403

    def test_profile_vitals_update_keeps_snapshot_and_creates_history(self, client, jwt_encode):
        uid = "PAT-VITALS-PROFILE"
        r = client.put(f"/emr/patient/{uid}/profile",
                       headers=_auth_headers(jwt_encode, role="patient", uid=uid),
                       json={"height": 171, "weight": 66, "blood_pressure": "118/76"})
        assert r.status_code == 201
        data = r.get_json()
        assert data["patient_metadata"]["height"] == 171
        assert data["patient_metadata"]["weight"] == 66
        assert data["patient_metadata"]["blood_pressure"] == "118/76"

        history = client.get(f"/emr/vitals/patient/{uid}",
                             headers=_auth_headers(jwt_encode, role="patient", uid=uid))
        assert history.status_code == 200
        rows = history.get_json()
        assert len(rows) == 1
        assert float(rows[0]["height_cm"]) == 171.0
        assert float(rows[0]["weight_kg"]) == 66.0
        assert rows[0]["bp_systolic"] == 118
        assert rows[0]["bp_diastolic"] == 76
        assert rows[0]["recorded_by"] == "self"


class TestReadAuditLogs:
    def test_patient_reports_read_writes_audit_log(self, client, jwt_encode):
        patient_id = "PAT-AUDIT-REPORT"
        doctor_token = _make_jwt(jwt_encode, role="doctor", uid="DOC-AUDIT-REPORT")
        upload = client.post(
            "/reports/upload",
            headers={"Authorization": f"Bearer {doctor_token}", "Content-Type": "application/json"},
            json={
                "patient_id": patient_id,
                "encrypted_report_blob": {"data": "secret"},
                "encrypted_aes_key": "encrypted-key",
            },
        )
        assert upload.status_code == 201

        r = client.get(f"/reports/patient/{patient_id}",
                       headers=_auth_headers(jwt_encode, role="patient", uid=patient_id))
        assert r.status_code == 200

        from db import db_cursor
        with db_cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action='patient_reports_listed' AND target=%s ORDER BY ts DESC",
                (patient_id,),
            )
            rows = cur.fetchall()
        assert len(rows) >= 1
        assert rows[0]["actor"] == patient_id

    def test_report_read_writes_audit_log(self, client, jwt_encode):
        patient_id = "PAT-AUDIT-REPORT2"
        doctor_token = _make_jwt(jwt_encode, role="doctor", uid="DOC-AUDIT-REPORT2")
        upload = client.post(
            "/reports/upload",
            headers={"Authorization": f"Bearer {doctor_token}", "Content-Type": "application/json"},
            json={
                "patient_id": patient_id,
                "encrypted_report_blob": {"data": "secret"},
                "encrypted_aes_key": "encrypted-key",
            },
        )
        assert upload.status_code == 201
        record_id = upload.get_json()["record_id"]

        r = client.get(f"/reports/{record_id}",
                       headers=_auth_headers(jwt_encode, role="patient", uid=patient_id))
        assert r.status_code == 200

        from db import db_cursor
        with db_cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action='report_viewed' AND target=%s ORDER BY ts DESC",
                (record_id,),
            )
            rows = cur.fetchall()
        assert len(rows) >= 1
        assert rows[0]["actor"] == patient_id

    def test_emr_profile_read_writes_audit_log(self, client, jwt_encode):
        uid = "PAT-AUDIT-PROFILE"
        client.put(
            f"/emr/patient/{uid}/profile",
            headers=_auth_headers(jwt_encode, role="patient", uid=uid),
            json={"name": "Audit Patient", "age": 28},
        )
        assert client.get(f"/emr/patient/{uid}/profile",
                          headers=_auth_headers(jwt_encode, role="doctor")).status_code == 200

        from db import db_cursor
        with db_cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action='emr_profile_read' AND target=%s ORDER BY ts DESC",
                (uid,),
            )
            rows = cur.fetchall()
        assert len(rows) >= 1
        assert rows[0]["actor"] == "test-uid-001"

    def test_emr_doctor_encounters_read_writes_audit_log(self, client, jwt_encode):
        doctor_id = "DOC-AUDIT-ENCOUNTER"
        client.post(
            "/emr/encounters",
            headers=_auth_headers(jwt_encode, role="doctor", uid=doctor_id),
            json={"patient_id": "PAT-AUDIT-ENCOUNTER", "doctor_id": doctor_id},
        )

        r = client.get(
            f"/emr/encounters/doctor/{doctor_id}",
            headers=_auth_headers(jwt_encode, role="doctor", uid=doctor_id),
        )
        assert r.status_code == 200

        from db import db_cursor
        with db_cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action='emr_doctor_encounters_read' AND target=%s ORDER BY ts DESC",
                (doctor_id,),
            )
            rows = cur.fetchall()
        assert len(rows) >= 1
        assert rows[0]["actor"] == doctor_id

    def test_cleanup_archives_access_request_before_delete(self, client, jwt_encode, monkeypatch):
        import server
        from db import db_cursor

        # Prevent the cleanup function from scheduling a background timer during the test.
        class DummyTimer:
            def __init__(self, interval, fn):
                pass
            def start(self):
                pass
        monkeypatch.setattr(server._threading, "Timer", DummyTimer)

        doctor_token = _make_jwt(jwt_encode, role="doctor", uid="DOC-ACCESS-ARCHIVE")
        patient_id = "PAT-ACCESS-ARCHIVE"
        create = client.post(
            "/access/request",
            headers={"Authorization": f"Bearer {doctor_token}", "Content-Type": "application/json"},
            json={
                "profile_code": patient_id,
                "doctor_code": "DOC-ACCESS-ARCHIVE",
                "doctor_public_pem": "pem",
                "encrypted_doctor_profile_b64": "abc",
            },
        )
        assert create.status_code == 201
        request_id = create.get_json()["request_id"]

        # Backdate approved_at and set status to approved so cleanup will archive it.
        with db_cursor() as cur:
            cur.execute(
                "UPDATE access_requests SET status='approved', approved_at = now() - interval '49 hours' WHERE request_id = %s",
                (request_id,)
            )

        server._cleanup_old_requests()

        with db_cursor(commit=False) as cur:
            cur.execute("SELECT * FROM access_requests WHERE request_id = %s", (request_id,))
            assert cur.fetchone() is None
            cur.execute("SELECT * FROM access_requests_archive WHERE request_id = %s", (request_id,))
            row = cur.fetchone()
        assert row is not None
        assert row["profile_code"] == patient_id

    def test_access_history_endpoint_returns_archived_metadata(self, client, jwt_encode, monkeypatch):
        import server
        from db import db_cursor

        class DummyTimer:
            def __init__(self, interval, fn):
                pass
            def start(self):
                pass
        monkeypatch.setattr(server._threading, "Timer", DummyTimer)

        doctor_token = _make_jwt(jwt_encode, role="doctor", uid="DOC-ACCESS-HISTORY")
        patient_id = "PAT-ACCESS-HISTORY"
        create = client.post(
            "/access/request",
            headers={"Authorization": f"Bearer {doctor_token}", "Content-Type": "application/json"},
            json={
                "profile_code": patient_id,
                "doctor_code": "DOC-ACCESS-HISTORY",
                "doctor_public_pem": "pem",
                "encrypted_doctor_profile_b64": "abc",
            },
        )
        assert create.status_code == 201
        request_id = create.get_json()["request_id"]

        with db_cursor() as cur:
            cur.execute(
                "UPDATE access_requests SET status='approved', approved_at = now() - interval '49 hours' WHERE request_id = %s",
                (request_id,)
            )

        server._cleanup_old_requests()

        r = client.get(
            f"/audit/access_history/{patient_id}",
            headers={"Authorization": f"Bearer {doctor_token}"},
        )
        assert r.status_code == 200
        history = r.get_json()
        assert isinstance(history, list)
        assert len(history) >= 1
        assert history[0]["profile_code"] == patient_id
        secret_fields = {
            "doctor_public_pem",
            "encrypted_doctor_profile",
            "wrapped_key",
            "encrypted_kdata",
            "temp_key_expires_at",
            "encrypted_record",
        }
        assert secret_fields.isdisjoint(history[0])

        patient_token = jwt_encode({
            "sub": "patient@example.com",
            "uid": patient_id,
            "role": "patient",
            "name": "Patient User",
            "profile_code": patient_id,
            "exp": time.time() + 3600,
        })
        r2 = client.get(
            f"/audit/access_history/{patient_id}",
            headers={"Authorization": f"Bearer {patient_token}"},
        )
        assert r2.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
#   ADMIN ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAccessRequests:
    def test_duplicate_pending_access_request_returns_existing(self, client, jwt_encode):
        headers = _auth_headers(jwt_encode, role="doctor", uid="DOC-DUP-PENDING")
        first = client.post("/access/request", headers=headers, json={"patient_id": "PAT-DUP-PENDING"})
        assert first.status_code == 201

        second = client.post("/access/request", headers=headers, json={"patient_id": "PAT-DUP-PENDING"})
        assert second.status_code == 200
        data = second.get_json()
        assert data["message"] == "already_pending"
        assert data["id"] == first.get_json()["id"]

    def test_duplicate_approved_access_request_is_not_500(self, client, jwt_encode):
        headers = _auth_headers(jwt_encode, role="doctor", uid="DOC-DUP-APPROVED")
        first = client.post("/access/request", headers=headers, json={"patient_id": "PAT-DUP-APPROVED"})
        assert first.status_code == 201
        request_id = first.get_json()["id"]

        from db import db_cursor
        with db_cursor() as cur:
            cur.execute(
                "UPDATE access_db SET status='approved', responded_at=now() WHERE id=%s",
                (request_id,),
            )

        second = client.post("/access/request", headers=headers, json={"patient_id": "PAT-DUP-APPROVED"})
        assert second.status_code == 200
        data = second.get_json()
        assert data["message"] == "already_approved"
        assert data["id"] == request_id

    def test_denied_access_request_can_be_reopened(self, client, jwt_encode):
        headers = _auth_headers(jwt_encode, role="doctor", uid="DOC-DUP-DENIED")
        first = client.post("/access/request", headers=headers, json={"patient_id": "PAT-DUP-DENIED"})
        assert first.status_code == 201
        request_id = first.get_json()["id"]

        from db import db_cursor
        with db_cursor() as cur:
            cur.execute(
                "UPDATE access_db SET status='denied', responded_at=now() WHERE id=%s",
                (request_id,),
            )

        second = client.post("/access/request", headers=headers, json={"patient_id": "PAT-DUP-DENIED"})
        assert second.status_code == 200
        data = second.get_json()
        assert data["message"] == "request_reopened"
        assert data["id"] == request_id
        assert data["status"] == "pending"


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


# ═══════════════════════════════════════════════════════════════════════════════
#   UNIT TESTS - _norm_allergy_list
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormAllergyList:
    """Pure unit tests - no DB or HTTP needed."""

    def setup_method(self):
        from emr.models import _norm_allergy_list
        self.norm = _norm_allergy_list

    def test_list_input_passthrough(self):
        assert self.norm(["Penicillin", "Latex"]) == ["Penicillin", "Latex"]

    def test_comma_string_splits_correctly(self):
        result = self.norm("Penicillin, Sulfa drugs")
        assert result == ["Penicillin", "Sulfa drugs"]

    def test_extra_whitespace_stripped(self):
        result = self.norm("  Ibuprofen ,  Aspirin  ")
        assert result == ["Ibuprofen", "Aspirin"]

    def test_empty_string_returns_empty(self):
        assert self.norm("") == []

    def test_none_returns_empty(self):
        assert self.norm(None) == []

    def test_empty_list_returns_empty(self):
        assert self.norm([]) == []

    def test_case_insensitive_dedupe_preserves_first_casing(self):
        result = self.norm("Penicillin, penicillin, PENICILLIN")
        assert result == ["Penicillin"]

    def test_mixed_list_and_extra_commas(self):
        # Leading/trailing commas produce empty strings that should be dropped
        result = self.norm(",Dust,,Pollen,")
        assert result == ["Dust", "Pollen"]

    def test_list_with_duplicates_deduped(self):
        result = self.norm(["Latex", "latex", "LATEX"])
        assert result == ["Latex"]


# ═══════════════════════════════════════════════════════════════════════════════
#   UNIT TESTS - check_allergy_conflicts
# ═══════════════════════════════════════════════════════════════════════════════

class TestVitalsModel:
    """Pure unit tests - no DB or HTTP needed."""

    def setup_method(self):
        from emr.models import validate_vitals, new_vitals
        self.validate = validate_vitals
        self.new = new_vitals

    def test_required_fields(self):
        errors = self.validate({})
        assert "patient_id" in errors
        assert "recorded_by" in errors

    def test_valid_vitals(self):
        errors = self.validate({
            "patient_id": "PAT-MODEL",
            "recorded_by": "DOC-MODEL",
            "height_cm": 170,
            "weight_kg": 65,
            "heart_rate_bpm": 72,
            "blood_sugar_mgdl": 95,
            "oxygen_saturation_pct": 98,
        })
        assert errors == []

    def test_negative_values_rejected(self):
        errors = self.validate({
            "patient_id": "PAT-MODEL",
            "recorded_by": "DOC-MODEL",
            "height_cm": -1,
            "weight_kg": -1,
            "heart_rate_bpm": -1,
            "blood_sugar_mgdl": -1,
            "oxygen_saturation_pct": -1,
        })
        assert "height_cm cannot be negative" in errors
        assert "weight_kg cannot be negative" in errors
        assert "heart_rate_bpm cannot be negative" in errors
        assert "blood_sugar_mgdl cannot be negative" in errors
        assert "oxygen_saturation_pct cannot be negative" in errors

    def test_absurd_heart_rate_rejected(self):
        errors = self.validate({
            "patient_id": "PAT-MODEL",
            "recorded_by": "DOC-MODEL",
            "heart_rate_bpm": 401,
        })
        assert "heart_rate_bpm is too high" in errors

    def test_new_vitals_normalises_fields(self):
        result = self.new({
            "patient_id": "PAT-MODEL",
            "recorded_by": "DOC-MODEL",
            "height_cm": "170",
            "weight_kg": "65.5",
            "bp_systolic": "120",
            "bp_diastolic": "80",
            "heart_rate_bpm": "72",
            "blood_sugar_mgdl": "95.5",
            "oxygen_saturation_pct": "98",
            "notes": " morning ",
        })
        assert result["patient_id"] == "PAT-MODEL"
        assert result["recorded_by"] == "DOC-MODEL"
        assert result["height_cm"] == 170.0
        assert result["weight_kg"] == 65.5
        assert result["bp_systolic"] == 120
        assert result["bp_diastolic"] == 80
        assert result["heart_rate_bpm"] == 72
        assert result["blood_sugar_mgdl"] == 95.5
        assert result["oxygen_saturation_pct"] == 98.0
        assert result["notes"] == "morning"
        assert "id" in result


class TestCheckAllergyConflicts:
    """Pure unit tests - no DB or HTTP needed."""

    def setup_method(self):
        from emr.models import check_allergy_conflicts
        self.check = check_allergy_conflicts

    # ── Empty inputs ──────────────────────────────────────────────────────────

    def test_empty_allergies_returns_no_conflicts(self):
        meds = [{"name": "Amoxicillin"}]
        assert self.check([], meds) == []

    def test_empty_medications_returns_no_conflicts(self):
        assert self.check(["Penicillin"], []) == []

    def test_both_empty_returns_empty(self):
        assert self.check([], []) == []

    # ── Direct / high severity ────────────────────────────────────────────────

    def test_exact_match_high_severity(self):
        """Prescribing 'Penicillin' when patient is allergic to Penicillin."""
        conflicts = self.check(["Penicillin"], [{"name": "Penicillin V"}])
        assert len(conflicts) == 1
        assert conflicts[0]["severity"] == "high"
        assert conflicts[0]["medication"] == "Penicillin V"
        assert conflicts[0]["allergy"] == "Penicillin"

    def test_case_insensitive_direct_match(self):
        """Case should not matter for matching."""
        conflicts = self.check(["IBUPROFEN"], [{"name": "ibuprofen"}])
        assert len(conflicts) == 1
        assert conflicts[0]["severity"] == "high"

    # ── Cross-reactivity / moderate severity ──────────────────────────────────

    def test_cross_reactive_amoxicillin_vs_penicillin_allergy(self):
        """Amoxicillin is cross-reactive with penicillin allergy - canonical test."""
        conflicts = self.check(["Penicillin"], [{"name": "Amoxicillin"}])
        assert len(conflicts) == 1
        assert conflicts[0]["severity"] == "moderate"
        assert conflicts[0]["medication"] == "Amoxicillin"
        assert conflicts[0]["allergy"] == "Penicillin"

    def test_cross_reactive_bactrim_vs_sulfa_allergy(self):
        conflicts = self.check(["sulfa"], [{"name": "Bactrim"}])
        assert any(c["severity"] in ("high", "moderate") for c in conflicts)

    def test_cross_reactive_ibuprofen_vs_aspirin_allergy(self):
        conflicts = self.check(["aspirin"], [{"name": "Ibuprofen"}])
        assert len(conflicts) == 1
        assert conflicts[0]["medication"] == "Ibuprofen"

    # ── No conflict ───────────────────────────────────────────────────────────

    def test_no_conflict_safe_medication(self):
        """Cetirizine has no known cross-reactivity with Penicillin."""
        conflicts = self.check(["Penicillin"], [{"name": "Cetirizine"}])
        assert conflicts == []

    def test_no_conflict_unrelated_allergy(self):
        conflicts = self.check(["Dust mites"], [{"name": "Paracetamol"}])
        assert conflicts == []

    # ── Multiple medications ──────────────────────────────────────────────────

    def test_multiple_meds_one_conflict(self):
        meds = [{"name": "Paracetamol"}, {"name": "Amoxicillin"}]
        conflicts = self.check(["Penicillin"], meds)
        assert len(conflicts) == 1
        assert conflicts[0]["medication"] == "Amoxicillin"

    def test_multiple_meds_multiple_conflicts(self):
        meds = [{"name": "Amoxicillin"}, {"name": "Ampicillin"}]
        conflicts = self.check(["Penicillin"], meds)
        med_names = {c["medication"] for c in conflicts}
        assert "Amoxicillin" in med_names
        assert "Ampicillin" in med_names

    # ── Deduplication ─────────────────────────────────────────────────────────

    def test_duplicate_conflict_suppressed(self):
        """Same (medication, allergy) pair should appear only once."""
        conflicts = self.check(
            ["Penicillin", "Penicillin"],  # duplicate allergy entries
            [{"name": "Amoxicillin"}],
        )
        assert len(conflicts) == 1

    # ── Safety: must not raise ────────────────────────────────────────────────

    def test_med_without_name_key_does_not_crash(self):
        """Medications without a 'name' key must be silently skipped."""
        conflicts = self.check(["Penicillin"], [{"dosage": "500mg"}])
        assert conflicts == []

    def test_allergy_none_in_list_does_not_crash(self):
        """None values in allergies list must be silently skipped."""
        conflicts = self.check([None, "Penicillin"], [{"name": "Amoxicillin"}])
        # Should still detect the Penicillin conflict
        assert any(c["allergy"] == "Penicillin" for c in conflicts)


# ═══════════════════════════════════════════════════════════════════════════════
#   INTEGRATION TESTS - Allergy conflict prescription flow
# ═══════════════════════════════════════════════════════════════════════════════

class TestAllergyConflictPrescriptions:

    def _create_patient_profile_with_penicillin_allergy(self, client, jwt_encode, uid):
        """Helper: create an EMR profile with a penicillin allergy."""
        r = client.put(
            f"/emr/patient/{uid}/profile",
            headers=_auth_headers(jwt_encode, role="patient", uid=uid),
            json={
                "name": "Allergy Test Patient",
                "age": 30,
                "allergies": ["Penicillin"],
            },
        )
        assert r.status_code in (200, 201), f"Profile create failed: {r.get_json()}"
        return r.get_json()

    # ── 409 on allergy conflict ───────────────────────────────────────────────

    def test_amoxicillin_vs_penicillin_allergy_returns_409(self, client, jwt_encode):
        """Prescribing Amoxicillin to a patient with Penicillin allergy - 409."""
        uid = "PAT-ALLERGY-001"
        self._create_patient_profile_with_penicillin_allergy(client, jwt_encode, uid)

        r = client.post(
            "/emr/prescriptions",
            headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-ALLERGY-001"),
            json={
                "patient_id":  uid,
                "diagnosis":   "Throat infection",
                "medications": [{"name": "Amoxicillin", "dosage": "500mg"}],
            },
        )
        assert r.status_code == 409
        data = r.get_json()
        assert data["error"] == "allergy_conflict"
        assert isinstance(data["conflicts"], list)
        assert len(data["conflicts"]) >= 1
        assert data["conflicts"][0]["medication"] == "Amoxicillin"
        assert data["conflicts"][0]["allergy"] == "Penicillin"

    def test_conflict_prescription_not_saved_on_409(self, client, jwt_encode):
        """When 409 is returned the prescription must NOT be written to the DB."""
        from emr import store
        uid = "PAT-ALLERGY-002"
        self._create_patient_profile_with_penicillin_allergy(client, jwt_encode, uid)

        client.post(
            "/emr/prescriptions",
            headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-ALLERGY-002"),
            json={
                "patient_id":  uid,
                "diagnosis":   "Skin infection",
                "medications": [{"name": "Amoxicillin"}],
            },
        )

        # Verify nothing was written
        saved = store.prescriptions_for_patient(uid)
        assert saved == [], f"Expected no prescriptions, found: {saved}"

    # ── 201 with override ─────────────────────────────────────────────────────

    def test_override_flag_saves_prescription(self, client, jwt_encode):
        """Same conflict + override_allergy_check: true - 201, prescription saved."""
        uid = "PAT-ALLERGY-003"
        self._create_patient_profile_with_penicillin_allergy(client, jwt_encode, uid)

        r = client.post(
            "/emr/prescriptions",
            headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-ALLERGY-003"),
            json={
                "patient_id":           uid,
                "diagnosis":            "Throat infection",
                "medications":          [{"name": "Amoxicillin", "dosage": "500mg"}],
                "override_allergy_check": True,
            },
        )
        assert r.status_code == 201
        data = r.get_json()
        assert data["patient_id"] == uid

    def test_override_prescription_actually_stored(self, client, jwt_encode):
        """After override 201 the prescription must be retrievable."""
        from emr import store
        uid = "PAT-ALLERGY-004"
        self._create_patient_profile_with_penicillin_allergy(client, jwt_encode, uid)

        client.post(
            "/emr/prescriptions",
            headers=_auth_headers(jwt_encode, role="doctor", uid="DOC-ALLERGY-004"),
            json={
                "patient_id":           uid,
                "diagnosis":            "Ear infection",
                "medications":          [{"name": "Amoxicillin"}],
                "override_allergy_check": True,
            },
        )
        saved = store.prescriptions_for_patient(uid)
        assert len(saved) == 1
        assert saved[0]["medications"][0]["name"] == "Amoxicillin"

    def test_override_produces_audit_log_entry(self, client, jwt_encode):
        """Override must write a prescription_allergy_override audit entry."""
        uid = "PAT-ALLERGY-005"
        doc_email = "overriding.doctor@test.com"
        self._create_patient_profile_with_penicillin_allergy(client, jwt_encode, uid)

        token = jwt_encode({
            "sub": doc_email,
            "uid": "DOC-ALLERGY-005",
            "role": "doctor",
            "exp": time.time() + 3600,
        })
        client.post(
            "/emr/prescriptions",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "patient_id":           uid,
                "diagnosis":            "Test override audit",
                "medications":          [{"name": "Amoxicillin"}],
                "override_allergy_check": True,
            },
        )

        # Check the audit_log table for the override entry
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
        from db import db_cursor
        with db_cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action='prescription_allergy_override' AND target=%s",
                (uid,),
            )
            rows = cur.fetchall()
        assert len(rows) >= 1, "Expected audit_log entry for prescription_allergy_override"
        assert "Amoxicillin" in rows[0]["detail"]

    # ── No allergies recorded ─────────────────────────────────────────────────

    def test_no_allergies_recorded_prescription_succeeds(self, client, jwt_encode):
        """Patient has an EMR profile but no allergies - prescription succeeds."""
        uid = "PAT-ALLERGY-006"
        client.put(
            f"/emr/patient/{uid}/profile",
            headers=_auth_headers(jwt_encode, role="patient", uid=uid),
            json={"name": "No Allergy Patient", "allergies": []},
        )

        r = client.post(
            "/emr/prescriptions",
            headers=_auth_headers(jwt_encode, role="doctor"),
            json={
                "patient_id":  uid,
                "diagnosis":   "Fever",
                "medications": [{"name": "Amoxicillin", "dosage": "500mg"}],
            },
        )
        assert r.status_code == 201

    # ── No EMR profile at all ─────────────────────────────────────────────────

    def test_no_emr_profile_prescription_succeeds(self, client, jwt_encode):
        """Patient with no EMR profile - no conflict possible - prescription saved."""
        uid = "PAT-ALLERGY-007"  # No profile created for this patient

        r = client.post(
            "/emr/prescriptions",
            headers=_auth_headers(jwt_encode, role="doctor"),
            json={
                "patient_id":  uid,
                "diagnosis":   "Bacterial infection",
                "medications": [{"name": "Amoxicillin", "dosage": "500mg"}],
            },
        )
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.get_json()}"

    # ── Allergy string normalisation round-trip via profile endpoint ──────────

    def test_allergy_comma_string_saved_as_list(self, client, jwt_encode):
        """
        If the browser sends allergies as a comma-separated string (the known
        bug in emr.html), the API should still persist it as a proper list.
        """
        # Use a unique UID unrelated to any other test to avoid rate-limiter 429
        uid = "PAT-NORM-ROUNDTRIP"
        # Simulate the broken browser payload: allergies as a string
        r = client.put(
            f"/emr/patient/{uid}/profile",
            headers=_auth_headers(jwt_encode, role="patient", uid=uid),
            json={"allergies": "Penicillin, Latex"},
        )
        assert r.status_code in (200, 201)
        data = r.get_json()
        # The stored value must be a list, not a string
        assert isinstance(data["allergies"], list), (
            f"Expected list, got {type(data['allergies'])}: {data['allergies']}"
        )
        assert "Penicillin" in data["allergies"]
        assert "Latex" in data["allergies"]
