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
                    rate_limits
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


# ═══════════════════════════════════════════════════════════════════════════════
#   UNIT TESTS — _norm_allergy_list
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormAllergyList:
    """Pure unit tests — no DB or HTTP needed."""

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
#   UNIT TESTS — check_allergy_conflicts
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckAllergyConflicts:
    """Pure unit tests — no DB or HTTP needed."""

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
        """Amoxicillin is cross-reactive with penicillin allergy — canonical test."""
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
#   INTEGRATION TESTS — Allergy conflict prescription flow
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
        """Prescribing Amoxicillin to a patient with Penicillin allergy → 409."""
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
        """Same conflict + override_allergy_check: true → 201, prescription saved."""
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
        """Patient has an EMR profile but no allergies → prescription succeeds."""
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
        """Patient with no EMR profile → no conflict possible → prescription saved."""
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
