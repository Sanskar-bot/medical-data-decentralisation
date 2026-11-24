"""[C2][X3][X4] EMR create routes need a grant and take the doctor from the token."""
import pytest

MED = [{"name": "Paracetamol", "dosage": "500mg", "frequency": "BD", "duration": "3d"}]


@pytest.fixture
def w(app, clean_db, make_user, grant_access):
    owner = make_user("patient")
    granted, stranger, admin = make_user("doctor"), make_user("doctor"), make_user("admin")
    grant_access(granted, owner)
    return {"owner": owner, "granted": granted, "stranger": stranger, "admin": admin}


def _posts(w, doctor_id_claim):
    pid = w["owner"]["id"]
    return [
        ("/emr/prescriptions", {"patient_id": pid, "diagnosis": "x", "medications": MED,
                                "doctor_id": doctor_id_claim}),
        ("/emr/lab-reports", {"patient_id": pid, "report_type": "CBC", "results": {},
                              "doctor_id": doctor_id_claim}),
        ("/emr/conditions", {"patient_id": pid, "description": "Asthma",
                             "recorded_by": doctor_id_claim}),
        ("/emr/encounters", {"patient_id": pid, "doctor_id": doctor_id_claim}),
        ("/emr/vitals", {"patient_id": pid, "heart_rate_bpm": 70, "recorded_by": doctor_id_claim}),
        ("/emr/appointments", {"patient_id": pid, "date_time": "2030-01-01T10:00:00",
                               "doctor_id": doctor_id_claim}),
    ]


@pytest.mark.parametrize("who", ["stranger", "admin"])
def test_writes_without_grant_are_refused(client, w, make_token, who):
    for url, body in _posts(w, "SOMEONE-ELSE"):
        r = client.post(url, headers=make_token(w[who]), json=body)
        assert r.status_code == 403, (who, url, r.status_code, r.get_json())


def test_granted_doctor_cannot_forge_author(client, w, make_token, db):
    for url, body in _posts(w, "FORGED-DOCTOR"):
        r = client.post(url, headers=make_token(w["granted"]), json=body)
        assert r.status_code == 201, (url, r.status_code, r.get_json())
        data = r.get_json()
        author = data.get("doctor_id") or data.get("recorded_by")
        assert author != "FORGED-DOCTOR", url
