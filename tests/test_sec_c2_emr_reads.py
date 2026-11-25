"""[C2][X2] EMR prescriptions and lab reports: deny by default."""
import uuid

import pytest


@pytest.fixture
def world(app, clean_db, db, make_user, grant_access):
    owner, other = make_user("patient"), make_user("patient")
    granted, stranger, admin = make_user("doctor"), make_user("doctor"), make_user("admin")
    grant_access(granted, owner)
    rx, lab = str(uuid.uuid4()), str(uuid.uuid4())
    with db() as cur:
        cur.execute("INSERT INTO emr_profiles (patient_id, name) VALUES (%s, 'Owner')", (owner["id"],))
        cur.execute("INSERT INTO emr_prescriptions (id, patient_id, doctor_id, medications) "
                    "VALUES (%s, %s, %s, '[]')", (rx, owner["id"], granted["doctor_code"]))
        cur.execute("INSERT INTO emr_lab_reports (id, patient_id, doctor_id, report_type) "
                    "VALUES (%s, %s, %s, 'CBC')", (lab, owner["id"], granted["doctor_code"]))
    return {"owner": owner, "other": other, "granted": granted, "stranger": stranger,
            "admin": admin, "rx": rx, "lab": lab}


def _urls(w):
    pid = w["owner"]["id"]
    return [f"/emr/prescriptions/patient/{pid}", f"/emr/prescriptions/{w['rx']}",
            f"/emr/lab-reports/patient/{pid}", f"/emr/lab-reports/{w['lab']}"]


@pytest.mark.parametrize("who", ["stranger", "admin", "other"])
def test_denied(client, world, make_token, who):
    for url in _urls(world):
        r = client.get(url, headers=make_token(world[who]))
        assert r.status_code == 403, (who, url, r.status_code)


@pytest.mark.parametrize("who", ["owner", "granted"])
def test_allowed(client, world, make_token, who):
    for url in _urls(world):
        r = client.get(url, headers=make_token(world[who]))
        assert r.status_code == 200, (who, url, r.status_code)


def test_authored_prescription_and_lab_still_require_patient_grant(
    client, clean_db, db, make_user, make_token
):
    """Authorship alone grants no patient-wide or record-read access."""
    owner, author = make_user("patient"), make_user("doctor")
    rx_id, lab_id = str(uuid.uuid4()), str(uuid.uuid4())
    with db() as cur:
        cur.execute(
            "INSERT INTO emr_prescriptions (id, patient_id, doctor_id, medications) "
            "VALUES (%s, %s, %s, '[]')",
            (rx_id, owner["id"], author["doctor_code"]),
        )
        cur.execute(
            "INSERT INTO emr_lab_reports (id, patient_id, doctor_id, report_type) "
            "VALUES (%s, %s, %s, 'CBC')",
            (lab_id, owner["id"], author["doctor_code"]),
        )

    urls = (
        f"/emr/prescriptions/patient/{owner['id']}",
        f"/emr/prescriptions/{rx_id}",
        f"/emr/lab-reports/patient/{owner['id']}",
        f"/emr/lab-reports/{lab_id}",
    )
    for url in urls:
        response = client.get(url, headers=make_token(author))
        assert response.status_code == 403, (url, response.status_code)
