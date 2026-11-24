"""[C2][X2] EMR profile: deny by default."""
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
    return [f"/emr/patient/{pid}/profile", f"/emr/patient/{w['owner']['profile_code']}/profile"]


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


def test_stranger_doctor_cannot_write_profile(client, world, make_token):
    r = client.put(f"/emr/patient/{world['owner']['id']}/profile",
                   headers=make_token(world["stranger"]), json={"name": "Hacked"})
    assert r.status_code == 403
