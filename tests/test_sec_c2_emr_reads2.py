"""[C2][X2] EMR appointments, conditions and encounters: deny by default."""
import uuid

import pytest


@pytest.fixture
def world(app, clean_db, db, make_user, grant_access):
    owner = make_user("patient")
    granted, stranger, admin = make_user("doctor"), make_user("doctor"), make_user("admin")
    grant_access(granted, owner)
    enc = str(uuid.uuid4())
    with db() as cur:
        cur.execute("INSERT INTO encounters (id, patient_id, doctor_id) VALUES (%s, %s, %s)",
                    (enc, owner["id"], granted["doctor_code"]))
        cur.execute("INSERT INTO conditions (id, patient_id, description, recorded_by) "
                    "VALUES (%s, %s, 'Asthma', %s)", (str(uuid.uuid4()), owner["id"], granted["doctor_code"]))
    return {"owner": owner, "granted": granted, "stranger": stranger, "admin": admin, "enc": enc}


def _urls(w):
    pid = w["owner"]["id"]
    return [f"/emr/appointments/patient/{pid}", f"/emr/conditions/patient/{pid}",
            f"/emr/encounters/patient/{pid}", f"/emr/encounters/{w['enc']}",
            f"/emr/encounters/{w['enc']}/bundle"]


@pytest.mark.parametrize("who", ["stranger", "admin"])
def test_denied(client, world, make_token, who):
    for url in _urls(world):
        r = client.get(url, headers=make_token(world[who]))
        assert r.status_code == 403, (who, url, r.status_code)


@pytest.mark.parametrize("who", ["owner", "granted"])
def test_allowed(client, world, make_token, who):
    for url in _urls(world):
        r = client.get(url, headers=make_token(world[who]))
        assert r.status_code == 200, (who, url, r.status_code)
