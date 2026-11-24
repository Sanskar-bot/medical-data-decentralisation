"""[C2] Reports and images: only the patient or a granted doctor may read."""
import os
import uuid

import pytest


@pytest.fixture
def world(app, clean_db, db, make_user, grant_access):
    import server
    owner, other = make_user("patient"), make_user("patient")
    granted, stranger = make_user("doctor"), make_user("doctor")
    admin, recep = make_user("admin"), make_user("receptionist")
    grant_access(granted, owner)
    rid, iid = str(uuid.uuid4()), str(uuid.uuid4())
    with db() as cur:
        cur.execute("INSERT INTO records (id, patient_id, doctor_id) VALUES (%s, %s, %s)",
                    (rid, owner["id"], granted["id"]))
        cur.execute("INSERT INTO images (id, record_id, encrypted_image_path) VALUES (%s, %s, %s)",
                    (iid, rid, f"images/{iid}.enc"))
    path = os.path.join(server.UPLOADS_DIR, "images", f"{iid}.enc")
    with open(path, "wb") as fh:
        fh.write(b"ciphertext")
    yield {"owner": owner, "other": other, "granted": granted, "stranger": stranger,
           "admin": admin, "recep": recep, "rid": rid, "iid": iid}
    os.remove(path)


def _urls(w):
    return [f"/reports/patient/{w['owner']['id']}", f"/reports/{w['rid']}",
            f"/images/record/{w['rid']}", f"/images/download/{w['iid']}"]


@pytest.mark.parametrize("who", ["admin", "recep", "stranger", "other"])
def test_denied_roles_get_403(client, world, make_token, who):
    for url in _urls(world):
        r = client.get(url, headers=make_token(world[who]))
        assert r.status_code == 403, (who, url, r.status_code)


@pytest.mark.parametrize("who", ["owner", "granted"])
def test_allowed_roles_get_200(client, world, make_token, who):
    for url in _urls(world):
        r = client.get(url, headers=make_token(world[who]))
        assert r.status_code == 200, (who, url, r.status_code)
