"""[C2] EMR update/delete: author only, grant required, admin denied."""
import uuid

import pytest


@pytest.fixture
def w(app, clean_db, db, make_user, grant_access):
    owner = make_user("patient")
    author, admin = make_user("doctor"), make_user("admin")
    grant_access(author, owner)
    ids = {"appt": str(uuid.uuid4()), "cond": str(uuid.uuid4()), "enc": str(uuid.uuid4())}
    with db() as cur:
        cur.execute("INSERT INTO emr_appointments (id, patient_id, doctor_id, date_time) "
                    "VALUES (%s, %s, %s, '2030-01-01T10:00:00')", (ids["appt"], owner["id"], author["id"]))
        cur.execute("INSERT INTO conditions (id, patient_id, description, recorded_by) "
                    "VALUES (%s, %s, 'Asthma', %s)", (ids["cond"], owner["id"], author["doctor_code"]))
        cur.execute("INSERT INTO encounters (id, patient_id, doctor_id) VALUES (%s, %s, %s)",
                    (ids["enc"], owner["id"], author["doctor_code"]))
    return {"owner": owner, "author": author, "admin": admin, **ids}


def _calls(w):
    return [("put", f"/emr/appointments/{w['appt']}", {"status": "completed"}),
            ("put", f"/emr/conditions/{w['cond']}", {"notes": "n"}),
            ("put", f"/emr/encounters/{w['enc']}", {"summary": "s"}),
            ("delete", f"/emr/appointments/{w['appt']}", None)]


def test_admin_cannot_change_clinical_rows(client, w, make_token):
    for method, url, body in _calls(w):
        r = getattr(client, method)(url, headers=make_token(w["admin"]), json=body)
        assert r.status_code == 403, (url, r.status_code)


def test_author_loses_rights_after_revoke(client, w, make_token, db):
    with db() as cur:
        cur.execute("UPDATE access_db SET status = 'revoked'")
    for method, url, body in _calls(w):
        r = getattr(client, method)(url, headers=make_token(w["author"]), json=body)
        assert r.status_code == 403, (url, r.status_code)


def test_author_with_grant_can_update(client, w, make_token):
    for method, url, body in _calls(w):
        r = getattr(client, method)(url, headers=make_token(w["author"]), json=body)
        assert r.status_code == 200, (url, r.status_code)
