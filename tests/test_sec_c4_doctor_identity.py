"""[C4] A doctor cannot request access under another doctor's code or key."""
import os

import pytest

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}
ENC = "x" * 32


@pytest.fixture
def w(app, clean_db, db, make_user):
    p = make_user("patient")
    good, evil = make_user("doctor"), make_user("doctor")
    with db() as cur:
        cur.execute("UPDATE doctors SET public_pem = %s WHERE doctor_code = %s", ("GOOD-PEM", good["doctor_code"]))
        cur.execute("UPDATE doctors SET public_pem = %s WHERE doctor_code = %s", ("EVIL-PEM", evil["doctor_code"]))
    return p, good, evil


def _stored(db):
    with db() as cur:
        cur.execute("SELECT doctor_code, doctor_public_pem FROM access_requests")
        return cur.fetchall()


def test_jwt_route_rejects_other_doctors_code(client, w, make_token, db):
    p, good, evil = w
    body = {"profile_code": p["profile_code"], "doctor_code": good["doctor_code"],
            "doctor_public_pem": "EVIL-PEM", "encrypted_doctor_profile_b64": ENC}
    assert client.post("/access/request", headers=make_token(evil), json=body).status_code == 403
    assert _stored(db) == []


def test_jwt_route_rejects_substituted_key(client, w, make_token, db):
    p, good, _ = w
    body = {"profile_code": p["profile_code"], "doctor_code": good["doctor_code"],
            "doctor_public_pem": "ATTACKER-PEM", "encrypted_doctor_profile_b64": ENC}
    assert client.post("/access/request", headers=make_token(good), json=body).status_code == 400
    assert _stored(db) == []


def test_simple_route_needs_that_doctor(client, w, make_token, db):
    p, good, evil = w
    body = {"doctor_code": good["doctor_code"], "doctor_public_pem": "GOOD-PEM",
            "encrypted_doctor_profile_b64": ENC}
    url = f"/request_access_simple/{p['profile_code']}"
    assert client.post(url, headers=API, json=body).status_code == 403
    assert client.post(url, headers={**API, **make_token(evil)}, json=body).status_code == 403
    body_bad = dict(body, doctor_public_pem="EVIL-PEM")
    assert client.post(url, headers={**API, **make_token(good)}, json=body_bad).status_code == 400
    assert client.post(url, headers={**API, **make_token(good)}, json=body).status_code == 201
    assert [dict(r) for r in _stored(db)] == [{"doctor_code": good["doctor_code"], "doctor_public_pem": "GOOD-PEM"}]


def test_simple_route_patient_qr_share_allowed(client, w, make_token):
    p, good, _ = w
    body = {"doctor_code": good["doctor_code"], "doctor_public_pem": "GOOD-PEM",
            "encrypted_doctor_profile_b64": ENC}
    r = client.post(f"/request_access_simple/{p['profile_code']}", headers={**API, **make_token(p)}, json=body)
    assert r.status_code == 201
