"""[C3] /update_request_status is bound to the request's owner."""
import os

import pytest

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}


@pytest.fixture
def req(app, clean_db, db, make_user):
    p, d, other = make_user("patient"), make_user("doctor"), make_user("patient")
    with db() as cur:
        cur.execute("INSERT INTO access_requests (request_id, profile_code, doctor_code, status) "
                    "VALUES ('req-2', %s, %s, 'pending')", (p["profile_code"], d["doctor_code"]))
    return p, d, other


def test_api_key_alone_cannot_change_status(client, req):
    r = client.post("/update_request_status", headers=API, json={"request_id": "req-2", "status": "denied"})
    assert r.status_code == 403


def test_other_patient_cannot_deny(client, req, make_token):
    _, _, other = req
    r = client.post("/update_request_status", headers={**API, **make_token(other)},
                    json={"request_id": "req-2", "status": "denied"})
    assert r.status_code == 403


def test_doctor_cannot_deny_but_can_cancel(client, req, make_token):
    _, d, _ = req
    hdr = {**API, **make_token(d)}
    assert client.post("/update_request_status", headers=hdr,
                       json={"request_id": "req-2", "status": "denied"}).status_code == 403
    assert client.post("/update_request_status", headers=hdr,
                       json={"request_id": "req-2", "status": "cancelled"}).status_code == 200


def test_owner_can_deny(client, req, make_token):
    p, _, _ = req
    r = client.post("/update_request_status", headers={**API, **make_token(p)},
                    json={"request_id": "req-2", "status": "denied"})
    assert r.status_code == 200
