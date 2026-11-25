"""[C3][FC5] /approve_request: API key alone is not enough; owner only; pending only."""
import os

import pytest

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}


@pytest.fixture
def req(app, clean_db, db, make_user):
    p, d, other = make_user("patient"), make_user("doctor"), make_user("patient")
    with db() as cur:
        cur.execute("INSERT INTO access_requests (request_id, profile_code, doctor_code, status) "
                    "VALUES ('req-1', %s, %s, 'pending')", (p["profile_code"], d["doctor_code"]))
    body = {"request_id": "req-1", "doctor_code": d["doctor_code"], "patient_code": p["profile_code"],
            "wrapped_key": "WK", "encrypted_kdata_with_temp": {"nonce": "n", "ciphertext": "c"},
            "temp_key_expires_at": "2099-01-01T00:00:00+00:00"}
    return p, d, other, body


def test_api_key_alone_cannot_approve(client, req, db):
    _, _, _, body = req
    assert client.post("/approve_request", headers=API, json=body).status_code == 403
    with db() as cur:
        cur.execute("SELECT count(*) AS n FROM wrapped_keys")
        assert cur.fetchone()["n"] == 0


def test_other_patient_cannot_approve(client, req, make_token):
    _, _, other, body = req
    r = client.post("/approve_request", headers={**API, **make_token(other)}, json=body)
    assert r.status_code == 403


def test_owner_approves_once(client, req, make_token, db):
    p, _, _, body = req
    hdr = {**API, **make_token(p)}
    assert client.post("/approve_request", headers=hdr, json=body).status_code == 200
    with db() as cur:
        cur.execute("SELECT status FROM access_requests WHERE request_id = 'req-1'")
        assert cur.fetchone()["status"] == "approved"
        cur.execute("SELECT count(*) AS n FROM wrapped_keys")
        assert cur.fetchone()["n"] == 1
    assert client.post("/approve_request", headers=hdr, json=body).status_code == 409


def test_approval_without_expiry_uses_configured_default(client, req, make_token, db, monkeypatch):
    from datetime import datetime, timezone, timedelta
    p, _, _, body = req
    body.pop("temp_key_expires_at")
    monkeypatch.setenv("WRAPPED_KEY_TTL_HOURS", "2")
    before = datetime.now(timezone.utc) + timedelta(hours=1, minutes=59)
    response = client.post("/approve_request", headers={**API, **make_token(p)}, json=body)
    assert response.status_code == 200
    with db(commit=False) as cur:
        cur.execute("SELECT temp_key_expires_at FROM wrapped_keys")
        expiry = cur.fetchone()["temp_key_expires_at"]
    assert expiry > before


def test_denied_request_cannot_be_approved(client, req, make_token, db):
    p, _, _, body = req
    with db() as cur:
        cur.execute("UPDATE access_requests SET status = 'denied' WHERE request_id = 'req-1'")
    r = client.post("/approve_request", headers={**API, **make_token(p)}, json=body)
    assert r.status_code == 409
