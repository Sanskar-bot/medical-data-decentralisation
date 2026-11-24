"""[C3] Nobody can list every patient's access requests with the API key."""
import os

import pytest

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}


@pytest.fixture
def two(app, clean_db, db, make_user):
    a, b, d = make_user("patient"), make_user("patient"), make_user("doctor")
    with db() as cur:
        for rid, p in (("ra", a), ("rb", b)):
            cur.execute("INSERT INTO access_requests (request_id, profile_code, doctor_code) "
                        "VALUES (%s, %s, %s)", (rid, p["profile_code"], d["doctor_code"]))
    return a, b, d


def test_active_requests_is_gone(client, two):
    assert client.get("/active_requests", headers=API).status_code == 404


def test_mine_lists_only_own(client, two, make_token):
    a, _, _ = two
    r = client.get("/access_requests/mine", headers=make_token(a))
    assert r.status_code == 200
    assert [x["request_id"] for x in r.get_json()] == ["ra"]


def test_request_status_bound_to_caller(client, two, make_token):
    a, b, d = two
    assert client.get("/request_status/ra", headers=API).status_code == 404
    assert client.get("/request_status/ra", headers={**API, **make_token(b)}).status_code == 404
    assert client.get("/request_status/ra", headers={**API, **make_token(a)}).status_code == 200
    assert client.get("/request_status/ra", headers={**API, **make_token(d)}).status_code == 200
