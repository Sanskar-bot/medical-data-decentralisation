"""[C3] Per-service API keys are accepted and attributed; unknown keys are not."""
import os

KEY_LANDING = "L" * 40
KEY_PORTAL = "P" * 40


def test_parse_service_keys():
    import server
    keys = server._parse_service_keys(f"landing={KEY_LANDING}, patient_portal={KEY_PORTAL}, bad=short")
    assert keys == {"landing": KEY_LANDING, "patient_portal": KEY_PORTAL}


def test_service_key_accepted_and_attributed(client, clean_db, db, make_user, make_token, monkeypatch):
    import server
    monkeypatch.setattr(server, "_SERVICE_API_KEYS", {"landing": KEY_LANDING})
    p = make_user("patient")
    hdr = {"X-API-Key": KEY_LANDING, **make_token(p)}
    assert client.get(f"/get_patient_data/{p['profile_code']}", headers=hdr).status_code == 200
    with server.app.test_request_context("/", headers={"X-API-Key": KEY_LANDING}):
        assert server._require_api_key() is None
        from flask import g
        assert g.api_service == "landing"
        server.audit("unit_test_action")
    with db() as cur:
        cur.execute("SELECT actor FROM audit_log WHERE action = 'unit_test_action'")
        assert cur.fetchone()["actor"] == "service:landing"


def test_unknown_key_rejected(client, clean_db, monkeypatch):
    import server
    monkeypatch.setattr(server, "_SERVICE_API_KEYS", {"landing": KEY_LANDING})
    r = client.get("/get_patient_public/X", headers={"X-API-Key": "Z" * 40})
    assert r.status_code == 401


def test_legacy_key_still_works(client, clean_db):
    r = client.get("/get_patient_public/NOPE", headers={"X-API-Key": os.environ["SERVER_API_KEY"]})
    assert r.status_code == 404
