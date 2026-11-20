"""Integration coverage for JWT-protected per-share snapshot endpoints."""

import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_DIR = os.path.join(ROOT, "server")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)


@pytest.fixture(scope="module")
def app():
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, ".env"))
    from db import init_db
    init_db()
    from server import app as flask_app
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db():
    from db import db_cursor
    yield db_cursor


@pytest.fixture(autouse=True)
def reset_share_rate_limit():
    from db import db_cursor
    with db_cursor() as cur:
        cur.execute("DELETE FROM rate_limits WHERE endpoint = 'create_snapshot_share'")


@pytest.fixture(scope="module")
def key_material():
    from common.crypto_utils import generate_rsa_keypair
    patient_private, patient_public = generate_rsa_keypair(2048)
    doctor_private, doctor_public = generate_rsa_keypair(2048)
    return patient_private, patient_public, doctor_private, doctor_public


def token(app, role, code, uid=None):
    from server import _jwt_encode
    claims = {"sub": f"{role}@example.test", "uid": uid or code, "role": role,
              "exp": time.time() + 3600}
    if role == "patient":
        claims["profile_code"] = code
    else:
        claims["doctor_code"] = code
    return {"Authorization": f"Bearer {_jwt_encode(claims)}",
            "Content-Type": "application/json"}


def identities(key_material):
    from common.crypto_utils import rsa_serialize_public
    _, patient_public, _, doctor_public = key_material
    patient_code = f"PAT-SHARE-{uuid.uuid4().hex}"
    doctor_code = f"DOC-SHARE-{uuid.uuid4().hex}"
    with __import__("db").db_cursor() as cur:
        cur.execute("""
            INSERT INTO patients (profile_code, encrypted_record, patient_public_pem)
            VALUES (%s, '{}'::jsonb, %s)
        """, (patient_code, rsa_serialize_public(patient_public).decode()))
        cur.execute("""
            INSERT INTO doctors (doctor_code, doctor_id, public_pem)
            VALUES (%s, %s, %s)
        """, (doctor_code, str(uuid.uuid4()), rsa_serialize_public(doctor_public).decode()))
    return patient_code, doctor_code


def build_package(key_material, patient_code, doctor_code, *, ttl=3600, share_id=None,
                  expires_at=None, plaintext=b"snapshot bytes"):
    from common.share_scheme import create_share
    patient_private, _, _, doctor_public = key_material
    expiry = expires_at or (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
    return create_share(plaintext, patient_private, doctor_public,
                        share_id or str(uuid.uuid4()), patient_code, doctor_code, expiry)


def post_share(client, app, key_material, patient_code, doctor_code, *, ttl=3600,
               expires_at=None, payload_overrides=None):
    package = build_package(key_material, patient_code, doctor_code, ttl=ttl,
                            expires_at=expires_at)
    body = {**package, "label": "Visit snapshot", "expires_in_seconds": ttl}
    body.update(payload_overrides or {})
    response = client.post("/shares", headers=token(app, "patient", patient_code), json=body)
    return response, package, body


def row_for(share_id):
    from db import db_cursor
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM shares WHERE share_id = %s", (share_id,))
        return cur.fetchone()


def test_patient_creates_named_doctor_fetches_and_opens_share(client, app, key_material):
    from common.crypto_utils import rsa_load_public
    from common.share_scheme import open_share
    patient_code, doctor_code = identities(key_material)
    response, package, _ = post_share(client, app, key_material, patient_code, doctor_code)
    assert response.status_code == 201
    fetched = client.get(f"/shares/{package['share_id']}", headers=token(app, "doctor", doctor_code))
    assert fetched.status_code == 200
    data = fetched.get_json()
    _, _, doctor_private, _ = key_material
    patient_public = rsa_load_public(data["patient_public_pem"].encode())
    assert open_share(data["share"], doctor_private, patient_public, doctor_code) == b"snapshot bytes"


def test_wrong_doctor_gets_404_and_other_patient_cannot_revoke(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    response, package, _ = post_share(client, app, key_material, patient_code, doctor_code)
    assert response.status_code == 201
    wrong_doctor = client.get(f"/shares/{package['share_id']}",
                              headers=token(app, "doctor", "DOC-NOT-NAMED"))
    assert wrong_doctor.status_code == 404
    wrong_patient = client.delete(f"/shares/{package['share_id']}",
                                  headers=token(app, "patient", "PAT-NOT-OWNER"))
    assert wrong_patient.status_code == 404


def test_unauthenticated_share_requests_return_401(client):
    assert client.get("/shares/incoming").status_code == 401
    assert client.get("/shares/outgoing").status_code == 401
    assert client.post("/shares", json={}).status_code == 401


def test_fetch_after_server_expiry_returns_410_and_clears_blobs(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    response, package, _ = post_share(client, app, key_material, patient_code, doctor_code)
    assert response.status_code == 201
    from db import db_cursor
    with db_cursor() as cur:
        cur.execute("UPDATE shares SET expires_at = now() - interval '1 second' WHERE share_id = %s",
                    (package["share_id"],))
    fetched = client.get(f"/shares/{package['share_id']}", headers=token(app, "doctor", doctor_code))
    assert fetched.status_code == 410
    row = row_for(package["share_id"])
    assert row["status"] == "expired"
    assert row["ciphertext_blob"] is None and row["wrapped_key"] is None and row["signature"] is None


def test_delete_revokes_and_clears_share(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    response, package, _ = post_share(client, app, key_material, patient_code, doctor_code)
    assert response.status_code == 201
    revoked = client.delete(f"/shares/{package['share_id']}",
                            headers=token(app, "patient", patient_code))
    assert revoked.status_code == 200
    fetched = client.get(f"/shares/{package['share_id']}", headers=token(app, "doctor", doctor_code))
    assert fetched.status_code == 410
    row = row_for(package["share_id"])
    assert row["status"] == "revoked"
    assert row["ciphertext_blob"] is None and row["wrapped_key"] is None and row["signature"] is None


def test_purge_expired_shares_nulls_payload_and_marks_purged(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    response, package, _ = post_share(client, app, key_material, patient_code, doctor_code)
    assert response.status_code == 201
    from db import db_cursor
    with db_cursor() as cur:
        cur.execute("UPDATE shares SET expires_at = now() - interval '1 second' WHERE share_id = %s",
                    (package["share_id"],))
    from server import purge_expired_shares
    assert purge_expired_shares() >= 1
    row = row_for(package["share_id"])
    assert row["status"] == "purged" and row["purged_at"] is not None
    assert row["ciphertext_blob"] is None and row["wrapped_key"] is None and row["signature"] is None


@pytest.mark.parametrize("ttl", [299, 604801])
def test_ttl_outside_bounds_returns_400(client, app, key_material, ttl):
    patient_code, doctor_code = identities(key_material)
    response, _, _ = post_share(client, app, key_material, patient_code, doctor_code, ttl=ttl)
    assert response.status_code == 400


def test_oversized_payload_returns_413(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    body = {"patient_code": patient_code, "doctor_code": doctor_code,
            "ciphertext": "x" * (5 * 1024 * 1024 + 1)}
    response = client.post("/shares", headers=token(app, "patient", patient_code), json=body)
    assert response.status_code == 413


def test_package_expiry_outside_tolerance_is_rejected(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    old_expiry = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    response, _, _ = post_share(client, app, key_material, patient_code, doctor_code,
                                ttl=3600, expires_at=old_expiry)
    assert response.status_code == 400
    assert response.get_json()["error"] == "package_expiry_mismatch"


def test_list_responses_do_not_include_ciphertext_or_wrapped_key(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    response, package, _ = post_share(client, app, key_material, patient_code, doctor_code)
    assert response.status_code == 201
    incoming = client.get("/shares/incoming", headers=token(app, "doctor", doctor_code)).get_json()
    outgoing = client.get("/shares/outgoing", headers=token(app, "patient", patient_code)).get_json()
    assert package["share_id"] in [entry["share_id"] for entry in incoming["shares"]]
    assert package["share_id"] in [entry["share_id"] for entry in outgoing["shares"]]
    for payload in (incoming, outgoing):
        serialized = str(payload)
        assert "ciphertext" not in serialized and "wrapped_key" not in serialized


def test_audit_entries_cover_create_fetch_revoke_purge_without_key_material(client, app, key_material):
    patient_code, doctor_code = identities(key_material)
    response, package, _ = post_share(client, app, key_material, patient_code, doctor_code)
    assert response.status_code == 201
    assert client.get(f"/shares/{package['share_id']}", headers=token(app, "doctor", doctor_code)).status_code == 200
    client.delete(f"/shares/{package['share_id']}", headers=token(app, "patient", patient_code))

    patient2, doctor2 = identities(key_material)
    response2, package2, _ = post_share(client, app, key_material, patient2, doctor2)
    assert response2.status_code == 201
    from db import db_cursor
    with db_cursor() as cur:
        cur.execute("UPDATE shares SET expires_at = now() - interval '1 second' WHERE share_id = %s",
                    (package2["share_id"],))
    from server import purge_expired_shares
    purge_expired_shares()

    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT action, actor, target, detail FROM audit_log
             WHERE (target IN (%s, %s) OR (action = 'share_purged' AND actor = 'system'))
               AND action IN ('share_created','share_fetched','share_revoked','share_purged')
        """, (package["share_id"], package2["share_id"]))
        records = cur.fetchall()
    actions = {record["action"] for record in records}
    assert {"share_created", "share_fetched", "share_revoked", "share_purged"} <= actions
    audit_text = str(records)
    for secret in (package["wrapped_key"], package["ciphertext"], package["signature"]):
        assert secret not in audit_text
