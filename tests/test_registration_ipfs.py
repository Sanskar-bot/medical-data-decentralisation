"""Registration envelope storage and lifecycle over the fake IPFS client."""

import base64
import os
import time
import uuid
from contextlib import contextmanager

import pytest

from common.crypto_utils import generate_rsa_keypair, rsa_serialize_public, rsa_sign

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}


def registration(private_key, public_pem, profile_code, ciphertext="Y2lwaGVydGV4dA=="):
    envelope = {"nonce": "bm9uY2U=", "ciphertext": ciphertext}
    signature = rsa_sign(private_key, (envelope["nonce"] + "|" + envelope["ciphertext"]).encode())
    return {
        "profile_code": profile_code,
        "encrypted_record": envelope,
        "signature": signature,
        "patient_public_pem": public_pem,
    }


def own_token(app, profile_code):
    from server import _jwt_encode
    return {"Authorization": "Bearer " + _jwt_encode({
        "sub": profile_code, "uid": profile_code, "role": "patient",
        "profile_code": profile_code, "exp": time.time() + 600,
    })}


def test_registration_stores_only_ipfs_pointer_and_fetches_verified_envelope(client, app, db, clean_db):
    private_key, public_key = generate_rsa_keypair(2048)
    profile_code = "PAT-IPFS-" + uuid.uuid4().hex
    public_pem = rsa_serialize_public(public_key).decode()
    response = client.post("/register_user", headers=API,
                          json=registration(private_key, public_pem, profile_code))
    assert response.status_code == 200
    with db(commit=False) as cur:
        cur.execute("SELECT encrypted_record, ipfs_cid, ciphertext_sha256, ciphertext_size FROM patients WHERE profile_code=%s",
                    (profile_code,))
        row = cur.fetchone()
    assert row["encrypted_record"] is None
    assert row["ipfs_cid"] and row["ciphertext_sha256"] and row["ciphertext_size"]

    fetched = client.get(f"/get_patient_data/{profile_code}",
                         headers={**API, **own_token(app, profile_code)})
    assert fetched.status_code == 200
    assert fetched.get_json()["encrypted_record"]["ciphertext"] == "Y2lwaGVydGV4dA=="


def test_registration_tampering_fails_closed_and_replacement_unpins_old(client, app, db, clean_db):
    private_key, public_key = generate_rsa_keypair(2048)
    profile_code = "PAT-IPFS-" + uuid.uuid4().hex
    public_pem = rsa_serialize_public(public_key).decode()
    first_ciphertext = base64.b64encode(uuid.uuid4().bytes).decode()
    first = client.post("/register_user", headers=API,
                        json=registration(private_key, public_pem, profile_code, first_ciphertext))
    assert first.status_code == 200
    ipfs = app.config["IPFS_CLIENT"]
    first_row = first.get_json()
    first_cid = first_row["ipfs_cid"]

    tampered_payload = registration(private_key, public_pem, profile_code, "bmV3LWNpcGhlcnRleHQ=")
    second = client.post("/register_user", headers=API, json=tampered_payload)
    assert second.status_code == 200
    assert first_cid not in ipfs.pins

    current = second.get_json()["ipfs_cid"]
    ipfs.tamper(current, b"altered")
    fetched = client.get(f"/get_patient_data/{profile_code}",
                         headers={**API, **own_token(app, profile_code)})
    assert fetched.status_code == 503
    assert fetched.get_json()["error"] == "ciphertext_integrity_failed"


def test_patient_deletion_unpins_registration_record(client, app, db, clean_db):
    private_key, public_key = generate_rsa_keypair(2048)
    profile_code = "PAT-IPFS-" + uuid.uuid4().hex
    public_pem = rsa_serialize_public(public_key).decode()
    unique_ciphertext = base64.b64encode(uuid.uuid4().bytes).decode()
    created = client.post("/register_user", headers=API,
                          json=registration(private_key, public_pem, profile_code, unique_ciphertext))
    cid = created.get_json()["ipfs_cid"]
    ipfs = app.config["IPFS_CLIENT"]
    assert cid in ipfs.pins

    deleted = client.delete(f"/registration-record/{profile_code}",
                            headers=own_token(app, profile_code))
    assert deleted.status_code == 200
    assert cid not in ipfs.pins


def test_deleting_one_of_two_rows_with_same_cid_keeps_content_pinned(app, db):
    import server

    ipfs = app.config["IPFS_CLIENT"]
    stored = ipfs.store_ciphertext(b"shared encrypted registration content")
    profile_codes = ["PAT-SHARED-CID-" + uuid.uuid4().hex for _ in range(2)]
    with db() as cur:
        for profile_code in profile_codes:
            cur.execute("""
                INSERT INTO patients
                    (profile_code, encrypted_record, ipfs_cid,
                     ciphertext_sha256, ciphertext_size)
                VALUES (%s, NULL, %s, %s, %s)
            """, (profile_code, stored.cid, stored.sha256, stored.size))
        cur.execute("DELETE FROM patients WHERE profile_code = %s", (profile_codes[0],))

    with app.app_context():
        server._unpin_ciphertext(stored.cid)

    assert stored.cid in ipfs.pins


def test_failed_registration_db_insert_best_effort_unpins_uploaded_ciphertext(app, monkeypatch):
    import server

    private_key, public_key = generate_rsa_keypair(2048)
    profile_code = "PAT-IPFS-FAIL-" + uuid.uuid4().hex
    public_pem = rsa_serialize_public(public_key).decode()
    ipfs = app.config["IPFS_CLIENT"]
    ipfs.blocks.clear()
    ipfs.pins.clear()

    class FailingCursor:
        def execute(self, query, params=None):
            if "SELECT ipfs_cid FROM patients" in query:
                return
            if "INSERT INTO patients" in query:
                raise RuntimeError("simulated database insert failure")
            raise AssertionError(f"unexpected SQL: {query}")

        def fetchone(self):
            return None

    @contextmanager
    def fail_patient_insert(*, commit=True):
        yield FailingCursor()

    monkeypatch.setattr(server, "db_cursor", fail_patient_insert)
    with app.app_context(), pytest.raises(RuntimeError, match="simulated database insert failure"):
        server._db_upsert_patient(
            profile_code,
            registration(private_key, public_pem, profile_code),
        )

    assert not ipfs.pins


def test_failed_duplicate_registration_insert_keeps_referenced_cid_pinned(app, monkeypatch):
    import json
    import server

    profile_code = "PAT-IPFS-REFERENCED-" + uuid.uuid4().hex
    envelope = {"nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVydGV4dA=="}
    serialized = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    ipfs = app.config["IPFS_CLIENT"]
    stored = ipfs.store_ciphertext(serialized)

    class FailingCursor:
        last_query = ""

        def execute(self, query, params=None):
            self.last_query = query
            if "INSERT INTO patients" in query:
                raise RuntimeError("simulated duplicate row failure")

        def fetchone(self):
            if "SELECT EXISTS" in self.last_query:
                return {"referenced": True}
            if "SELECT ipfs_cid FROM patients" in self.last_query:
                return {"ipfs_cid": stored.cid}
            raise AssertionError(f"unexpected query: {self.last_query}")

    @contextmanager
    def fail_patient_insert(*, commit=True):
        yield FailingCursor()

    monkeypatch.setattr(server, "db_cursor", fail_patient_insert)
    with app.app_context(), pytest.raises(RuntimeError, match="simulated duplicate row failure"):
        server._db_upsert_patient(profile_code, {"encrypted_record": envelope})

    assert stored.cid in ipfs.pins

