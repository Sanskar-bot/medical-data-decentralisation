"""Database-backed pin repair and delayed orphan cleanup tests."""

import base64
import json
import uuid

import ipfs_maintenance


def test_pin_repair_restores_missing_content(clean_db, app, db):
    client = app.config["IPFS_CLIENT"]
    payload = b"ciphertext used by pin repair"
    stored = client.store_ciphertext(payload)
    client.pins.discard(stored.cid)
    with db() as cur:
        cur.execute("""
            INSERT INTO patients
                (profile_code, encrypted_record, ipfs_cid, ciphertext_sha256, ciphertext_size)
            VALUES (%s, NULL, %s, %s, %s)
        """, ("PAT-REPAIR-" + uuid.uuid4().hex, stored.cid, stored.sha256, stored.size))

    result = ipfs_maintenance.repair_pins(client)
    assert result["repaired"] == 1
    assert stored.cid in client.pins
    with db(commit=False) as cur:
        cur.execute("SELECT status FROM ipfs_pin_status WHERE cid=%s AND target='primary'",
                    (stored.cid,))
        assert cur.fetchone()["status"] == "pinned"


def test_orphan_cleanup_unpins_after_grace(clean_db, app, db):
    client = app.config["IPFS_CLIENT"]
    client.blocks.clear()
    client.pins.clear()
    orphan = b"orphaned ciphertext"
    cid = client.add_bytes(orphan)
    assert cid in client.pins

    result = ipfs_maintenance.cleanup_orphans(client, grace_seconds=0)
    assert result["observed"] == 1
    assert result["removed"] == 1
    assert cid not in client.pins
    with db(commit=False) as cur:
        cur.execute("SELECT status FROM ipfs_pin_status WHERE cid=%s AND target='primary'", (cid,))
        assert cur.fetchone()["status"] == "unpinned"


def test_pin_repair_repairs_missing_replica(clean_db, app, db, monkeypatch):
    from fake_ipfs import FakeIPFSClient

    primary = app.config["IPFS_CLIENT"]
    payload = b"replica repair ciphertext"
    stored = primary.store_ciphertext(payload)
    replica = FakeIPFSClient(api_url="http://replica")
    primary.pin_targets = [("replica", replica.api_url)]
    monkeypatch.setattr(ipfs_maintenance, "IPFSClient", lambda **_kwargs: replica)
    with db() as cur:
        cur.execute("""
            INSERT INTO patients
                (profile_code, encrypted_record, ipfs_cid, ciphertext_sha256, ciphertext_size)
            VALUES (%s, NULL, %s, %s, %s)
        """, ("PAT-REPLICA-" + uuid.uuid4().hex, stored.cid, stored.sha256, stored.size))

    result = ipfs_maintenance.repair_pins(primary)
    assert result["repaired"] == 1
    assert stored.cid in replica.pins
    assert replica.get_verified_bytes(stored.cid, stored.sha256) == payload
    with db(commit=False) as cur:
        cur.execute("SELECT status FROM ipfs_pin_status WHERE cid=%s AND target='replica'",
                    (stored.cid,))
        assert cur.fetchone()["status"] == "pinned"


def test_legacy_inline_rows_migrate_only_after_verified_upload(clean_db, app, db):
    client = app.config["IPFS_CLIENT"]
    patient_code = "PAT-LEGACY-IPFS-" + uuid.uuid4().hex
    share_id = str(uuid.uuid4())
    envelope = {"nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVydGV4dA=="}
    share_ciphertext = b"already-encrypted legacy share"
    with db() as cur:
        cur.execute("""
            INSERT INTO patients (profile_code, encrypted_record)
            VALUES (%s, %s)
        """, (patient_code, json.dumps(envelope)))
        cur.execute("""
            INSERT INTO shares (share_id, patient_code, doctor_code, expires_at, ciphertext_blob)
            VALUES (%s, %s, %s, now() + interval '1 hour', %s)
        """, (share_id, patient_code, "DOC-LEGACY-IPFS",
              json.dumps({"version": 1, "ciphertext": base64.b64encode(share_ciphertext).decode()})))

    assert ipfs_maintenance.legacy_inline_counts() == {"registrations": 1, "shares": 1}
    result = ipfs_maintenance.migrate_legacy_ciphertext(client)
    assert result == {"registrations": 1, "shares": 1, "failed": 0}

    with db(commit=False) as cur:
        cur.execute("""
            SELECT encrypted_record, ipfs_cid, ciphertext_sha256, ciphertext_size
              FROM patients WHERE profile_code = %s
        """, (patient_code,))
        patient = cur.fetchone()
        cur.execute("""
            SELECT ciphertext_blob, ipfs_cid, ciphertext_sha256, ciphertext_size
              FROM shares WHERE share_id = %s
        """, (share_id,))
        share = cur.fetchone()
    assert patient["encrypted_record"] is None
    assert share["ciphertext_blob"].get("ciphertext") is None
    assert client.get_verified_bytes(patient["ipfs_cid"], patient["ciphertext_sha256"])
    assert client.get_verified_bytes(share["ipfs_cid"], share["ciphertext_sha256"]) == share_ciphertext
    assert patient["ciphertext_size"] and share["ciphertext_size"] == len(share_ciphertext)
    assert ipfs_maintenance.legacy_inline_counts() == {"registrations": 0, "shares": 0}


def test_legacy_migration_leaves_inline_row_when_refetch_verification_fails(clean_db, app, db):
    from fake_ipfs import FakeIPFSClient

    class TamperingClient(FakeIPFSClient):
        def store_ciphertext(self, data):
            stored = super().store_ciphertext(data)
            self.tamper(stored.cid, b"corrupted after upload")
            return stored

    client = TamperingClient()
    patient_code = "PAT-LEGACY-TAMPER-" + uuid.uuid4().hex
    envelope = {"nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVydGV4dA=="}
    with db() as cur:
        cur.execute("INSERT INTO patients (profile_code, encrypted_record) VALUES (%s, %s)",
                    (patient_code, json.dumps(envelope)))

    result = ipfs_maintenance.migrate_legacy_ciphertext(client)
    assert result["registrations"] == 0 and result["failed"] == 1
    with db(commit=False) as cur:
        cur.execute("SELECT encrypted_record, ipfs_cid FROM patients WHERE profile_code=%s",
                    (patient_code,))
        row = cur.fetchone()
    assert row["encrypted_record"] is not None and row["ipfs_cid"] is None
    assert not client.pins

