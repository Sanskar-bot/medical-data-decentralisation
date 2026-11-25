"""Real-Kubo integration and ciphertext-at-rest sentinel tests."""

import base64
import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("IPFS_INTEGRATION") != "1",
    reason="requires the dedicated real-Kubo CI job",
)


def _jwt(app, role, code):
    from server import _jwt_encode
    claims = {"sub": code, "uid": code, "role": role, "exp": time.time() + 3600}
    claims["profile_code" if role == "patient" else "doctor_code"] = code
    return {"Authorization": "Bearer " + _jwt_encode(claims), "Content-Type": "application/json"}


def _pg_dump_text():
    database_url = os.environ["TEST_DATABASE_URL"]
    parsed = urlparse(database_url)
    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = unquote(parsed.password)
    result = subprocess.run([
        "pg_dump", "--no-owner", "--no-privileges",
        "-h", parsed.hostname or "127.0.0.1",
        "-p", str(parsed.port or 5432),
        "-U", unquote(parsed.username or ""),
        unquote(parsed.path.lstrip("/")),
    ], check=True, capture_output=True, env=env)
    return result.stdout


def _assert_absent_from_kubo_volume(marker: bytes):
    roots = [Path(os.environ["KUBO_DATA_DIR"])]
    replica = os.environ.get("KUBO_REPLICA_DATA_DIR")
    if replica:
        roots.append(Path(replica))
    for root in roots:
        assert root.exists(), f"Kubo data volume not mounted at {root}"
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    assert marker not in path.read_bytes(), f"plaintext sentinel found in {path.name}"
                except PermissionError as exc:
                    raise AssertionError(f"Cannot inspect Kubo data file {path}") from exc


def test_real_kubo_registration_and_share_ciphertext_have_no_plaintext_leaks(
    client, app, clean_db
):
    from common.crypto_utils import (
        aesgcm_encrypt, generate_aes_key, generate_rsa_keypair,
        rsa_serialize_public, rsa_sign,
    )
    from common.share_scheme import create_share, open_share
    from common.crypto_utils import rsa_load_public

    sentinel = ("MEDVAULT_IPFS_SENTINEL_" + uuid.uuid4().hex).encode("ascii")
    patient_private, patient_public = generate_rsa_keypair(2048)
    doctor_private, doctor_public = generate_rsa_keypair(2048)
    patient_code = "PAT-IPFS-CI-" + uuid.uuid4().hex
    doctor_code = "DOC-IPFS-CI-" + uuid.uuid4().hex
    doctor_id = str(uuid.uuid4())
    public_pem = rsa_serialize_public(patient_public).decode("utf-8")

    envelope = aesgcm_encrypt(generate_aes_key(), json.dumps({
        "note": sentinel.decode("ascii"),
    }).encode("utf-8"))
    signature = rsa_sign(
        patient_private,
        (envelope["nonce"] + "|" + envelope["ciphertext"]).encode("utf-8"),
    )
    registered = client.post("/register_user", headers={"X-API-Key": os.environ["SERVER_API_KEY"]}, json={
        "profile_code": patient_code,
        "encrypted_record": envelope,
        "signature": signature,
        "patient_public_pem": public_pem,
    })
    assert registered.status_code == 200, registered.get_json()

    from db import db_cursor
    with db_cursor() as cur:
        cur.execute("INSERT INTO doctors (doctor_code, doctor_id, public_pem) VALUES (%s,%s,%s)",
                    (doctor_code, doctor_id, rsa_serialize_public(doctor_public).decode()))
        cur.execute("SELECT encrypted_record, ipfs_cid, ciphertext_sha256, ciphertext_size FROM patients WHERE profile_code=%s",
                    (patient_code,))
        registration_row = cur.fetchone()
    assert registration_row["encrypted_record"] is None
    assert registration_row["ipfs_cid"] and registration_row["ciphertext_sha256"]

    fetched_registration = client.get(
        f"/get_patient_data/{patient_code}",
        headers={"X-API-Key": os.environ["SERVER_API_KEY"], **_jwt(app, "patient", patient_code)},
    )
    assert fetched_registration.status_code == 200, fetched_registration.get_json()
    assert fetched_registration.get_json()["encrypted_record"] == envelope

    share_id = str(uuid.uuid4())
    ttl = 3600
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
    package = create_share(sentinel, patient_private, doctor_public,
                           share_id, patient_code, doctor_code, expiry)
    created_share = client.post("/shares", headers=_jwt(app, "patient", patient_code), json={
        **package, "label": "Integration snapshot", "expires_in_seconds": ttl,
    })
    assert created_share.status_code == 201, created_share.get_json()

    fetched_share = client.get(f"/shares/{share_id}", headers=_jwt(app, "doctor", doctor_code))
    assert fetched_share.status_code == 200, fetched_share.get_json()
    share_bytes = base64.b64decode(fetched_share.get_json()["share"]["ciphertext"])
    fetched_package = dict(fetched_share.get_json()["share"])
    fetched_package["ciphertext"] = base64.b64encode(share_bytes).decode("ascii")
    assert open_share(fetched_package, doctor_private,
                      rsa_load_public(public_pem.encode()), doctor_code) == sentinel

    assert sentinel not in _pg_dump_text()
    _assert_absent_from_kubo_volume(sentinel)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["ipfs"] == "ok"


@pytest.mark.skip(reason="requires Phases 1-5 (client-side EMR encryption)")
def test_ui_emr_sentinel_absent_from_postgres_and_kubo_volume():
    """Deferred gate: add a browser-driven encrypted EMR write in Phases 1-5."""
