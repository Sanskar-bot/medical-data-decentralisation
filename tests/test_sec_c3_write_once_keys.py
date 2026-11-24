"""[C3] Public keys are write-once and records must carry a valid signature."""
import os

import pytest

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}


@pytest.fixture(scope="module")
def keys():
    from common.crypto_utils import generate_rsa_keypair, rsa_serialize_public
    a_priv, a_pub = generate_rsa_keypair(2048)
    b_priv, b_pub = generate_rsa_keypair(2048)
    return (a_priv, rsa_serialize_public(a_pub).decode()), (b_priv, rsa_serialize_public(b_pub).decode())


def _record(priv, pem, code):
    from common.crypto_utils import rsa_sign
    enc = {"nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVy"}
    sig = rsa_sign(priv, (enc["nonce"] + "|" + enc["ciphertext"]).encode())
    return {"profile_code": code, "encrypted_record": enc, "signature": sig, "patient_public_pem": pem}


def test_unsigned_or_badly_signed_record_rejected(client, clean_db, keys):
    (a_priv, a_pem), (b_priv, _) = keys
    body = _record(b_priv, a_pem, "PCODE1")
    assert client.post("/register_user", headers=API, json=body).status_code == 400
    body["signature"] = ""
    assert client.post("/register_user", headers=API, json=body).status_code == 400


def test_patient_key_cannot_be_swapped(client, clean_db, keys):
    (a_priv, a_pem), (b_priv, b_pem) = keys
    assert client.post("/register_user", headers=API, json=_record(a_priv, a_pem, "PCODE2")).status_code == 200
    assert client.post("/register_user", headers=API, json=_record(a_priv, a_pem, "PCODE2")).status_code == 200
    assert client.post("/register_user", headers=API, json=_record(b_priv, b_pem, "PCODE2")).status_code == 409


def test_doctor_key_cannot_be_swapped(client, clean_db, keys):
    (_, a_pem), (_, b_pem) = keys
    body = {"doctor_id": "d-1", "doctor_code": "DCODE1", "public_pem": a_pem}
    assert client.post("/register_doctor", headers=API, json=body).status_code == 200
    assert client.post("/register_doctor", headers=API, json=body).status_code == 200
    body["public_pem"] = b_pem
    assert client.post("/register_doctor", headers=API, json=body).status_code == 409
