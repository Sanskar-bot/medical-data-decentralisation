import base64
from datetime import datetime, timedelta, timezone

import pytest

from common.crypto_utils import generate_rsa_keypair
from common.share_scheme import (
    ShareExpired,
    ShareError,
    ShareTampered,
    ShareWrongRecipient,
    create_share,
    open_share,
)


@pytest.fixture(scope="module")
def keys():
    patient_private, patient_public = generate_rsa_keypair(2048)
    doctor_private, doctor_public = generate_rsa_keypair(2048)
    other_private, _ = generate_rsa_keypair(2048)
    return patient_private, patient_public, doctor_private, doctor_public, other_private


def make_share(keys, **overrides):
    patient_private, _, _, doctor_public, _ = keys
    fields = {
        "plaintext": b"selected snapshot",
        "patient_private_key": patient_private,
        "doctor_public_key": doctor_public,
        "share_id": "share-1",
        "patient_code": "patient-1",
        "doctor_code": "doctor-1",
        "expires_at_iso": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }
    fields.update(overrides)
    return create_share(**fields)


def test_round_trip(keys):
    _, patient_public, doctor_private, _, _ = keys
    share = make_share(keys)
    assert open_share(share, doctor_private, patient_public, "doctor-1") == b"selected snapshot"


def test_wrong_doctor_identity_is_refused(keys):
    _, patient_public, doctor_private, _, _ = keys
    with pytest.raises(ShareWrongRecipient):
        open_share(make_share(keys), doctor_private, patient_public, "doctor-2")


def test_wrong_doctor_key_fails(keys):
    _, patient_public, _, _, other_private = keys
    with pytest.raises(ShareTampered):
        open_share(make_share(keys), other_private, patient_public, "doctor-1")


def test_modified_ciphertext_fails(keys):
    _, patient_public, doctor_private, _, _ = keys
    share = make_share(keys)
    raw = bytearray(base64.b64decode(share["ciphertext"]))
    raw[0] ^= 1
    share["ciphertext"] = base64.b64encode(raw).decode()
    with pytest.raises(ShareTampered):
        open_share(share, doctor_private, patient_public, "doctor-1")


@pytest.mark.parametrize("field,value", [
    ("expires_at", (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()),
    ("doctor_code", "doctor-2"),
    ("share_id", "share-2"),
])
def test_modified_bound_fields_fail(keys, field, value):
    _, patient_public, doctor_private, _, _ = keys
    share = make_share(keys)
    share[field] = value
    with pytest.raises(ShareTampered):
        open_share(share, doctor_private, patient_public, share["doctor_code"])


def test_expired_share_is_refused_before_decryption(keys):
    _, patient_public, doctor_private, _, _ = keys
    share = make_share(keys, expires_at_iso="2020-01-01T00:00:00+00:00")
    with pytest.raises(ShareExpired, match="expired"):
        open_share(share, doctor_private, patient_public, "doctor-1")


def test_bad_signature_is_refused(keys):
    _, patient_public, doctor_private, _, _ = keys
    share = make_share(keys)
    share["signature"] = base64.b64encode(b"invalid").decode()
    with pytest.raises(ShareTampered, match="signature"):
        open_share(share, doctor_private, patient_public, "doctor-1")


def test_delimiter_in_bound_field_is_rejected(keys):
    with pytest.raises(ShareError, match=r"\|"):
        make_share(keys, patient_code="patient|other")


def test_shares_of_same_plaintext_use_distinct_key_material(keys):
    _, patient_public, doctor_private, _, _ = keys
    first, second = make_share(keys), make_share(keys)
    assert first["nonce"] != second["nonce"]
    assert first["wrapped_key"] != second["wrapped_key"]
    assert open_share(first, doctor_private, patient_public, "doctor-1") == b"selected snapshot"
    assert open_share(second, doctor_private, patient_public, "doctor-1") == b"selected snapshot"
