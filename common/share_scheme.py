"""Portable cryptographic operations for per-share snapshots.

This module deliberately has no Flask, database, or filesystem dependencies.
It can run in a client that owns the relevant private key.
"""

import base64
from datetime import datetime, timezone

from common.crypto_utils import (
    aesgcm_decrypt,
    aesgcm_encrypt,
    generate_aes_key,
    rsa_sign,
    rsa_unwrap_key,
    rsa_verify,
    rsa_wrap_key,
)


class ShareError(Exception):
    """Base error for invalid or inaccessible shares."""


class ShareExpired(ShareError):
    """The share's client-checked expiry has passed."""


class ShareTampered(ShareError):
    """The package is malformed, unsupported, or failed integrity checks."""


class ShareWrongRecipient(ShareError):
    """The share was addressed to a different doctor."""


def _validate_fields(share_id, patient_code, doctor_code, expires_at_iso):
    for name, value in (("share_id", share_id), ("patient_code", patient_code),
                        ("doctor_code", doctor_code), ("expires_at", expires_at_iso)):
        if not isinstance(value, str) or not value:
            raise ShareError(f"{name} must be a non-empty string")
        if "|" in value:
            raise ShareError(f"{name} must not contain '|'")
    try:
        _parse_datetime(expires_at_iso)
    except (TypeError, ValueError) as exc:
        raise ShareError("expires_at must be an ISO-8601 datetime") from exc


def _parse_datetime(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def _aad(share_id, patient_code, doctor_code, expires_at_iso):
    _validate_fields(share_id, patient_code, doctor_code, expires_at_iso)
    return f"v1|{share_id}|{patient_code}|{doctor_code}|{expires_at_iso}".encode("utf-8")


def _signature_payload(aad, nonce, ciphertext, wrapped_key):
    # Sign the decoded bytes represented by each base64 wire field.
    try:
        return aad + b"".join(base64.b64decode(value, validate=True)
                              for value in (nonce, ciphertext, wrapped_key))
    except (ValueError, TypeError) as exc:
        raise ShareTampered("share contains invalid base64 data") from exc


def create_share(plaintext: bytes, patient_private_key, doctor_public_key,
                 share_id, patient_code, doctor_code, expires_at_iso, version=1) -> dict:
    """Encrypt and sign one immutable snapshot for one named doctor."""
    if type(version) is not int or version != 1:
        raise ShareError("unsupported share version")
    if not isinstance(plaintext, bytes):
        raise ShareError("plaintext must be bytes")
    aad = _aad(share_id, patient_code, doctor_code, expires_at_iso)
    one_time_key = generate_aes_key()
    try:
        encrypted = aesgcm_encrypt(one_time_key, plaintext, aad=aad)
        wrapped_key = rsa_wrap_key(doctor_public_key, one_time_key)
        signature = rsa_sign(
            patient_private_key,
            _signature_payload(aad, encrypted["nonce"], encrypted["ciphertext"], wrapped_key),
        )
        return {
            "share_id": share_id,
            "version": version,
            "patient_code": patient_code,
            "doctor_code": doctor_code,
            "expires_at": expires_at_iso,
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
            "wrapped_key": wrapped_key,
            "signature": signature,
        }
    finally:
        # Python bytes are immutable; drop our reference promptly after use.
        one_time_key = None


def open_share(share: dict, doctor_private_key, patient_public_key,
               expected_doctor_code, now=None) -> bytes:
    """Verify and decrypt a share, including an honest-client expiry check."""
    try:
        if not isinstance(share, dict) or type(share.get("version")) is not int or share.get("version") != 1:
            raise ShareTampered("unsupported or malformed share version")
        if expected_doctor_code != share.get("doctor_code"):
            raise ShareWrongRecipient("share is addressed to another doctor")
        expiry = _parse_datetime(share["expires_at"])
        current = now or datetime.now(timezone.utc)
        if isinstance(current, str):
            current = _parse_datetime(current)
        elif not isinstance(current, datetime):
            raise ValueError("now must be a datetime or ISO-8601 string")
        elif current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        if expiry <= current.astimezone(timezone.utc):
            raise ShareExpired("share has expired")

        aad = _aad(share["share_id"], share["patient_code"],
                   share["doctor_code"], share["expires_at"])
        signed = _signature_payload(aad, share["nonce"], share["ciphertext"], share["wrapped_key"])
        if not rsa_verify(patient_public_key, signed, share["signature"]):
            raise ShareTampered("patient signature verification failed")
        one_time_key = rsa_unwrap_key(doctor_private_key, share["wrapped_key"])
        try:
            return aesgcm_decrypt(one_time_key, share["nonce"], share["ciphertext"], aad=aad)
        finally:
            one_time_key = None
    except (ShareExpired, ShareWrongRecipient, ShareTampered):
        raise
    except Exception as exc:
        raise ShareTampered("share could not be verified or decrypted") from exc
