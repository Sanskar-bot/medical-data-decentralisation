# Per-share snapshot implementation plan

## Files

- Add `common/share_scheme.py` and `common/test_share_scheme.py` for portable encryption, recipient key wrapping, signing, verification, expiry checks, and unit tests.
- Add `shares` and its indexes to `server/schema_additions.sql`; this repository applies that migration file after `schema.sql`.
- Add JWT-protected share endpoints, expiry purge logic, and hourly cleanup integration in `server/server.py`.
- Add `tests/test_shares_api.py` using the existing Flask test client and database fixtures.
- Add `client/share_demo.py` as a local demonstration.
- Update `docs/THREAT_MODEL.md`, `docs/PAPER_SECTION_THREAT_MODEL.md`, `README.md`, and `CHANGES.md` with scoped, honest documentation.

## Message format

The JSON package has `share_id`, integer `version`, `patient_code`, `doctor_code`, ISO-8601 UTC `expires_at`, and base64 `nonce`, `ciphertext`, `wrapped_key`, and `signature`. Associated data is UTF-8 encoding of `v1|share_id|patient_code|doctor_code|expires_at`; those fields may not contain `|`. A fresh AES-256 key encrypts the selected snapshot with AES-GCM and that associated data. The key is RSA-OAEP wrapped to the named doctor's public key. The patient signs associated data concatenated with the nonce, ciphertext, and wrapped key using RSA-PSS. The database stores only the encrypted package and metadata. Current portals still handle private keys and plaintext, so this is not end-to-end encryption.

## Endpoints

- `POST /shares`: patient creates a bounded-lifetime share for a registered doctor.
- `GET /shares/<share_id>`: the named doctor fetches an active share and patient public key.
- `GET /shares/incoming`: doctor lists metadata for active incoming shares.
- `GET /shares/outgoing`: patient lists their share metadata and status.
- `DELETE /shares/<share_id>`: owning patient revokes a share and clears stored blobs.
