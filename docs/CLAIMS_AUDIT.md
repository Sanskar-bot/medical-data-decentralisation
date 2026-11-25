# Claims Audit

Systematic review of all security- and architecture-related claims in the repository.
Performed against the current codebase as of this writing.

## Current IPFS facts

The project uses a private, offline Kubo/IPFS store for **encrypted patient registration records and per-share snapshot ciphertext only**. PostgreSQL stores their CIDs, SHA-256 digests, sizes, wrapped keys and metadata. Kubo's API is internal to the Docker network and its HTTP gateway is loopback-only. EMR profiles, prescriptions, vitals, notes, labs, conditions, encounters and appointments remain plaintext in PostgreSQL. Portal servers handle keys and encryption. Unpinning does not guarantee deletion from copies already fetched or backed up.

## Methodology

Searched the entire repository for the terms: `zero-trust`, `end-to-end` / `E2E`, `decentralized` / `decentralised`, `distributed storage`, `IPFS`, `blockchain`, `only manage encrypted metadata`, `fully control`, `24-hour` / `24 hours`, `time-limited`, `auto-expire`, `all 25 security issues`, `HIPAA`, `FHIR`, `compliant`, `submitted`, `published`, `conference`.

## Current corrections

The README status section now includes per-share snapshots among encrypted payloads, describes the remaining plaintext EMR data, and no longer states that API-key comparison uses `!=`. `server._require_api_key`, `server._jwt_decode`, and the portal API-key check use `hmac.compare_digest`; RSA package signatures are verified with `rsa_verify`. The former permanent patient-wide authorship grant was removed: `server._doctor_has_active_access` delegates to `authorize_patient_access`, which accepts approved `access_db` rows or unexpired wrapped-key grants. `access_db` approval expiry remains open. Entries below preserve older quoted claims for audit history; they do not describe the current behavior where the evidence has since changed.

## Audit Table

### README.md

| File | Line | Original Text | Verdict | Evidence | Suggested Replacement |
|------|------|---------------|---------|----------|-----------------------|
| README.md | 1 | `# 🏥 Decentralized Healthcare Data Management System` | **Overclaim** | The system is centralized Flask+Postgres with a private offline Kubo store used only for registration and share ciphertext. | `# 🏥 MedVault — Consent-Based Sharing for Encrypted Patient Records` |
| README.md | 15 | `secure, end-to-end encrypted platform that decentralizes medical data ownership` | **Overclaim** | Encryption/decryption occurs in the portal servers, not on the patient's device (`portals/patient_portal.py:api_register` L102–109, `portals/landing.py` L653–693). The portals handle private keys and plaintext. Most EMR data (notes, prescriptions, vitals, etc.) is stored as plaintext columns (`server/schema.sql` L138–407). | `a research prototype of consent-based sharing for encrypted patient records` |
| README.md | 16 | `[claim of full patient control]` | **Overclaim** | The portal server and DB admin can read private keys and plaintext EMR data. The patient does not hold keys on their own device in the current implementation. | `Patients authorize access to their records via consent-based key sharing` |
| README.md | 16 | `only with consent for a limited time` | **Partially Accurate** | Consent is required (`/request_access_simple`, `/approve_request`). Time-limiting: `temp_key_expires_at` checked in `_db_get_wrapped_key` (`server/server.py`), and `responded_at > NOW() - INTERVAL '24 hours'` in `landing.py` L3382. However the `access_db` table itself has no expiry column (`schema.sql` L181–191), and `_doctor_has_active_access` grants permanent implicit access if the doctor ever wrote EMR data (`server/server.py` check #3: `emr_prescriptions`/`emr_lab_reports`). The actual data key K_data, once decrypted, cannot be un-known. | `Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.` |
| README.md | 52 | `distributed storage (like IPFS or hybrid clouds)` | **Inaccurate** | Private Kubo/IPFS stores encrypted registration and share ciphertext only; EMR clinical data remains in PostgreSQL (`docker-compose.yml` L1–17). | Remove entirely, or replace with: `The current prototype uses a centralized PostgreSQL database. Distributed storage is a planned future direction.` |
| README.md | 53 | `servers only manage encrypted metadata` | **Inaccurate** | The server stores plaintext: `doctor_notes.note_text` (L146), `emr_profiles.*` (L215–227), `emr_prescriptions.diagnosis/medications/notes` (L288–298), `emr_lab_reports.results/notes` (L302–313), `conditions.description/notes` (L344–358), `vitals.*` (L372–388), `encounters.reason/summary` (L392–407) — all in `server/schema.sql`. | `The server stores the patient's initial registration record as an encrypted blob; most clinical data added later (notes, prescriptions, vitals, lab results) is currently stored in plaintext.` |
| README.md | 65 | `RSA/ECC` | **Partially Inaccurate** | RSA-4096 OAEP is used (`common/crypto_utils.py` L74, L100–120). No ECC code exists. | `RSA-4096 OAEP` |
| README.md | 66 | `IPFS / Hybrid Cloud` for Storage | **Partially accurate** | PostgreSQL stores metadata; private Kubo/IPFS stores registration and share ciphertext only. | `PostgreSQL + private Kubo/IPFS ciphertext store (limited scope)` |
| README.md | 84 | `Doctor requests temporary (24-hour) access` | **Partially Accurate** | The `temp_key_expires_at` timestamp is set to 24 hours (`patient_portal.py:api_approve`). The server SQL query in `_db_get_wrapped_key` checks `temp_key_expires_at > now()`. However, once the doctor decrypts the temp key T and recovers K_data, the 24-hour window cannot prevent re-use of K_data. JWT-based approvals have no expiry. | `Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.` |
| README.md | 87 | `auto-expire after a set duration` | **Overclaim** | Only the `wrapped_keys.temp_key_expires_at` column is checked server-side. The server does not delete the wrapped key row. No auto-expiry background job deletes or invalidates these entries. Prescriptions have no expiry at all. | Remove or note: `The server stops serving the wrapped key after the timestamp expires; no automatic deletion occurs.` |
| README.md | 95 | `Servers only hold data for a short window (e.g., 24 hours)` | **Inaccurate** | Plaintext clinical data is stored permanently in Postgres. `encrypted_record` in the `patients` table is permanent. No auto-delete job exists. | Remove this claim. |
| README.md | 97 | `End-to-End Encryption — AES-GCM for confidentiality, RSA/ECC for secure sharing` | **Overclaim** | Only `patients.encrypted_record` is encrypted. The portal server decrypts and handles keys. No ECC is used. | `Hybrid encryption for the initial patient registration record (AES-256-GCM + RSA-4096 OAEP); most clinical data is not yet encrypted.` |

### CHANGES.md

| File | Line | Original Text | Verdict | Evidence | Suggested Replacement |
|------|------|---------------|---------|----------|-----------------------|
| CHANGES.md | 3 | `All 25 security issues have been remediated` | **Overclaim** | Open items include: `approve_request` caller authorization, `access_db` expiry, per-grant keys, plaintext EMR data, server-side key generation, password-derived key backup, and unused Argon2 function. H7's timing-compare issue and H8 are fixed. | `25 identified issues were addressed as described below. Some systemic design limitations remain; see docs/THREAT_MODEL.md.` |
| H8 | `api_register` function-level re-import | **CONFIRMED** | The function-level import makes `derive_kek_from_password` and `wrap_key_with_kek` local variables throughout `api_register`; calls before the import raise `UnboundLocalError` by Python scoping rules. This has not been run against a live server. | Fixed in Stage 3 by removing only the function-level re-import. |
| CHANGES.md | 15 (C2) | `AES-256-GCM encryption using an Argon2id machine-derived key` | **Accurate for secure_key_store.py** | `common/secure_key_store.py` L130–145 uses `argon2.low_level.hash_secret_raw` with `Type.ID` for the machine-key derivation in the Linux fallback. | No change needed. |
| CHANGES.md | 69–71 (M3) | Claims `derive_kek_argon2()` added and old one deprecated | **Accurate as written, but misleading by omission** | The function exists (`crypto_utils.py` L192–214). But zero call sites use it. All runtime KEK derivation uses `derive_kek_from_password` (PBKDF2): `patient_portal.py` L15/L108, `landing.py` L692, `share_details.py` L38/L74, `respond_request.py` L34/L92/L109/L161. | Add: `Note: derive_kek_argon2() is currently unused at runtime. All key-wrapping call sites still use the deprecated PBKDF2-based derive_kek_from_password(). Migration is incomplete.` |

### START.py

| File | Line | Original Text | Verdict | Evidence | Suggested Replacement |
|------|------|---------------|---------|----------|-----------------------|
| START.py | 109 | `Zero-Trust Health Portal` | **Overclaim** | The portal servers are fully trusted — they generate keys, perform encryption, hold private keys in memory, and can read all plaintext. This is the opposite of zero-trust. | `MedVault — Health Portal` (template/UI only — not edited per rules; listed here for author awareness) |

### Templates and UI files (not edited — listed for reference)

| File | Line | Original Text | Verdict | Evidence | Suggested Replacement |
|------|------|---------------|---------|----------|-----------------------|
| portals/templates/landing.html | 35 | `Zero-Trust Medical Platform` | **Overclaim** | See START.py entry above. | `Consent-Based Sharing Prototype` |
| portals/templates/landing.html | 120 | `Access is time-limited to 24 hours and every event is audit-logged` | **Partially Accurate** | Wrapped-key access has a server-side expiry; JWT-based approvals (`access_db`) currently have no expiry. Audit logging exists (`audit_log` table). | `Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.` |
| portals/templates/landing.html | 214 | `A zero-trust medical records platform built for patient sovereignty` | **Overclaim** | See above. | `A research prototype of consent-based sharing for encrypted patient records` |
| portals/templates/landing.html | 235 | `All records are encrypted end-to-end` | **Inaccurate** | Most clinical data is stored in plaintext (see README L53 audit entry). | `Patient registration records are encrypted; clinical data encryption is planned.` |
| portals/templates/dashboard.html | 67 | `Encrypted in transit and at rest with zero-trust access controls` | **Overclaim** | In-transit: TLS is configured in nginx. At-rest encryption: only the `encrypted_record` blob. Zero-trust: not applicable. | `Encrypted in transit (TLS). Registration record encrypted at rest.` |
| portals/templates/dashboard.html | 217 | `Zero-trust, review-first approvals` | **Overclaim** | Approvals are consent-based, but zero-trust does not apply. | `Consent-based, review-first approvals` |
| portals/templates/partials/sidebar.html | 6 | `Zero-Trust Health Platform` | **Overclaim** | See above. | `Consent-Based Health Platform` |
| portals/templates/emr.html | 96 | `Sensitive records remain end-to-end encrypted separately` | **Overclaim** | Only `patients.encrypted_record` is encrypted. EMR profiles, vitals, prescriptions, etc. are plaintext in the database. | `The initial patient registration record is encrypted separately.` |
| portals/templates/health_record.html | 10 | `End-to-end encrypted personal health record` | **Overclaim** | The portal server decrypts on behalf of the patient. Not end-to-end. | `Encrypted personal health record (server-mediated decryption)` |
| portals/templates/profile.html | 56 | `AES-256-GCM (end-to-end)` | **Overclaim** | AES-256-GCM is used for the registration record, but decryption happens on the portal server. | `AES-256-GCM (server-side decryption)` |
| portals/templates/access_requests.html | 60 | `Access is valid for 24 hours` | **Partially Accurate** | Server-side enforcement exists. Cryptographic revocation does not. | Keep, but note elsewhere that the guarantee is server-enforced only. |
| portals/patient_ui.html | 832 | `End-to-End Encrypted` | **Overclaim** | See above. | `Encrypted` |
| portals/patient_ui.html | 842 | `Zero-Trust` | **Overclaim** | See above. | Remove or replace with `Consent-Based` |
| portals/patient_ui.html | 1037 | `Zero-Trust Storage` | **Overclaim** | See above. | `Encrypted Storage` |
| portals/patient_ui.html | 1049 | `Doctor access auto-expires in 24 hours` | **Partially Accurate** | Wrapped-key access expires server-side. JWT-based approvals have no expiry, and cryptographic revocation is not possible after key decryption. | `Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.` |
| portals/patient_ui.html | 1169 | `Decentralised storage` | **Inaccurate** | No decentralised storage. | `Encrypted storage` |

### Code comments (not edited — listed for reference)

| File | Line | Original Text | Verdict | Evidence | Suggested Replacement |
|------|------|---------------|---------|----------|-----------------------|
| portals/landing.py | 653 | `Generate RSA keypair for decentralized data` | **Misleading** | The keypair is generated server-side in the portal, not on a patient device. Data is stored in a centralized Postgres DB. | `Generate RSA keypair for patient record encryption` |
| portals/landing.py | 2301 | `Notes are deleted from the server once patient views them (decentralised` | **UNVERIFIED** | Would need to verify the note-deletion endpoint. The term "decentralised" is incorrect regardless. | Remove "decentralised" qualifier. |
| server/server.py | 5 | `Decentralised medical-data server` | **Overclaim** | Centralized server. | `Medical-data server (research prototype)` |
| common/test_crypto.py | 16 | `My secret FHIR record` | **Not a claim** | Test data string. No FHIR implementation. | No change needed; it's a test fixture. |

## Summary

- **Fixed:** H7 timing comparison now uses `hmac.compare_digest`; H8's function-local re-import was removed after confirmation that it caused `UnboundLocalError` by Python scoping rules. The H8 failure mode was not run against a live server.
- **Remaining open items:** `approve_request` caller check, `access_db` expiry, per-grant keys, plaintext EMR data, server-side key generation, password-derived key backup, and the unused Argon2 function.

- **Terms never found in code or logic:** `HIPAA`, `compliant`, `blockchain` (outside text), `published`, `conference`
- **Terms found in implementation and docs:** `IPFS` (private ciphertext store for registration and share records only)
- **Terms found only in aspirational text, not code:** `distributed storage`, `zero-trust`, `decentralized/decentralised` (as architecture), `end-to-end encrypted` (as a system-wide property)
- **Accurate claims:** AES-256-GCM encryption exists, RSA-4096 key wrapping exists, consent-based sharing exists, 24-hour server-side expiry exists
- **Systemic gap:** EMR clinical data remains plaintext in PostgreSQL; server-mediated encryption is not end-to-end protection.

