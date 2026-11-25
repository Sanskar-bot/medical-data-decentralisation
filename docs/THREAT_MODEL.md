# Threat Model — MedVault

> **Scope:** This document describes the security properties of the *current prototype* as implemented.
> Claims about the planned phone-first design are clearly marked **PLANNED, NOT IMPLEMENTED**.
> Every claim about current behaviour cites a source file and function or line number.

The patient's registration record and per-share snapshots are encrypted. Most clinical data added later (notes, prescriptions, vitals, lab results) is stored in plaintext. Encryption and key handling currently happen in the portal server. Wrapped-key access has a 24-hour server-side expiry; approved grants in `access_db` currently have no expiry in backend authorization checks. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.

## Private IPFS ciphertext store

Kubo/IPFS stores only the ciphertext bytes for encrypted patient registration records and per-share snapshot packages. PostgreSQL stores each registration CID, ciphertext SHA-256 and size alongside the patient public key and signature. For shares, PostgreSQL stores the CID, ciphertext SHA-256 and size, expiry/identity metadata, wrapped key and signature. Fetches verify the returned bytes against both the stored SHA-256 and a locally recalculated CID before returning ciphertext; a mismatch or unavailable node fails closed with HTTP 503. The signature already present on each ciphertext package remains the client-side authenticity check.

The optional inline-size threshold is **not implemented**; in-scope payloads are stored on IPFS regardless of size. The current v1 registration/share signatures do not bind the stored CID or SHA-256 into AAD or the signed package. Protection comes from the signature over the ciphertext bytes and fetch-time SHA-256/CID verification. Doctor registration-record fetch now verifies the signature before decrypting; share clients use the v1 package verifier before decrypting.

The Kubo primary and replica run offline with bootstrap peers removed. The HTTP gateway binds to loopback inside each container; the RPC API is reachable only from the private internal Docker network by the backend and maintenance worker. Configurable pin targets are private Kubo APIs. Pin state is tracked per target, and the maintenance worker repairs missing pins, delays orphan removal to avoid racing writes, and runs repository garbage collection on a schedule. The `ipfs_data` and `ipfs_replica_data` Docker volumes must be included in backups; restore both volumes together with the matching PostgreSQL metadata and verify CIDs before reopening service.

The maintenance worker migrates legacy inline registration and share ciphertext in batches. Until migration completes, those legacy encrypted bytes can remain in PostgreSQL. The patient registration deletion endpoint removes that patient's registration record and share metadata/pins; it does not delete plaintext EMR data or the patient account. A separate, broader patient deletion workflow remains out of scope.

IPFS provides content addressing, integrity checking, deduplication and portability between private Kubo nodes. It does not provide anonymity or guaranteed deletion. Unpinning plus repository garbage collection removes this service's live references, but cannot remove copies fetched by another party or copies preserved in backups, snapshots or logs. This is a private ciphertext store, not public decentralisation.

## Per-share snapshot scheme

New snapshot shares encrypt only the patient-selected snapshot with a fresh one-time key. The patient's permanent data key is never sent to the doctor. Each share has its own key; the expiry, share ID, patient ID, and doctor ID are bound to the ciphertext and covered by the patient's signature. The server stores the encrypted snapshot on private IPFS and keeps its CID, SHA-256, size, wrapped key, signature and expiry metadata in PostgreSQL. Expiry/revocation clears the metadata and unpins from configured nodes; this does not erase any copy already fetched or retained elsewhere.

This scheme assumes doctors follow the protocol and do not intentionally copy or leak data. A doctor who already decrypted a snapshot can retain it. Screenshots and a compromised doctor device are outside the protection provided here. Database backups, WAL, replicas, and logs may retain old ciphertext and wrapped keys. The server sees metadata about who shared with whom and when. Doctor identity verification is not implemented. In the current deployment, the patient and doctor portals run server-side and handle private keys and plaintext, so the server is not blind to plaintext. The portable crypto module could later run in native patient and doctor clients; no such client is implemented here. This is not end-to-end encryption.

**Key authenticity remains an open issue.** The API returns `patient_public_pem` to the doctor, and the patient gets the doctor's public key from the server's directory. A malicious or compromised server could substitute either key. A signature verified under a supplied patient key proves only that the package matches that key; RSA wrapping to a supplied doctor key does not prove that the key belongs to the named doctor. Before a future client design makes stronger privacy claims, clients need an authenticated binding between identities and keys. Candidate approaches include out-of-band fingerprint comparison, key pinning on first contact (which does not protect the first contact), or keys certified through a registry-verified doctor identity process. None is implemented.

---

## 1. Scope and System Overview

### Components

| Component | Technology | Role |
|-----------|-----------|------|
| Backend API server | Flask (Python), Gunicorn | REST API, authentication (JWT), data storage, access control |
| PostgreSQL database | Postgres 16 | Persistent storage for all tables |
| Patient portal | Flask (Python), Gunicorn | Server-side web application for patients; generates RSA keys, performs encryption/decryption |
| Doctor portal | Flask (Python), Gunicorn | Server-side web application for doctors |
| Landing portal | Flask (Python), Gunicorn | Unified entry point; also handles registration and some doctor workflows |
| Nginx reverse proxy | Nginx (Alpine) | TLS termination, hostname-based routing |
| Client scripts | Python CLI | Standalone scripts for patient key sharing (`client/share_details.py`, `client/respond_request.py`) |

All components run in Docker containers on a single host (`docker-compose.yml`).

### Data Flow: Patient Registration

1. Patient submits name, email, password via the portal UI.
2. The **portal server** (not the patient's browser) generates an RSA-4096 keypair and a 32-byte AES-256 data key K_data (`portals/patient_portal.py:api_register` L102–103, `portals/landing.py` L653–693).
3. The portal encrypts the patient's basic record (name, age, email, notes) with K_data using AES-256-GCM (`aesgcm_encrypt`, L106/L690).
4. K_data is wrapped with a KEK derived from the patient's password using PBKDF2-SHA256 (200,000 iterations) (`derive_kek_from_password`, `crypto_utils.py` L179–190). The wrapped key and salt are stored in a local JSON file on the portal server.
5. The RSA private key is stored via `SecureKeyStore` — DPAPI on Windows, AES-256-GCM with an Argon2id machine-derived key on Linux (`secure_key_store.py` L130–171).
6. The RSA private key is also wrapped with a fresh PBKDF2-derived KEK and sent to the backend as `encrypted_private_key` for key-recovery purposes (`patient_portal.py` L111–123).
7. The encrypted record, public key PEM, and signature are posted to the backend (`/register_user`).
8. The backend stores these in the `patients` table as `encrypted_record` (JSONB), `patient_public_pem`, and `signature` (`server/schema.sql` L53–59).

### Data Flow: Consent-Based Sharing

1. Doctor submits an access request for a patient profile code (`/request_access_simple`, `server/server.py` L1820–1900).
2. The request is stored in `access_requests` with status `pending` (`schema.sql` L71–94).
3. Patient views pending requests in the portal. The portal server decrypts the doctor's encrypted profile using the patient's RSA private key (`patient_portal.py:api_requests` L194–214).
4. Patient approves: the portal server unwraps K_data from local storage using the patient's password, generates a temporary AES key T, encrypts K_data with T, wraps T with the doctor's RSA public key, and posts the result to `/approve_request` with a 24-hour `temp_key_expires_at` (`patient_portal.py:api_approve`).
5. The backend stores the wrapped key in `wrapped_keys` and updates the access request to `approved` (`server/server.py:approve_request` L1940–2000).

### Data Flow: Doctor Access

1. Doctor requests the patient's data. The backend checks `_doctor_has_active_access` (`server/server.py`), which delegates to `authorize_patient_access` (`server/authz.py`) and returns true if:
   - A non-expired entry exists in `wrapped_keys` (checks `temp_key_expires_at > now()`), **OR**
   - An `approved` row exists in `access_db` (no expiry check).
   - There is no patient-wide grant based on previous prescription or lab authorship. Specific record endpoints may authorize the doctor who authored that record, and only for that record.
2. If access is granted, the backend returns the wrapped key. The doctor's portal/client unwraps T with their RSA private key, then decrypts K_data with T.
3. The doctor can then decrypt the `encrypted_record` using K_data.
4. All EMR data (prescriptions, notes, vitals, etc.) is served as plaintext from the database — no decryption step is needed for these.

---

## 2. Assets

| Asset | Sensitivity | Storage Location |
|-------|------------|-----------------|
| Patient registration record and per-share snapshots | High | Ciphertext in private IPFS; PostgreSQL stores CIDs, SHA-256 digests, sizes, keys and metadata |
| EMR profiles, prescriptions, lab reports, conditions, vitals, encounters, doctor notes | High | `emr_profiles`, `emr_prescriptions`, `emr_lab_reports`, `conditions`, `vitals`, `encounters`, `doctor_notes` — **all plaintext** in Postgres |
| Patient RSA private key | Critical | Portal server filesystem (`SecureKeyStore`, DPAPI or AES-GCM), plus encrypted backup in `users.encrypted_private_key` |
| AES data key K_data | Critical | Wrapped in portal server's `user_data.json` (KEK from password via PBKDF2) |
| Patient login password | Critical | Hashed in `users.password_hash` (werkzeug `pbkdf2:sha256`). Also used to derive KEK — if intercepted, K_data can be unwrapped. |
| Doctor RSA private key | Critical | Portal server filesystem (`SecureKeyStore`) |
| Consent records | Medium | `access_requests`, `access_db`, `wrapped_keys` tables |
| Audit log | Medium | `audit_log` table (append-only by convention, `schema.sql` L316–328) |
| Metadata (who treats whom, access timestamps) | Medium | `access_requests`, `access_db`, `wrapped_keys`, `appointments` tables |
| JWT secrets | Critical | `server/jwt_secret.txt` or `JWT_SECRET` env var |
| Server API key | High | `SERVER_API_KEY` env var or `server/api_key.txt` |

---

## 3. Actors and Trust Assumptions

| Actor | Trust Level | Rationale |
|-------|------------|-----------|
| **Patient** | Trusted | The system is designed to serve the patient's interests. The patient chooses their password and authorizes access. |
| **Patient's device (browser)** | Semi-trusted | In the current deployment, the browser only submits forms. All crypto happens on the portal server. The browser trusts the portal server implicitly. |
| **Doctor** | Semi-trusted | Authorized to access data only with patient consent. However, once a doctor decrypts K_data, they possess it permanently. A malicious doctor can retain and re-use it. |
| **Doctor's device** | Semi-trusted | Same considerations as patient's device. |
| **Hospital / Operator** | Semi-trusted (effectively trusted in current design) | Runs the Docker stack. Has access to all container filesystems and the Postgres database. Can read all plaintext clinical data, all private keys (via `SecureKeyStore` file access or `/etc/machine-id`), and K_data (via the wrapped backup and password interception). |
| **Backend server process** | Trusted (by necessity in current design) | Handles JWTs, API keys, and all database writes. Receives the patient's password at login. Has access to all data. |
| **Portal server processes** | Trusted (by necessity in current design) | Generate RSA keys and K_data, perform encryption and decryption, handle the patient's password in memory (`patient_portal.py:api_register`, `api_approve`, `api_load_profile`). |
| **Database administrator** | Untrusted (should be, but effectively trusted) | Can read all plaintext EMR data directly. Can read `encrypted_record` and `wrapped_keys` but would need K_data or the patient's password to decrypt the registration blob. |
| **Network attacker (passive)** | Untrusted | Nginx enforces TLS 1.2+ (`nginx.conf` L45). HSTS is set. HTTP redirects to HTTPS. |
| **Network attacker (active, MitM)** | Untrusted | TLS mitigates if certificates are valid. Self-signed certs (`generate_certs.py`) in development weaken this. |
| **Malicious doctor** | Untrusted | Cannot be prevented from retaining decrypted K_data or plaintext data after legitimate access. Server-side expiry stops API access but not retained cryptographic material. |
| **Malicious insider (operator employee)** | Untrusted | Has all powers of the operator plus potential access to logs, backups, and the machine-id used for `SecureKeyStore` key derivation. |
| **Stolen/lost patient phone** | Not applicable in current design | The patient's phone is not used in the current implementation. The patient interacts via a web browser against the portal server. |

---

## 4. Current Implementation — Who Can See What

| Actor | Can Read Plaintext Clinical Data? | Can Read Private Keys? | Can Read K_data? | Evidence |
|-------|-----------------------------------|------------------------|------------------|----------|
| **Portal server** | Yes — decrypts `encrypted_record` in memory; serves plaintext EMR data from DB | Yes — loads from `SecureKeyStore` (`patient_portal.py` L196–197) | Yes — unwraps from `user_data.json` using patient's password (`api_approve`) | `patient_portal.py:api_approve`, `api_requests` |
| **Backend server** | Yes — all EMR tables are plaintext | No (does not call `SecureKeyStore`) | No (receives only wrapped keys) | `server/server.py`, `server/emr/store.py` |
| **Database admin** | Yes — direct SQL access to all plaintext tables | No (private keys stored on portal filesystem, not in DB; `users.encrypted_private_key` is wrapped) | No (would need patient password to unwrap `encrypted_private_key`) | `schema.sql` L138–407 |
| **Operator (Docker host)** | Yes — can access DB and portal filesystem | Yes — on Linux, can read portal container filesystem + `/etc/machine-id` to derive `SecureKeyStore` decryption key (`secure_key_store.py` L116–145) | Yes — can read `user_data.json` from portal volume mount, and intercept password from portal logs/memory | `docker-compose.yml` L29 (`.:/app` volume), `secure_key_store.py` |
| **Patient (via browser)** | Yes — their own data via portal UI | No — private key never sent to browser | No — K_data never sent to browser | Portal renders decrypted data server-side |
| **Doctor (via portal)** | Yes — EMR data served as plaintext; `encrypted_record` decrypted via portal on their behalf | No (doctor's private key on portal server) | Yes — unwraps T, then K_data, in portal server memory | `portals/landing.py` L3373–3384 for access check; doctor portal proxies to backend |
| **Network attacker** | No (TLS) | No (TLS) | No (TLS) | `nginx.conf` L40–46 |

---

## 5. Planned Phone-First Design

> **PLANNED, NOT IMPLEMENTED.** The following describes the author's intended future design.

- The patient client is planned as an Android app. No mobile code exists in this repository yet. The app is intended to hold the patient's records and private key on the device, using Android Keystore for key protection where available. **(PLANNED, NOT IMPLEMENTED)**
- Data is backed up to the patient's personal email or cloud account (similar to WhatsApp chat backups), encrypted with the patient's key.
- The server holds nothing, or only an encrypted cache of recent or emergency information.
- Initially, key loss means data loss. A recovery mechanism may come later.
- Doctor identity is planned to be verified by checking the doctor's licence number against a medical council registry. Currently an administrator creates doctor accounts manually (`portals/templates/admin_create_doctor.html`). The schema has `doctor_license_number` and `doctor_verification_status` columns (`schema.sql` L464–466), but no verification logic is implemented. **(PLANNED, NOT IMPLEMENTED)**

> **Note on registry verification:** Registry lookup availability, accuracy, and licence-number-to-person binding are unresolved design questions. A licence number alone does not prove that the person registering the account is the holder of that licence. Additional identity-proofing (e.g., in-person verification, video KYC, or a challenge sent to the registered address of the licence holder) would be needed to close this gap.

In this design, the portal server would no longer generate or hold private keys. Encryption and decryption would occur exclusively on the patient's phone. The server would be a relay for encrypted blobs, not a custodian.

---

## 6. Gap Table

| Property | README / Intent Claims | Current Status | Planned Design | Work Needed |
|----------|----------------------|----------------|----------------|-------------|
| **Client-held confidentiality** | "end-to-end encrypted platform" | Registration records and share snapshots are encrypted, while most other clinical data is plaintext. Portal servers handle keys and encryption. | Phone-side encryption of all data; server sees only ciphertext. | Move key generation and all encrypt/decrypt to patient device. Encrypt all EMR entities before storage. |
| **Server learns nothing** | "servers only manage encrypted metadata" | Server stores plaintext prescriptions, notes, vitals, lab reports, conditions, encounters, appointments, and EMR profiles. | Server stores only encrypted blobs. | Encrypt all clinical tables. Redesign EMR endpoints to accept/return ciphertext. |
| **Time-limited access** | "24-hour" / "time-limited" | `wrapped_keys.temp_key_expires_at` is checked in SQL (`_db_get_wrapped_key`). `access_db` approved rows have no expiry in backend authorization checks. Once K_data is decrypted, it cannot be un-known. The old patient-wide authorship grant was removed. | Same server-side expiry, but K_data never leaves patient device; doctor gets ephemeral session keys. | Add expiry to `access_db`. Design session-key protocol where K_data is never shared. |
| **Per-share snapshot expiry** | New snapshot shares are individually expiring | Each snapshot uses a fresh key wrapped to one doctor; server-side expiry and purge clear live fields. An honest doctor client checks expiry, but a doctor who already decrypted can retain the snapshot. Portals still handle keys and plaintext. | Move share creation and opening to patient and doctor devices; retain honest-doctor assumption. | Implement native clients; assess backup/WAL retention and doctor identity verification; do not promise post-decryption deletion. |
| **Snapshot retention after fetch** | Expiry removes access to the selected snapshot | Expiry blocks future fetches and clears live database fields. It cannot erase plaintext already decrypted by the doctor, screenshots, or copies on a compromised device. | Doctor viewer enforces expiry while the doctor is assumed to follow the protocol. | Keep expiry claims limited to best-effort access control; address device security and retention policies separately. |
| **Share key authenticity** | The public key selected for a patient or doctor belongs to that named person | The API supplies the patient's verification key and the server directory supplies the doctor's wrapping key. Clients do not independently authenticate either key; a server that substitutes keys can defeat the intended identity binding. | Clients verify key fingerprints or use keys certified to verified identities. | Design authenticated key discovery, rotation, and recovery; evaluate out-of-band comparison, pinning, and registry-backed certification. |
| **Revocation** | Author acknowledges revocation cannot un-see data | Revoking an `access_db` grant blocks that grant. A separate, unexpired `wrapped_keys` grant may still authorize access until its expiry; the doctor may retain already-decrypted data. | Revocation deletes server-side session keys; K_data never shared. | Document the limits of server-side expiry and revocation clearly. |
| **Doctor identity verification** | Doctor identity verified by checking licence number against a medical council registry | Admin manually creates doctor accounts (`admin_create_doctor.html`). `users.doctor_verification_status` column exists but defaults to `'unverified'` and `doctor_license_number` column exists but no verification logic is implemented (`schema.sql` L464–466). **(NOT IMPLEMENTED)** | Automated lookup of licence number against an external medical council registry, plus identity-proofing to confirm the registrant is the licence holder. | Implement registry API integration; design identity-proofing step (licence number alone does not prove the registrant is that doctor); handle registry unavailability and data-quality issues. |
| **Patient device (Android app)** | Patient data lives on the patient's own phone; private key held on-device using Android Keystore | No mobile code exists in the repository. All crypto runs on the server-side portal. **(NOT IMPLEMENTED)** | Android app holds records and private key on-device, using Android Keystore for hardware-backed key protection where available. | Build Android app; implement on-device key generation, encryption, and decryption; remove portal-side crypto for patient data; design secure sync protocol between app and server. |
| **Key recovery** | "key loss means data loss" initially | Private key backup wrapped with PBKDF2-derived KEK stored in `users.encrypted_private_key` (`patient_portal.py` L117–123). Same password used for login and KEK derivation. | Recovery via personal cloud backup. | Separate recovery password from login password, or use Argon2id. |
| **Backup** | Planned personal cloud/email backup | No backup mechanism beyond the DB and `encrypted_private_key` column. | WhatsApp-style encrypted backup to patient's cloud. | Build backup export/import. |
| **Emergency access** | Not mentioned | No emergency access mechanism. | Possibly an encrypted emergency cache on server. | Design and implement. |
| **Audit integrity** | Audit log exists | `audit_log` table with append-only comment (`schema.sql` L326). No technical enforcement — any SQL user can UPDATE or DELETE. No tamper detection (no hash chain, no signatures). | Tamper-evident log. | Add hash chaining or digital signatures to audit entries. |
| **Metadata privacy** | Not explicitly claimed | The server knows: which patients exist, which doctors exist, who requested access to whom, when access was granted, and all appointment metadata — all in plaintext. | Server should not learn access patterns. | Encrypt metadata or use a blind-access protocol. |

---

## 7. Security Goals and Explicit Non-Goals

### Goals

1. **Confidentiality of the patient registration record:** The initial patient details (name, age, email, notes) should be readable only by the patient and authorized doctors. The current consent-based sharing prototype for encrypted patient records encrypts the registration record with AES-256-GCM.
2. **Consent-based access:** A doctor can access patient data only after the patient explicitly approves the request.
3. **Time-limited access tokens:** Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (`access_db`) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.
4. **Transport security:** All communication encrypted via TLS 1.2+ with HSTS.
5. **Credential protection:** Passwords hashed with werkzeug `pbkdf2:sha256`. Private keys protected with DPAPI (Windows) or Argon2id-derived machine key (Linux).
6. **Per-share snapshot confidentiality:** For each new share, the server receives an encrypted snapshot and a key wrapped for one named doctor; the patient's permanent data key is not shared. Expiry and recipient are authenticated in the package, subject to the honest-doctor assumption and the current server-side portal limitation.

### Explicit Non-Goals

1. **Revocation of already-decrypted data.** Once a doctor decrypts K_data or reads plaintext, revocation cannot make them "un-see" it. This is a fundamental limitation of any system that shares cryptographic keys.
2. **Protection against a compromised portal server.** The current design trusts the portal server with private keys and plaintext. This is a known limitation of the prototype.
3. **Protection against the operator / hosting provider.** The operator can access the database, container filesystems, and `/etc/machine-id`. They can read all data.
4. **Metadata privacy.** The server knows who accesses whom and when.
5. **Key loss recovery (robust).** Key loss currently means partial data loss (the registration record becomes unrecoverable without the password).
6. **Coercion resistance.** The system does not protect against a patient being compelled to share their password or approve access under duress.
7. **Hospital legal record-retention.** The system's access controls do not override a hospital's legal obligation to retain medical records. The system is designed for patient-held copies of data, not to replace a hospital's own record-keeping systems.

---

## 8. Attack Scenarios

| # | Actor | Attack | Current Outcome | Mitigation Status |
|---|-------|--------|-----------------|-------------------|
| A1 | Network attacker | Intercept traffic | Blocked by TLS (nginx.conf L40–46) | ✅ Mitigated |
| A2 | Malicious doctor | Retain K_data after 24h expiry | Doctor keeps K_data forever; can decrypt `encrypted_record` offline. Server-side expiry only blocks API calls. | ⚠️ Fundamental limitation, documented |
| A3 | Malicious doctor | Access plaintext EMR data beyond 24h | Approved `access_db` grants have no expiry in backend authorization checks. The former patient-wide authorship grant is removed. | ❌ Not mitigated |
| A4 | Operator / insider | Read all clinical data | All EMR data is plaintext in Postgres. Private keys recoverable via filesystem + machine-id. | ❌ Not mitigated (by design in prototype) |
| A5 | Database admin | Read plaintext EMR data | Direct SQL access to all plaintext tables. | ❌ Not mitigated |
| A6 | Any API client with API key | Approve access request for any patient | `/approve_request` checks only the static API key, not patient identity (`server/server.py` L1940–1944). | ❌ Not mitigated |
| A7 | Any API client with API key | Submit access request for any doctor | `/request_access_simple` checks only the static API key (`server/server.py` L1822). | ⚠️ Partially mitigated (JWT required for `/access/request`) |
| A8 | Timing side-channel | Extract API key via timing on string comparison | `_require_api_key` uses `hmac.compare_digest` on UTF-8 encoded values (L123). | ✅ Fixed |
| A9 | Attacker with patient password | Derive KEK, unwrap K_data | PBKDF2 with 200k iterations (`derive_kek_from_password`). Same password used for login. Backend receives password at login. | ⚠️ Partially mitigated (iteration count helps but password reuse is a risk) |
| A10 | Attacker with machine-id | Decrypt private keys on Linux | `SecureKeyStore` Linux fallback derives key from `/etc/machine-id` (`secure_key_store.py` L116–145). Any process on the machine can read this. | ⚠️ Software-only protection, documented in code |
| A11 | Audit log tampering | Delete or modify audit entries | No technical enforcement — `audit_log` is append-only by convention only (`schema.sql` L326). | ❌ Not mitigated |

---

## 9. Open Issues and Future Work (ordered by importance)

**Remaining open items:** `approve_request` caller check, `access_db` expiry, per-grant keys, plaintext EMR data, server-side key generation, password-derived key backup, and the unused Argon2 function. The implicit prescription/lab authorship grant has been removed. API-key and JWT HMAC comparisons use `hmac.compare_digest`; H7's timing-compare issue and H8 are fixed.

1. **Encrypt all clinical data.** Most EMR data is stored in plaintext. This is the single largest gap between claims and implementation. All tables (`doctor_notes`, `emr_profiles`, `emr_prescriptions`, `emr_lab_reports`, `conditions`, `vitals`, `encounters`) should store ciphertext.

2. **Move crypto to patient device.** Key generation, encryption, and decryption currently happen on the portal server. Moving these to the patient's device (phone or browser) is necessary for genuine end-to-end confidentiality.

3. **Add expiry to `access_db`.** Approved grants currently remain active in backend authorization checks until revoked (`schema.sql` L181–191).

4. **Authenticate `approve_request` to the patient.** Currently protected only by a shared static API key. Any holder of the API key can approve any request (`server/server.py` L1940–1944).

5. **Use constant-time comparisons for API keys and HMAC signatures.** Fixed: `_require_api_key`, JWT validation and portal API-key validation use `hmac.compare_digest`.

6. **Migrate all KEK derivation to Argon2id.** `derive_kek_argon2` exists (`crypto_utils.py` L192–214) but is not wired into runtime KEK call sites. All such call sites use PBKDF2.

8. **Separate login password from KEK password.** The same password is sent to the backend at login and used to derive the KEK for K_data wrapping. An operator who intercepts the password can unwrap K_data.

9. **Implement doctor identity verification.** The `doctor_verification_status` column exists but defaults to `'unverified'` with no verification logic.

10. **Add tamper-evident audit logging.** The `audit_log` table has no integrity protection (no hash chain, no signatures).

11. **Implement key recovery.** Current recovery relies on `encrypted_private_key` wrapped with the login password via PBKDF2.

12. **Design and implement emergency access.** No mechanism exists for emergency scenarios.

13. **Implement encrypted backup/export.** No backup export mechanism exists.

14. **Address metadata privacy.** The server learns the full access graph (who requested access to whom and when).

