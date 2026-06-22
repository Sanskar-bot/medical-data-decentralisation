# Graph Report - medical-data-decentralisation  (2026-04-27)

## Corpus Check
- 28 files · ~53,492 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 502 nodes · 1031 edges · 37 communities detected
- Extraction: 76% EXTRACTED · 24% INFERRED · 0% AMBIGUOUS · INFERRED: 250 edges (avg confidence: 0.76)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]

## God Nodes (most connected - your core abstractions)
1. `exists()` - 50 edges
2. `SecureKeyStore` - 37 edges
3. `load_json()` - 31 edges
4. `_auth_headers()` - 28 edges
5. `derive_kek_from_password()` - 26 edges
6. `bh()` - 22 edges
7. `unwrap_key_with_kek()` - 20 edges
8. `_require_api_key()` - 20 edges
9. `_headers()` - 18 edges
10. `audit()` - 17 edges

## Surprising Connections (you probably didn't know these)
- `Unlock a doctor's RSA private key from the local credential store.      Return` --uses--> `SecureKeyStore`  [INFERRED]
  portals\doctor_portal.py → common\secure_key_store.py
- `Doctor adds a clinical note to a patient profile. Server enforces access check.` --uses--> `SecureKeyStore`  [INFERRED]
  portals\doctor_portal.py → common\secure_key_store.py
- `Fetch all notes for a patient; returns filtered list for this doctor.` --uses--> `SecureKeyStore`  [INFERRED]
  portals\doctor_portal.py → common\secure_key_store.py
- `Doctor deletes their own note.` --uses--> `SecureKeyStore`  [INFERRED]
  portals\doctor_portal.py → common\secure_key_store.py
- `Proxy note images from the backend server for display in the doctor portal.` --uses--> `SecureKeyStore`  [INFERRED]
  portals\doctor_portal.py → common\secure_key_store.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.04
Nodes (93): api_lookup_doctor(), exists(), _append_login_history(), approve_request(), audit(), auth_login(), auth_login_history(), auth_logout() (+85 more)

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (71): Doctor adds a clinical note to a patient profile. Server enforces access check., Fetch all notes for a patient; returns filtered list for this doctor., Doctor deletes their own note., Proxy note images from the backend server for display in the doctor portal., api_emr_proxy(), _api_key(), api_resolve_patient(), dashboard() (+63 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (65): new_appointment(), new_lab_report(), new_patient_profile(), new_prescription(), _now_iso(), emr/models.py — Data schemas and validation for EMR entities.  Each model is a p, Return list of missing required field names., Return list of validation error strings (empty = valid). (+57 more)

### Community 3 - "Community 3"
Cohesion: 0.07
Nodes (52): aesgcm_decrypt(), rsa_load_private(), rsa_unwrap_key(), rsa_verify(), unwrap_key_with_kek(), api_add_note(), api_audit_log(), api_delete_note() (+44 more)

### Community 4 - "Community 4"
Cohesion: 0.07
Nodes (18): app(), _auth_headers(), _clean_emr_data(), _init_dirs(), jwt_encode(), _make_jwt(), tests/test_emr_api.py — Automated tests for the EMR module endpoints.  Uses Flas, Ensure the server data directories exist before importing. (+10 more)

### Community 5 - "Community 5"
Cohesion: 0.12
Nodes (34): aesgcm_encrypt(), derive_kek_from_password(), generate_aes_key(), generate_rsa_keypair(), Decrypt a blob produced by rsa_hybrid_encrypt., Return a 32-byte AES key (AES-256)., Encrypt plaintext with AES-GCM.     Returns dict with base64-encoded nonce, cip, Wrap (encrypt) a symmetric key with recipient's RSA public key using OAEP. (+26 more)

### Community 6 - "Community 6"
Cohesion: 0.1
Nodes (36): rsa_load_public(), api_approve(), api_deny(), api_key(), api_load_profile(), api_note_image(), api_patient_notes(), api_qr_transfer() (+28 more)

### Community 7 - "Community 7"
Cohesion: 0.22
Nodes (13): approve_on_server(), fetch_active_requests(), load_local_user_json(), load_patient_private(), main(), Robustly load client/Users/<profile_code>/user_data.json.      Uses the script, Ask user password once and unwrap K_data from local_json['key_protection']., Call POST /approve_request with required payload. (+5 more)

### Community 8 - "Community 8"
Cohesion: 0.27
Nodes (9): _DATA_BLOB, delete_private_key(), _dpapi_decrypt(), _dpapi_encrypt(), common/secure_key_store.py ========================== RSA private key storage, Convert credential ID to a safe filename., Encrypt bytes using DPAPI (current-user scope)., Decrypt a DPAPI blob; returns plaintext bytes. (+1 more)

### Community 9 - "Community 9"
Cohesion: 0.33
Nodes (9): fetch_all_active_requests(), fetch_request_status_by_id(), find_doctor_folder_by_code(), load_local_doctor(), poll_for_update(), post_request(), Automatically locate doctor folder using doctor_code only., Polls server until request status != 'pending' or until timeout.     Returns th (+1 more)

### Community 10 - "Community 10"
Cohesion: 0.22
Nodes (8): check_password(), hash_password(), _is_json_request(), login_required(), True when the caller expects a JSON response (API / XHR call)., Return a werkzeug pbkdf2:sha256 hash of *raw*., Verify *raw* against *stored*.      Handles two hash formats:       1. werkze, Decorator that enforces Flask-session authentication.      Also accepts a vali

### Community 11 - "Community 11"
Cohesion: 0.83
Nodes (3): main(), print_separator(), register()

### Community 12 - "Community 12"
Cohesion: 1.0
Nodes (2): main(), try_decrypt()

### Community 17 - "Community 17"
Cohesion: 1.0
Nodes (1): Encrypt bytes using DPAPI (current-user scope).

### Community 18 - "Community 18"
Cohesion: 1.0
Nodes (1): Decrypt a DPAPI blob; returns plaintext bytes.

### Community 19 - "Community 19"
Cohesion: 1.0
Nodes (1): Convert credential ID to a safe filename.

### Community 20 - "Community 20"
Cohesion: 1.0
Nodes (1): DPAPI-backed key storage.      Usage:         SecureKeyStore.store_private_ke

### Community 21 - "Community 21"
Cohesion: 1.0
Nodes (1): Return the active requests list or [] on error (non-fatal).

### Community 22 - "Community 22"
Cohesion: 1.0
Nodes (1): Return array of all active requests. Clients should filter by profile_code.

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (1): Return a single request object by request_id, or 404 if not found.

### Community 24 - "Community 24"
Cohesion: 1.0
Nodes (1): Return wrapped keys for the specified profile. Looks under     PATIENTS_DIR/<pr

### Community 25 - "Community 25"
Cohesion: 1.0
Nodes (1): Remove stale entries from active_requests.json, then reschedule itself.

### Community 26 - "Community 26"
Cohesion: 1.0
Nodes (1): Decorator — validates JWT and optionally checks role.

### Community 27 - "Community 27"
Cohesion: 1.0
Nodes (1): Send (simulated) OTP to email. In prod: plug in SendGrid/SES.

### Community 28 - "Community 28"
Cohesion: 1.0
Nodes (1): Full registration: name, email, role, password_hash (bcrypt done client-side or

### Community 29 - "Community 29"
Cohesion: 1.0
Nodes (1): Called by landing.py during registration to create a users_db entry,     enabli

### Community 30 - "Community 30"
Cohesion: 1.0
Nodes (1): Doctor uploads an encrypted visit report (hybrid encryption).     Body: patient

### Community 31 - "Community 31"
Cohesion: 1.0
Nodes (1): Patient or approved doctor fetches encrypted report list.

### Community 32 - "Community 32"
Cohesion: 1.0
Nodes (1): Fetch single encrypted report (patient or approved doctor).

### Community 33 - "Community 33"
Cohesion: 1.0
Nodes (1): Upload encrypted medical image binary.     Multipart form: record_id, file_hash

### Community 34 - "Community 34"
Cohesion: 1.0
Nodes (1): Return all doctor notes for a given patient profile code.

### Community 35 - "Community 35"
Cohesion: 1.0
Nodes (1): Doctor adds a note for a patient (called from doctor portal).

### Community 36 - "Community 36"
Cohesion: 1.0
Nodes (1): Serve a saved note image file.

### Community 37 - "Community 37"
Cohesion: 1.0
Nodes (1): Delete a doctor note by its ID.

### Community 38 - "Community 38"
Cohesion: 1.0
Nodes (1): Return True iff the doctor has a non-expired wrapped key for this patient.

### Community 39 - "Community 39"
Cohesion: 1.0
Nodes (1): Returns all notes for this patient.     Protected by API key — both doctor and

### Community 40 - "Community 40"
Cohesion: 1.0
Nodes (1): Doctor deletes their own note.     Requires: X-API-Key + JSON body { "doctor_co

## Knowledge Gaps
- **107 isolated node(s):** `Return list of all active requests from server (or raise).`, `Load patient private key object. Accepts folder or file path.`, `Robustly load client/Users/<profile_code>/user_data.json.      Uses the script`, `Ask user password once and unwrap K_data from local_json['key_protection'].`, `Call POST /approve_request with required payload.` (+102 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 12`** (3 nodes): `main()`, `try_decrypt()`, `diag_decrypt.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 17`** (1 nodes): `Encrypt bytes using DPAPI (current-user scope).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 18`** (1 nodes): `Decrypt a DPAPI blob; returns plaintext bytes.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 19`** (1 nodes): `Convert credential ID to a safe filename.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 20`** (1 nodes): `DPAPI-backed key storage.      Usage:         SecureKeyStore.store_private_ke`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 21`** (1 nodes): `Return the active requests list or [] on error (non-fatal).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (1 nodes): `Return array of all active requests. Clients should filter by profile_code.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (1 nodes): `Return a single request object by request_id, or 404 if not found.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 24`** (1 nodes): `Return wrapped keys for the specified profile. Looks under     PATIENTS_DIR/<pr`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 25`** (1 nodes): `Remove stale entries from active_requests.json, then reschedule itself.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 26`** (1 nodes): `Decorator — validates JWT and optionally checks role.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 27`** (1 nodes): `Send (simulated) OTP to email. In prod: plug in SendGrid/SES.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (1 nodes): `Full registration: name, email, role, password_hash (bcrypt done client-side or`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 29`** (1 nodes): `Called by landing.py during registration to create a users_db entry,     enabli`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 30`** (1 nodes): `Doctor uploads an encrypted visit report (hybrid encryption).     Body: patient`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 31`** (1 nodes): `Patient or approved doctor fetches encrypted report list.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 32`** (1 nodes): `Fetch single encrypted report (patient or approved doctor).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (1 nodes): `Upload encrypted medical image binary.     Multipart form: record_id, file_hash`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 34`** (1 nodes): `Return all doctor notes for a given patient profile code.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 35`** (1 nodes): `Doctor adds a note for a patient (called from doctor portal).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 36`** (1 nodes): `Serve a saved note image file.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 37`** (1 nodes): `Delete a doctor note by its ID.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 38`** (1 nodes): `Return True iff the doctor has a non-expired wrapped key for this patient.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 39`** (1 nodes): `Returns all notes for this patient.     Protected by API key — both doctor and`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `Doctor deletes their own note.     Requires: X-API-Key + JSON body { "doctor_co`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `exists()` connect `Community 0` to `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 9`?**
  _High betweenness centrality (0.604) - this node is a cross-community bridge._
- **Why does `_read()` connect `Community 2` to `Community 0`?**
  _High betweenness centrality (0.218) - this node is a cross-community bridge._
- **Why does `_init_dirs()` connect `Community 4` to `Community 0`?**
  _High betweenness centrality (0.145) - this node is a cross-community bridge._
- **Are the 47 inferred relationships involving `exists()` (e.g. with `load_patient_private()` and `load_local_user_json()`) actually correct?**
  _`exists()` has 47 INFERRED edges - model-reasoned connections that need verification._
- **Are the 35 inferred relationships involving `SecureKeyStore` (e.g. with `Unlock a doctor's RSA private key from the local credential store.      Return` and `Doctor adds a clinical note to a patient profile. Server enforces access check.`) actually correct?**
  _`SecureKeyStore` has 35 INFERRED edges - model-reasoned connections that need verification._
- **Are the 25 inferred relationships involving `derive_kek_from_password()` (e.g. with `load_patient_private()` and `unwrap_local_K_data_from_local_json_once()`) actually correct?**
  _`derive_kek_from_password()` has 25 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Return list of all active requests from server (or raise).`, `Load patient private key object. Accepts folder or file path.`, `Robustly load client/Users/<profile_code>/user_data.json.      Uses the script` to the rest of the system?**
  _107 weakly-connected nodes found - possible documentation gaps or missing edges._