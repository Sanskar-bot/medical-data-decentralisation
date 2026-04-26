# Graph Report - medical-data-decentralisation  (2026-04-26)

## Corpus Check
- 22 files · ~42,166 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 296 nodes · 673 edges · 15 communities detected
- Extraction: 72% EXTRACTED · 28% INFERRED · 0% AMBIGUOUS · INFERRED: 189 edges (avg confidence: 0.78)
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
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]

## God Nodes (most connected - your core abstractions)
1. `exists()` - 45 edges
2. `derive_kek_from_password()` - 24 edges
3. `load_json()` - 24 edges
4. `_require_api_key()` - 19 edges
5. `unwrap_key_with_kek()` - 18 edges
6. `bh()` - 17 edges
7. `audit()` - 15 edges
8. `save_json()` - 14 edges
9. `main()` - 13 edges
10. `SecureKeyStore` - 13 edges

## Surprising Connections (you probably didn't know these)
- `SecureKeyStore` --uses--> `Redirect to landing if not logged in.`  [INFERRED]
  common\secure_key_store.py → portals\landing.py
- `SecureKeyStore` --uses--> `Build headers that carry the Flask session cookie to doctor_portal.`  [INFERRED]
  common\secure_key_store.py → portals\landing.py
- `SecureKeyStore` --uses--> `Return temp_key_expires_at for the logged-in doctor's wrapped key.     Falls ba`  [INFERRED]
  common\secure_key_store.py → portals\landing.py
- `start()` --calls--> `_cleanup_old_requests()`  [INFERRED]
  START.py → server\server.py
- `load_patient_private()` --calls--> `exists()`  [INFERRED]
  client\respond_request.py → common\secure_key_store.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.12
Nodes (31): _api_key(), dashboard(), doctor_access_expiry(), doctor_add_note(), doctor_delete_note(), doctor_fetch_record(), doctor_load_profile(), doctor_note_image() (+23 more)

### Community 1 - "Community 1"
Cohesion: 0.13
Nodes (30): derive_kek_from_password(), unwrap_key_with_kek(), api_add_note(), api_audit_log(), api_delete_note(), api_doctor_notes_list(), api_doctor_patients(), api_fetch_record() (+22 more)

### Community 2 - "Community 2"
Cohesion: 0.12
Nodes (31): aesgcm_encrypt(), Encrypt plaintext with AES-GCM.     Returns dict with base64-encoded nonce, cip, Wrap (encrypt) a symmetric key with recipient's RSA public key using OAEP., rsa_load_public(), rsa_wrap_key(), api_approve(), api_deny(), api_key() (+23 more)

### Community 3 - "Community 3"
Cohesion: 0.11
Nodes (27): aesgcm_decrypt(), rsa_load_private(), rsa_verify(), auto_locate_doctor_folder(), auto_locate_doctor_folder(), get_encrypted_data(), get_wrapped_key(), load_doctor_private_from_folder() (+19 more)

### Community 4 - "Community 4"
Cohesion: 0.12
Nodes (27): add_doctor_note(), audit(), auth_login_history(), auth_me(), delete_doctor_note(), doctor_patients(), download_image(), get_images_for_record() (+19 more)

### Community 5 - "Community 5"
Cohesion: 0.15
Nodes (20): generate_aes_key(), generate_rsa_keypair(), Decrypt a blob produced by rsa_hybrid_encrypt., Return a 32-byte AES key (AES-256)., Hybrid encrypt: generate random AES key, encrypt data with AES-GCM,     then RS, rsa_hybrid_decrypt(), rsa_hybrid_encrypt(), rsa_serialize_private() (+12 more)

### Community 6 - "Community 6"
Cohesion: 0.14
Nodes (19): approve_on_server(), fetch_active_requests(), load_local_user_json(), load_patient_private(), main(), Robustly load client/Users/<profile_code>/user_data.json.      Uses the script, Ask user password once and unwrap K_data from local_json['key_protection']., Call POST /approve_request with required payload. (+11 more)

### Community 7 - "Community 7"
Cohesion: 0.13
Nodes (18): auth_login(), auth_otp_send(), auth_otp_verify(), auth_refresh(), auth_register(), _gen_otp(), get_patient_reports(), get_report() (+10 more)

### Community 8 - "Community 8"
Cohesion: 0.16
Nodes (11): approve_request(), _cleanup_old_requests(), get_request_status(), Return the active requests list or [] on error (non-fatal)., Write active requests atomically to prevent corruption on crash., Return a single request object by request_id, or 404 if not found., Remove stale entries from active_requests.json, then reschedule itself., _read_active_requests() (+3 more)

### Community 9 - "Community 9"
Cohesion: 0.15
Nodes (13): get_all_active_requests(), get_doctor_notes(), get_patient_data(), get_patient_public(), get_wrapped_key_for_profile(), Return all doctor notes for a given patient profile code., Serve a saved note image file., Return array of all active requests. Clients should filter by profile_code. (+5 more)

### Community 10 - "Community 10"
Cohesion: 0.27
Nodes (10): _DATA_BLOB, delete_private_key(), _dpapi_decrypt(), _dpapi_encrypt(), common/secure_key_store.py ========================== RSA private key storage, Convert credential ID to a safe filename., Encrypt bytes using DPAPI (current-user scope)., Decrypt a DPAPI blob; returns plaintext bytes. (+2 more)

### Community 11 - "Community 11"
Cohesion: 0.33
Nodes (9): fetch_all_active_requests(), fetch_request_status_by_id(), find_doctor_folder_by_code(), load_local_doctor(), poll_for_update(), post_request(), Automatically locate doctor folder using doctor_code only., Polls server until request status != 'pending' or until timeout.     Returns th (+1 more)

### Community 12 - "Community 12"
Cohesion: 0.22
Nodes (8): check_password(), hash_password(), _is_json_request(), login_required(), True when the caller expects a JSON response (API / XHR call)., Return a werkzeug pbkdf2:sha256 hash of *raw*., Verify *raw* against *stored*.      Handles two hash formats:       1. werkze, Decorator that enforces Flask-session authentication.      Also accepts a vali

### Community 13 - "Community 13"
Cohesion: 0.25
Nodes (9): _doctor_has_active_access(), doctor_notes_add(), doctor_notes_delete(), doctor_notes_for_patient(), _load_notes(), Return True iff the doctor has a non-expired wrapped key for this patient., Returns all notes for this patient.     Protected by API key — both doctor and, Doctor deletes their own note.     Requires: X-API-Key + JSON body { "doctor_co (+1 more)

### Community 14 - "Community 14"
Cohesion: 1.0
Nodes (2): main(), try_decrypt()

## Knowledge Gaps
- **53 isolated node(s):** `Return list of all active requests from server (or raise).`, `Load patient private key object. Accepts folder or file path.`, `Robustly load client/Users/<profile_code>/user_data.json.      Uses the script`, `Ask user password once and unwrap K_data from local_json['key_protection'].`, `Call POST /approve_request with required payload.` (+48 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 14`** (3 nodes): `main()`, `try_decrypt()`, `diag_decrypt.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `exists()` connect `Community 3` to `Community 0`, `Community 1`, `Community 2`, `Community 4`, `Community 6`, `Community 9`, `Community 10`, `Community 11`, `Community 13`?**
  _High betweenness centrality (0.526) - this node is a cross-community bridge._
- **Why does `load_json()` connect `Community 4` to `Community 9`, `Community 3`, `Community 7`?**
  _High betweenness centrality (0.164) - this node is a cross-community bridge._
- **Why does `derive_kek_from_password()` connect `Community 1` to `Community 0`, `Community 2`, `Community 3`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.082) - this node is a cross-community bridge._
- **Are the 42 inferred relationships involving `exists()` (e.g. with `load_patient_private()` and `load_local_user_json()`) actually correct?**
  _`exists()` has 42 INFERRED edges - model-reasoned connections that need verification._
- **Are the 23 inferred relationships involving `derive_kek_from_password()` (e.g. with `load_patient_private()` and `unwrap_local_K_data_from_local_json_once()`) actually correct?**
  _`derive_kek_from_password()` has 23 INFERRED edges - model-reasoned connections that need verification._
- **Are the 17 inferred relationships involving `unwrap_key_with_kek()` (e.g. with `load_patient_private()` and `unwrap_local_K_data_from_local_json_once()`) actually correct?**
  _`unwrap_key_with_kek()` has 17 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Return list of all active requests from server (or raise).`, `Load patient private key object. Accepts folder or file path.`, `Robustly load client/Users/<profile_code>/user_data.json.      Uses the script` to the rest of the system?**
  _53 weakly-connected nodes found - possible documentation gaps or missing edges._