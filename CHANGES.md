# CHANGES.md — Security Fixes Applied

All 25 security issues have been remediated. Changes are listed in implementation order.

---

## CRITICAL Fixes

### [C1] Committed Secrets — `server/server.py`, `.gitignore`
**File:** `server/server.py` (startup block, lines ~85–110)
**Fix:** `SERVER_API_KEY` environment variable is now the primary source for the API key; `api_key.txt` is only read as a fallback in `FLASK_ENV=development`. If `api_key.txt` exists in any non-development environment, startup raises `RuntimeError` to block accidental production deployments. Both `server/api_key.txt` and `server/audit.log` are now in `.gitignore`.

### [C2] Plaintext Key Storage on Linux — `common/secure_key_store.py`
**File:** `common/secure_key_store.py` (non-Windows `else` branch)
**Fix:** Replaced the no-op passthrough with AES-256-GCM encryption using an Argon2id machine-derived key. File format is `salt(16 bytes) || nonce(12 bytes) || AES-GCM-ciphertext`. Machine key is derived from `/etc/machine-id` (Linux) or `platform.node()` (macOS). A warning is logged that this is software-only protection. Windows DPAPI path is unchanged.

### [C3] JWT Secret == API Key — `server/server.py`
**File:** `server/server.py` (`_get_jwt_secret()`, line ~985)
**Fix:** `_get_jwt_secret()` now reads from the `JWT_SECRET` environment variable first, then falls back to a dedicated `server/jwt_secret.txt` (auto-generated with `secrets.token_hex(64)` on first run, separate from `api_key.txt`). `jwt_secret.txt` is added to `.gitignore`. A dev-mode warning is printed if `JWT_SECRET` is not set as an env var.

### [C4] Doctor Note Access Gate Bypass — `server/server.py`
**File:** `server/server.py` (`doctor_notes_add()`, `doctor_notes_delete()`)
**Fix:** Both endpoints now use `@_require_jwt(roles=["doctor"])` instead of `_require_api_key()`. `doctor_code` is derived from `request.jwt_payload["uid"]`, not from the request body. `doctor_name`, `doctor_specialization`, and `doctor_hospital` are still accepted from the body (metadata only).

---

## HIGH Fixes

### [H1] IDOR on Patient Data — `server/server.py`
**File:** `server/server.py` (`get_patient_data()`, `get_wrapped_key_for_profile()`, new helper `_caller_may_access_patient()`)
**Fix:** Added `_caller_may_access_patient(profile_code) -> bool` that checks the caller's JWT: patients may only access their own data; doctors may only access patients for whom they have an active wrapped key. Both endpoints call this helper and return HTTP 403 if access is denied.

### [H2] Legacy SHA-256 Password Hashing — `server/server.py`
**File:** `server/server.py` (`auth_login()`, new `POST /auth/upgrade_password`)
**Fix:** Legacy SHA-256 accounts now always return HTTP 403 `{"error": "password_reset_required", "reason": "legacy_hash"}` instead of silently logging in. The `pw_hash` (pre-hashed) login parameter is removed; only raw `password` is accepted. A new `POST /auth/upgrade_password` endpoint handles the migration by verifying the old SHA-256 hash and upgrading to `werkzeug pbkdf2:sha256`, returning a new access token.

### [H3] In-Memory Token Blocklist — `server/server.py`
**File:** `server/server.py` (blocklist section, `_jwt_decode()`, `auth_logout()`)
**Fix:** `_token_blocklist` is now backed by `server/token_blocklist.json`. On startup the file is loaded and expired JTIs are discarded. On add, the JTI + exp are appended to the in-memory set and written atomically to the file. `_jwt_decode` checks the in-memory set first; on restart recovery (empty set) it reloads from disk. The hourly cleanup job removes expired JTIs from both memory and file.

### [H4] In-Memory Rate Limiter — `server/server.py`
**File:** `server/server.py` (`rate_limited()` decorator, `_RATE_LIMITS_DIR`)
**Fix:** Per-IP rate-limit state is persisted to `server/rate_limits/<ip>.json`. Each request loads and filters the per-IP file atomically, then writes the updated timestamps. The hourly cleanup job deletes rate limit files older than 10 minutes. A comment notes Redis is the production path for multi-worker deployments.

### [H5] In-Memory OTP Store — `server/server.py`
**File:** `server/server.py` (`_otp_store`, `auth_otp_send()`, `auth_otp_verify()`)
**Fix:** `_otp_store` is now loaded from `server/otp_store.json` on startup (with expired entries discarded). All send/verify/delete operations update the file atomically under `_otp_lock`. Schema per entry: `{"otp": "...", "expires": float, "attempts": int}`.

### [H6] No File Upload Validation — `server/server.py`
**File:** `server/server.py` (`upload_image()`, `upload_profile_photo()`, app config)
**Fix:** `app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024` sets a global 10 MB limit. `upload_image()` additionally enforces a 5 MB per-file limit and validates the first 12 bytes against known magic bytes (jpg, png, gif, webp). `upload_profile_photo()` has the same magic-byte validation. An `@app.errorhandler(413)` returns JSON `{"error": "file_too_large"}`.

### [H7] Unvalidated Status Values — `server/server.py`
**File:** `server/server.py` (`update_request_status()`)
**Fix:** Added `ALLOWED_STATUSES = {"denied", "expired", "cancelled"}` whitelist. The "approved" transition is explicitly blocked with a helpful error message directing callers to `/approve_request`.

---

## MEDIUM Fixes

### [M1] No TLS Warning — `server/server.py`
**File:** `server/server.py` (startup block, `security_headers()`)
**Fix:** On startup, if `FLASK_ENV != "development"` and `BEHIND_TLS_PROXY` is not set, a loud WARNING is printed. The `Strict-Transport-Security` header is now only set when `BEHIND_TLS_PROXY` is set (plain HTTP + HSTS causes browser lockout issues).

### [M2] RSA Key Size 2048-bit — `common/crypto_utils.py`
**File:** `common/crypto_utils.py` (`generate_rsa_keypair()`)
**Fix:** Default `key_size` changed from 2048 to 4096 with an explanatory comment: "Medical records require long-term confidentiality; 4096-bit provides a wider margin against future attacks." Existing keys are not retroactively changed.

### [M3] PBKDF2 Instead of Argon2id — `common/crypto_utils.py`, `common/secure_key_store.py`
**Files:** `common/crypto_utils.py` (new `derive_kek_argon2()`), `common/secure_key_store.py` (Linux fallback)
**Fix:** Added `derive_kek_argon2(password, salt=None)` using argon2-cffi with `time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID`. `derive_kek_from_password()` is kept for backward compatibility but marked `DEPRECATED`. The Linux/macOS key store fallback uses Argon2id for machine key derivation instead of PBKDF2.

### [M4] Non-Atomic save_json() — `server/server.py`
**File:** `server/server.py` (`save_json()`)
**Fix:** Replaced the direct open-and-write implementation with the atomic pattern: write to `<path>.tmp`, `fsync`, then `os.replace()`. Same function signature; all call sites work unchanged.

### [M5] TOCTOU Race on users_db.json — `server/server.py`
**File:** `server/server.py` (`_users_db_lock`, `_load_users()`, `_save_users()`, multiple endpoints)
**Fix:** Added `_users_db_lock = threading.Lock()` and `_load_users()` / `_save_users()` helpers. All read-modify-write operations on `users_db.json` in `auth_login`, `internal_register_user_db`, `auth_register`, and `upload_profile_photo` are now wrapped in `with _users_db_lock:`.

### [M6] Missing Access Check on Note List — `server/server.py`
**File:** `server/server.py` (`doctor_notes_for_patient()`)
**Fix:** If a JWT is present, patient callers can only retrieve their own notes; doctor callers only if `_doctor_has_active_access` returns True. Requests with API key only (no JWT) are still allowed for portal-to-portal calls, with a TODO comment to remove this once portals migrate to JWT-authenticated calls.

### [M7] CSP Allows unsafe-inline — `server/server.py`
**File:** `server/server.py` (`security_headers()`, new `_set_csp_nonce` before_request, `_inject_csp_nonce` context_processor)
**Fix:** A per-request nonce is generated in `g.csp_nonce` via `@app.before_request`. `script-src` now uses `'nonce-{nonce}'` instead of `'unsafe-inline'`. The nonce is exposed to Jinja2 templates via `@app.context_processor`.

### [M8] Refresh Token Not Rotated — `server/server.py`
**File:** `server/server.py` (`auth_refresh()`)
**Fix:** On every successful refresh, the old refresh token's JTI is added to the blocklist (single-use enforcement). A new refresh token with a new JTI is issued and set in the cookie.

---

## LOW / INFO Fixes

### [L1] Debug Artifacts in Repo — `.gitignore`
**File:** `.gitignore`
**Fix:** Added `server/jwt_secret.txt`, `server/token_blocklist.json`, `server/otp_store.json`, `server/rate_limits/`, `doctor/fetch_patient_data_debug.py`, `portals/doctor_portal.py.bak`, `portals/patient_portal.py.bak`, `portals/patient_ui.html`, `**/__pycache__/`, `*.pyc`.

### [L2] Filename Typo — `doctor/patient_search.py`
**File:** `doctor/pateint_search.py` → `doctor/patient_search.py`
**Fix:** Renamed the misspelled file. No import references to the old name were found in `doctor/doctor.py` or other files (it is a standalone script).

### [L3] OTP in Server Log — `server/server.py`
**File:** `server/server.py` (`auth_otp_send()`)
**Fix:** `print(f"[DEV OTP] {email} → {otp}")` is now guarded by `if os.environ.get("FLASK_ENV") == "development":`, preventing OTPs from appearing in logs in any other environment.

### [L4] Unauthenticated Profile Photo Endpoint — `server/server.py`
**File:** `server/server.py` (`get_profile_photo()`)
**Fix:** Added `auth_err = _require_api_key()` guard. TODO comment added noting JWT ownership check is the correct long-term solution.

### [L5] Note Images Served Without Ownership Check — `server/server.py`
**File:** `server/server.py` (`serve_note_image()`)
**Fix:** After the API key check, the filename is parsed to extract `note_id` (format: `note_<uuid>.<ext>`). The note is loaded and if a JWT is present, the caller must be either the patient (`uid == note["patient_code"]`) or the creating doctor (`uid == note["doctor_code"]`). Requests without a JWT still pass (portal-to-portal fallback with TODO comment).

### [L6] Windows-Only Dependency — `requirements.txt`
**File:** `requirements.txt`
**Fix:** Added `; sys_platform == "win32"` platform marker to `pywin32-ctypes==0.2.3`. Added `argon2-cffi==23.1.0` for Argon2id key derivation (M3).

---

## Files Modified

| File | Changes |
|------|---------|
| `server/server.py` | C1, C3, C4, H1, H2, H3, H4, H5, H6, H7, M1, M4, M5, M6, M7, M8, L3, L4, L5 |
| `common/crypto_utils.py` | M2, M3 |
| `common/secure_key_store.py` | C2, M3 |
| `portals/auth_utils.py` | C1 (reads SERVER_API_KEY env var) |
| `requirements.txt` | L6, M3 |
| `.gitignore` | C1, C3, L1 |
| `doctor/patient_search.py` | L2 (new file — renamed from `pateint_search.py`) |

## Test Results

```
25 passed in 0.83s  (python -m pytest tests/test_emr_api.py -v, FLASK_ENV=development)
```

---

## Feature Additions

### [F1] Allergy/Interaction Safety Check — server/emr/models.py, server/emr/routes.py, portals/landing.py, portals/templates/doctor_prescriptions.html, portals/templates/emr.html

**Summary:** Added a clinical allergy conflict check to the prescription creation flow.

**Changes:**

- **server/emr/models.py**
  - Added _norm_allergy_list(value): normalises allergy data to a clean, deduplicated list[str], accepting both lists and comma-separated strings. Used to fix a data-type bug where emr.html was POSTing a raw string where the DB expected a JSON array.
  - Added ALLERGY_CROSS_REACTIVITY: a conservative clinical cross-reactivity table covering penicillin family, cephalosporins, sulfa drugs, NSAIDs, codeine-derived opioids, latex, iodine/contrast, egg, and shellfish→protamine. **Not a substitute for a licensed drug-interaction database.**
  - Added check_allergy_conflicts(allergies, medications) -> list[dict]: pure function (no DB/network access) returning one conflict dict per detected conflict with fields medication, llergy, matched_term, and severity ("high" for direct match, "moderate" for cross-reactivity table match).
  - 
ew_prescription() now also accepts "dose" as an alias for "dosage" to match the frontend payload.

- **server/emr/routes.py**
  - create_prescription(): after structural validation, fetches the patient's EMR profile, runs check_allergy_conflicts(), and returns **HTTP 409** {"error": "allergy_conflict", "conflicts": [...]} if conflicts are found and override_allergy_check is not 	rue. If override is 	rue, the prescription is saved normally and an prescription_allergy_override audit entry is written. A missing EMR profile (patient has none) is treated as no allergies and is not an error.
  - upsert_patient_profile(): the allergies merge path now calls _norm_allergy_list() so a comma-string POSTed by the browser is always persisted as a proper list.

- **portals/landing.py**
  - /doctor/add_prescription: the JWT proxy path now forwards **all** backend responses (including 409) to the browser. The file-based fallback path has been replaced with a **503** error directing the doctor to retry, so the safety check can never be silently bypassed in degraded mode.

- **portals/templates/doctor_prescriptions.html**
  - On 409 llergy_conflict response, renders an inline conflict panel using .alert-danger (high) and .alert-warning (moderate) — no auto-dismiss. A confirmation checkbox appears below; button text changes to "Confirm & Create Prescription". Re-submission with checkbox checked sends override_allergy_check: true. Editing any medication name clears the stale panel.

- **portals/templates/emr.html**
  - Fixed allergy display: profile.allergies (now a list) is joined with ', ' before being written to the #emr-allergies input and rendered in the medical history view.

- **	ests/test_emr_api.py**
  - Added TestNormAllergyList (9 unit tests) and TestCheckAllergyConflicts (13 unit tests) for the new pure functions.
  - Added TestAllergyConflictPrescriptions (8 integration tests) covering: 409 on conflict, nothing written on 409, 201+override, prescription stored on override, audit log entry on override, no-allergy patient, no-profile patient, comma-string normalisation round-trip.
