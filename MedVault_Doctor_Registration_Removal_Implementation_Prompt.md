# MedVault — Replace Doctor Self-Registration with Admin-Mediated Account Creation — Implementation Prompt

> **How to use this file:** Paste this entire document as the first message to a new Claude session with access to the MedVault codebase. It is self-contained: it documents the exact current registration flow (verified against source), specifies what to remove, and specifies the new admin-mediated flow to build in its place, with concrete decisions already made so no clarifying questions are needed to start. Execute in the order given in §8.

---

## 0. THE CHANGE, IN ONE SENTENCE

Doctors will no longer be able to create their own account from the public landing page. Instead, a doctor contacts the MedVault team, the team verifies their identity/credentials manually (outside the app), and a team member with an `admin` or `receptionist` role logs in and creates the doctor's account on their behalf from a new internal screen.

---

## 1. CURRENT STATE — VERIFIED AGAINST SOURCE

MedVault runs as **two cooperating Flask processes**: `portals/landing.py` (the public-facing portal, default port 5003) makes HTTP calls to `server/server.py` (the backend/API process, referenced as `BACKEND = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")` at `portals/landing.py:70`). Any change to registration must be made in **both** processes — a common mistake would be to only edit one side and leave a dangling call to the other.

### 1.1 Today's doctor self-registration flow

- **Frontend form:** `portals/templates/landing.html`, inside `<div id="role-register">` (line ~329). A role-selector tab bar (`.auth-tab-switcher`, lines ~334–337) toggles between `data-reg-role="patient"` and `data-reg-role="doctor"`. When "Doctor" is selected, a hidden block `<div id="doctor-fields">` (lines ~354–363) is revealed, adding `Specialization` and `Hospital / Clinic` fields to the same form used for patient registration. The submit handler (inline `<script>`, around line ~514–532) reads `role` from the hidden `#reg-role` field and posts to `role === 'doctor' ? '/register/doctor' : '/register/patient'`.
- **Portal route:** `portals/landing.py:573`, `@app.route("/register/doctor", methods=["POST"]) def register_doctor():`. This function:
  1. Validates name/email/username/password from the request body.
  2. Generates an RSA keypair for the doctor (`generate_rsa_keypair()`), derives a KEK from the doctor's own chosen password, wraps the private key, and stores it via `SecureKeyStore.store_private_key(f"doctor__{doctor_code}", wrapped...)`.
  3. Writes `doctor_data.json` and `doctor_public.pem` to a local folder under `DOCTORS_DIR`.
  4. Calls the backend at `{BACKEND}/register_doctor` (best-effort) and `{BACKEND}/internal/register_user_db` to create the `users` table row with `role="doctor"`.
  5. Immediately logs the new doctor in: sets a full session (`session["logged_in"] = True`, etc.) and fetches a JWT via `{BACKEND}/auth/login`, then redirects to `/dashboard`.
- **Backend routes:** `server/server.py:1380` (`/register_doctor`) and `server/server.py:1926` (`/internal/register_user_db`) — both currently reachable with no authentication, since they exist to support the public self-registration flow above.
- **Schema:** `server/schema.sql:8-26` — the `users` table already has a `role` column constrained to `CHECK (role IN ('patient','doctor','admin','receptionist'))`. **`admin` and `receptionist` already exist as valid roles today**, but there is currently **no code path anywhere in the repository that creates an admin or receptionist account** — these are presumably seeded directly in the database by whoever operates the deployment. This implementation must not assume any admin-account-creation UI exists; it only needs to assume admin/receptionist accounts already exist and can log in.
- There is **no** `must_change_password`-style flag on `users` today, and **no working email-delivery mechanism** in the codebase — OTP codes are currently only printed to the server console in development (`server/server.py:1850`, `print(f"[DEV OTP] {email} → {otp}")`). Do not assume you can silently email a doctor their new credentials; design around this constraint explicitly (see §3.3).
- **Role-gating already exists and should be reused:** `server/server.py:548`, `_require_jwt(roles=None)` — a decorator that returns `{"error": "forbidden", "required_roles": roles}` (403) when the caller's role doesn't match. Use this exact decorator for the new admin-only endpoint rather than writing new auth-checking logic.
- **Audit logging already exists and should be reused:** `server/server.py:375`, `def audit(action, actor="", target="", detail="", ip="")`, writing to the `audit_log` table. Every account-creation action in this feature must call this.

### 1.2 What is explicitly NOT changing

- Patient self-registration (`/register/patient`) is untouched — this task is scoped to doctors only.
- The underlying cryptographic account-creation mechanics (RSA keypair generation, KEK-wrapping, `SecureKeyStore`, `doctor_data.json`/`doctor_public.pem` files) are correct and must be preserved exactly — this is a change to *who can trigger this process and how*, not *what the process does cryptographically*.
- The `/login/upgrade` legacy-password-upgrade flow and `password_reset_required` mechanism (`server/server.py:2016`) are a different, unrelated feature (migrating old SHA-256 password hashes) — do not confuse this with the new "doctor must set their own password on first login" requirement in §3.3, which needs its own new mechanism.

---

## 2. WHY THIS CHANGE IS BEING MADE

Letting anyone claim to be a doctor and self-register — supplying only a name, specialization, and hospital as free-text fields with no verification — means the platform currently has no actual assurance that a "doctor" account holder is a real, licensed medical professional. Since doctor accounts can request access to patients' encrypted medical records, this is a meaningful trust gap for a product whose entire value proposition is patient trust and security. Moving account creation to a manual, team-verified, admin-mediated flow closes this gap: no doctor account exists in the system that a real person on the team hasn't personally verified.

---

## 3. TARGET STATE — DECISIONS MADE

### 3.1 Public-facing side: remove self-registration, add a clear path to request access

- Remove the "Doctor" tab and the `#doctor-fields` block from the registration panel in `landing.html` entirely — patients are the only self-registerable role from this point on. The registration panel's role-selector tab bar becomes unnecessary once there's only one role to register as; remove the tab bar too and simplify `#role-register` to a plain patient signup form.
- In its place, add a small, clearly visible **"Are you a doctor?"** callout inside the auth modal (near the existing login/register tabs, so it's visible regardless of which tab a doctor-inclined visitor happens to land on first) with:
  - A short sentence explaining that doctor accounts are created by the MedVault team after verifying credentials, for patient safety and trust.
  - A `mailto:` link (use a placeholder address, e.g. `doctors@medvault.example` — flag this clearly as a placeholder for the team to replace with their real contact address/process; do not invent a fake working email and present it as real) or, if the team already has a contact form elsewhere in the app, link to that instead.
- Any lingering client-side reference to `/register/doctor` (the submit handler's `role === 'doctor' ? '/register/doctor' : ...` branch) must be removed, not just hidden — since the role selector is gone, the form should unconditionally post to `/register/patient`.

### 3.2 Backend side: repurpose, don't delete, the account-creation logic

- **Do not delete** `register_doctor()` in `portals/landing.py` or `/register_doctor` / `/internal/register_user_db` in `server/server.py` — the cryptographic setup they perform is exactly what's still needed, just triggered differently.
- Change `/register_doctor` in `server/server.py` from a publicly-reachable route into an **internal-only** route: it should only ever be called server-to-server by the new admin endpoint (§3.3), never directly from a browser. Enforce this by requiring the same internal API-key header already used for other internal backend calls in this codebase (check `_headers()` in `portals/landing.py` and the existing internal-call authentication pattern used for `/internal/register_user_db` — reuse that exact pattern here rather than inventing a new one) **and** additionally requiring that the calling context has already validated an admin/receptionist JWT (done at the new endpoint in §3.3, one layer up).
- Remove the public route `portals/landing.py:573` `@app.route("/register/doctor", methods=["POST"])` entirely — the equivalent capability now lives only behind the new admin-authenticated route in §3.3. There should be no way to reach doctor-account creation without an authenticated admin/receptionist session.

### 3.3 New admin-mediated creation flow

**New backend endpoint:** `POST /admin/doctors` in `server/server.py`, decorated with `@_require_jwt(roles=["admin", "receptionist"])` (reusing the existing decorator from `server/server.py:548` exactly as-is — do not write a parallel role check).

Request body fields: `name`, `email`, `username`, `specialization`, `hospital`. **No password field** — the admin does not choose or know the doctor's permanent password. Instead:

1. Generate a cryptographically random temporary password server-side (reuse the existing `_secrets`/`secrets` module already imported in `server/server.py` — see the OTP generator at `server/server.py:400` for the existing pattern of secure random generation to follow, rather than inventing a new one).
2. Run through the same account-creation steps currently in `register_doctor()` (RSA keypair generation, KEK-wrap using the generated temporary password, `SecureKeyStore` storage, `doctor_data.json`/`doctor_public.pem` files, `users` table insert with `role="doctor"`) — extract this into a shared internal function (e.g. `_create_doctor_account(name, email, username, specialization, hospital, initial_password)`) called by the new endpoint, so the logic is written once, not duplicated between an old public route and a new internal one.
3. Add a new column to the `users` table: `must_change_password BOOLEAN DEFAULT FALSE` (add via `server/schema_additions.sql`, following its existing additive/idempotent migration style — do not edit `schema.sql`'s original `CREATE TABLE` in place, since this is a live, already-deployed table per the project's existing migration convention). Set this to `TRUE` for every account created through this new endpoint.
4. Call `audit("doctor_account_created", actor=<admin's email/username from the JWT>, target=<new doctor's email>, detail=f"Created by {admin_name} after manual verification")` (using the existing `audit()` function at `server/server.py:375`) so there is a permanent, queryable record of who created each doctor account and when — this record is itself part of what makes the new trust model auditable.
5. Return the generated temporary password **in the API response, once** — e.g. `{"doctor_code": ..., "temporary_password": ..., "message": "ok"}`. This is the only time the plaintext temporary password is ever transmitted; it must not be logged, stored anywhere in plaintext, or retrievable again after this response.

**Do not attempt to email the temporary password to the doctor.** As established in §1.1, there is no working email infrastructure in this codebase, and building one is out of scope for this task — do not silently add a fake or partial email feature. The temporary password is the admin's responsibility to relay to the doctor through whatever verified channel (phone call, in-person, secure message) the team already uses for the verification step itself.

**New portal route:** `portals/landing.py` gets a new proxying route (mirroring the existing pattern used for other admin-authenticated calls to the backend) that forwards the authenticated admin's request to `{BACKEND}/admin/doctors`, passing along the admin's JWT for the backend's `_require_jwt` check.

### 3.4 New admin-facing UI

- Add a new page/template, `portals/templates/admin_create_doctor.html`, extending `base.html` like every other page (reuse `partials/sidebar.html`/`partials/topbar.html` exactly as-is).
- Since `partials/sidebar.html` currently only branches on `role == 'patient'` / `role == 'doctor'` (verified — there is no `admin` branch today, `dashboard.html` only has a generic `{% else %}` fallback labeled "Administration"), add a new `{% elif role == 'admin' or role == 'receptionist' %}` branch to the sidebar with a "Create Doctor Account" nav item linking to this new page. Do not remove or restructure the existing patient/doctor branches.
- The form: `Full name`, `Email address`, `Username`, `Specialization`, `Hospital / Clinic` — the same fields as the old public doctor-registration form, minus the password field (per §3.3, the admin never sets it).
- On successful submission, display the returned `temporary_password` prominently in a one-time, clearly-labeled panel (e.g. "Temporary password — copy this now. It will not be shown again.") with a copy-to-clipboard button (reuse the existing `[data-copy]` pattern already implemented in `portals/static/js/app.js` for other copyable values in this app, rather than writing new clipboard-handling JS).
- Add a short confirmation reminder in the same panel telling the admin to relay this password to the doctor through a verified channel, and that the doctor will be required to set their own password on first login (per §3.5).

### 3.5 First-login forced password change

- On `POST /auth/login` (`server/server.py:1982`), after successful password verification and before issuing a normal session/JWT, check the new `must_change_password` column on the user record. If `TRUE`, return a distinct response (e.g. `{"error": "password_change_required", "temp_token": <short-lived limited-scope token>}`) rather than a normal successful login — mirroring the existing pattern already used for the legacy-hash case (`password_reset_required` at `server/server.py:2016`) so this fits the codebase's existing conventions rather than introducing a third, different shape for "you can't log in normally yet."
- Add a new endpoint, `POST /auth/set_initial_password`, accepting the `temp_token` plus a new password chosen by the doctor. On success: hash and store the new password, set `must_change_password = FALSE`, and proceed with normal login (issue the real session/JWT) — do not require the doctor to log in a second time after this step.
- On the frontend, `portals/templates/landing.html`'s login handler must detect the `password_change_required` response and show a "Set your password" form (new fields: new password + confirm) in place of the normal login form, submitting to `/auth/set_initial_password`. Reuse the existing password-strength-hint UI (`#password-strength`, already present for registration) for this new form rather than duplicating that logic.

---

## 4. FILES INVOLVED

| File | Change |
|---|---|
| `portals/templates/landing.html` | Remove doctor tab/fields from registration panel; add "Are you a doctor?" contact callout; add "set initial password" form handling to the login flow |
| `portals/landing.py` | Remove public `/register/doctor` route; add new admin-authenticated proxy route to `{BACKEND}/admin/doctors` |
| `server/server.py` | Repurpose `register_doctor()`/`/register_doctor` into an internal-only function called by a new `POST /admin/doctors` (guarded by `_require_jwt(roles=["admin","receptionist"])`); add `must_change_password` check to `/auth/login`; add new `POST /auth/set_initial_password` |
| `server/schema_additions.sql` | Add `must_change_password BOOLEAN DEFAULT FALSE` column to `users` |
| `portals/templates/admin_create_doctor.html` | New template — the admin-facing creation form and one-time temporary-password display |
| `portals/templates/partials/sidebar.html` | Add an `admin`/`receptionist` navigation branch (does not exist today) |
| `portals/static/js/app.js` | Reuse existing `[data-copy]` handler for the new temporary-password copy button; no new clipboard logic |

---

## 5. SECURITY REQUIREMENTS

- The new `/admin/doctors` endpoint must be unreachable by any role other than `admin`/`receptionist` — verify with an explicit test that a `patient` or `doctor` JWT gets a 403, not a 200.
- The temporary password must never be persisted in plaintext anywhere (not in logs, not in the `audit_log` detail field — the audit entry in §3.3 step 4 must describe the action, not include the password itself) and must never be returned again by any subsequent API call once the creation response has been sent.
- The `temp_token` issued for the forced password-change flow (§3.5) must be short-lived and scoped only to the `set_initial_password` action — it must not function as a general-purpose session token, and must be invalidated immediately after successful use (single use).
- Rate-limit `POST /admin/doctors` the same way other sensitive write endpoints in this codebase are already rate-limited (check the existing rate-limiting decorator/pattern used elsewhere in `server.py` and apply it consistently here) to prevent an admin account, if compromised, from being used to mass-create doctor accounts unnoticed.
- Every account creation through this flow must produce exactly one `audit_log` row identifying the acting admin — this is the feature's core trust guarantee and must not silently fail (if the `audit()` call's internal try/except swallows an error per its current implementation at `server/server.py:387-388`, that's acceptable for not blocking the request, but consider whether account creation without a successful audit write should instead be treated as a hard failure for this specific action, since the audit trail is the entire point of moving to this model — make an explicit decision here rather than inheriting the existing best-effort behavior by default).

---

## 6. BACKWARD COMPATIBILITY

- Existing doctor accounts (created via the old self-registration flow, with no `must_change_password` column set) must continue to log in normally — the new column defaults to `FALSE`, so existing rows are unaffected. Verify this explicitly with a test using a pre-existing doctor account fixture.
- No existing patient-registration behavior changes.
- No existing doctor-facing feature (dashboard, EMR, prescriptions, etc.) changes — this task is scoped entirely to account creation and first login.

---

## 7. HUMANIZED COPY FOR THIS FEATURE

Apply this project's established tone (warm, professional, calm, never robotic) to every new user-facing string introduced here:

- The "Are you a doctor?" callout should read as reassuring and professional, not bureaucratic — explain briefly *why* verification matters (patient trust and safety) rather than just stating a rule.
- The one-time temporary-password panel should clearly convey urgency ("copy this now") without sounding alarming.
- The forced password-change screen the doctor sees on first login should welcome them rather than reading like a generic security gate — e.g., acknowledge this is their first time signing in and that choosing their own password is the last setup step.
- Error messages (e.g., attempting to reach the removed `/register/doctor` route, or a non-admin hitting `/admin/doctors`) should never expose internal role/permission machinery to an end user in raw form — return a plain, calm explanation.

---

## 8. DELIVERABLE ORDER

1. **Schema migration** — add `must_change_password` to `server/schema_additions.sql`.
2. **Backend** — extract the shared `_create_doctor_account(...)` function; build `POST /admin/doctors`; update `/auth/login` and add `POST /auth/set_initial_password`; remove/repurpose the old public route.
3. **Portal proxy route** — new admin-authenticated route in `portals/landing.py`.
4. **Admin UI** — `admin_create_doctor.html` + sidebar branch.
5. **Public landing page changes** — remove doctor registration tab/fields; add the "Are you a doctor?" callout; add the forced-password-change UI to the login flow.
6. **Tests** — role-gating on `/admin/doctors` (403 for non-admin), successful creation end-to-end, forced first-login password change end-to-end, backward compatibility for pre-existing doctor accounts, audit log row creation.
7. **Self-audit** — confirm `/register/doctor` is no longer publicly reachable, confirm no plaintext temporary password appears in any log or audit record, confirm existing doctor/patient flows are unaffected.
