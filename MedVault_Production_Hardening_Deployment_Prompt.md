# MedVault — Production Hardening & Real Deployment — Implementation Prompt

> **How to use this file:** Paste this entire document as the first message to a
> coding agent (Claude Code, Cursor, etc.) that has file access to the
> `medical-data-decentralisation-main` codebase. It assumes the agent has **no
> prior context** on this project and may not be a strong programmer — every
> step below spells out the exact file, the exact current text, and the exact
> replacement, so it can be followed mechanically.
>
> **Ground rules for the agent:**
> 1. Do the steps **in order**. Later steps assume earlier ones are done.
> 2. After **every** step, run the command given in that step's "Verify" box
>    before moving on. If it fails, STOP and show the exact error — do not
>    guess a fix or skip ahead.
> 3. Never delete a file before confirming (via `grep`) that nothing else in
>    the repo imports/uses it.
> 4. At the very end, run the full checklist in **Section 9** before saying
>    "done."
> 5. If any instruction here conflicts with something you observe in the
>    actual code, trust the actual code — but flag the conflict clearly
>    instead of silently choosing one or the other.

---

## 0. THE GOAL, IN ONE SENTENCE

Take MedVault from **"a Docker Compose demo that only works on one machine
because two portals talk to the backend over plaintext HTTP using a
same-host-only API key file"** to **"a properly networked, HTTPS-terminated,
health-checked, fail-fast-on-misconfiguration deployment that a stranger could
stand up on a fresh Linux server following only the README."**

This does **not** try to make MedVault legally fit to store real patients'
protected health information (that would need a compliance review — BAAs,
audit retention policy, encrypted backups, penetration testing — which is out
of scope here). This prompt closes the concrete, verified engineering gaps
that stand between "works when I run it locally" and "works when deployed."

---

## 1. CURRENT STATE — VERIFIED AGAINST SOURCE

Everything below was confirmed by reading the actual files (not assumed) and,
where marked **LIVE-TESTED**, by actually installing dependencies, standing up
a real PostgreSQL instance, and running the app/tests against it.

### 1.1 What exists today

Four Flask apps, containerized with Gunicorn via `docker-compose.yml`:

| Service | File | Port | Purpose |
|---|---|---|---|
| Backend API | `server/server.py` (3,450 lines) | 5000 | JWT/API-key auth, crypto relay, all Postgres access via `server/db.py` |
| Patient Portal | `portals/patient_portal.py` | 5001 | Patient-facing UI, calls Backend over HTTP |
| Doctor Portal | `portals/doctor_portal.py` | 5002 | Doctor-facing UI, calls Backend over HTTP |
| Landing Page | `portals/landing.py` | 5003 | Public entry (login/register), calls Backend and Doctor Portal over HTTP |

**LIVE-TESTED:** the test suite genuinely passes — `99 passed` — but **only**
once a real `DATABASE_URL` pointing at a live Postgres instance is exported
before running pytest. Running `pytest` with no DB configured fails 56 of 99
tests with `RuntimeError: Database not initialized` — this is expected
behavior (the DB really is required), not a bug, but it means "the tests
pass" is not something you can verify without a database.

### 1.2 The exact blockers, each verified by reading the code

1. **`network_mode: host` on every one of the 5 services in
   `docker-compose.yml`** (lines 4, 23, 36, 48, 60). This throws away Docker's
   entire network isolation model: every container shares the host's network
   namespace, ports must never collide with anything else running on the
   host, and the setup cannot be moved to any multi-host or orchestrated
   environment (Swarm, Kubernetes, ECS, etc.) without a rewrite. Confirmed by
   reading `docker-compose.yml` directly.

2. **`network_mode: host` is not a style choice — it is a workaround for a
   real bug: the portal-to-portal and portal-to-backend URLs are hardcoded to
   `127.0.0.1`, not to Docker service names.** Confirmed by `grep`:
   - `portals/auth_utils.py:19` — `LANDING_URL = "http://127.0.0.1:5003"` (no
     env override at all).
   - `portals/landing.py:70` — `BACKEND = os.environ.get("SERVER_BASE",
     "http://127.0.0.1:5000")` (has an env override, at least).
   - `portals/landing.py:1472` — `DOCTOR_PORTAL = "http://127.0.0.1:5002"` (no
     env override at all).
   - `portals/patient_portal.py:26,28` and `portals/doctor_portal.py:29,31` —
     same pattern, `BACKEND` is env-overridable but `LANDING` is not.
   - `server/server.py:2964` — the Content-Security-Policy header hardcodes
     `connect-src 'self' http://127.0.0.1:5000` with no env override.
   Because everything is pinned to `127.0.0.1`, the only way for these
   services to actually reach each other in separate containers is to share
   the host's network stack — hence `network_mode: host`.

3. **A more serious, currently-invisible bug: three of the four services read
   the shared API key from the wrong place, and it will silently break in any
   config where `FLASK_ENV` is not `development`.** Confirmed by reading all
   four files:
   - `portals/auth_utils.py:136-140` — correctly reads `SERVER_API_KEY` from
     the environment first, falling back to `server/api_key.txt` only in dev
     mode. **This is the correct pattern and the one to copy everywhere.**
   - `portals/landing.py:79-81`, `portals/patient_portal.py:51-53`,
     `portals/doctor_portal.py:59-61` — each defines its **own** local
     `_api_key()` helper that does this instead:
     ```python
     def _api_key():
         kf = os.path.join(ROOT, "server", "api_key.txt")
         return open(kf).read().strip() if os.path.exists(kf) else ""
     ```
     This **never checks `SERVER_API_KEY` at all.** Today it "works" only
     because (a) `.env.example` ships with `FLASK_ENV=development`, which
     makes `server/server.py` write `api_key.txt` to disk on first run, and
     (b) `docker-compose.yml` bind-mounts the whole repo (`volumes: -
     .:/app`) into all four containers, so they all happen to see the same
     generated file. **The moment someone sets `FLASK_ENV=production` and
     `SERVER_API_KEY=<a-real-key>` (i.e. does exactly what `CHANGES.md`'s
     fix C1 tells them to do), `api_key.txt` is never created, `_api_key()`
     returns `""` in three of the four services, and every portal-to-backend
     call gets HTTP 401.** This is a real, reproducible landmine, not a
     hypothetical.

4. **No TLS anywhere.** `server/server.py`'s security-headers function only
   sets `Strict-Transport-Security` when the env var `BEHIND_TLS_PROXY` is
   set — but nothing in `docker-compose.yml`, `Dockerfile`, or any other file
   in the repo ever sets up a TLS-terminating proxy. Confirmed: no nginx,
   Caddy, Traefik, or certificate tooling anywhere in the repo. Today,
   everything really does run over plain HTTP.

5. **Only the `postgres` service has a healthcheck.** Confirmed by reading
   `docker-compose.yml`: `backend`, `patient_portal`, `doctor_portal`, and
   `landing` all have `restart: unless-stopped` but no `healthcheck:` block,
   and `depends_on:` for the three portal services lists `backend` with no
   `condition:`, meaning Compose only waits for the **container to start**,
   not for the **Flask app inside it to actually be answering requests**. A
   slow-starting or silently-broken backend (see point 3) will not be
   detected or retried.

6. **`init_db()` failure is swallowed, not fatal, in the backend itself.**
   `server/server.py:154-159`:
   ```python
   try:
       init_db()
       print("[DB] PostgreSQL connected ✓")
   except RuntimeError as _db_err:
       print(f"[DB] WARNING: {_db_err}")
       print("[DB] Server will start but DB operations will fail until DATABASE_URL is set.")
   ```
   This means a backend with a broken `DATABASE_URL` will still bind its port
   and look "up" to Docker/any load balancer, while every real request 500s.
   Combined with point 5 (no healthcheck), nothing in the stack will ever
   notice this failure mode.

7. **Three "TODO, not yet migrated" authorization bypasses still exist**,
   confirmed by reading `CHANGES.md` fixes M6, L4, L5 against the actual code
   in `server/server.py`:
   - `doctor_notes_for_patient()` — if the request carries **no JWT** (only an
     API key), it is allowed through with a code comment: *"still allowed for
     portal-to-portal calls, TODO: remove once portals migrate to JWT."*
   - `get_profile_photo()` — same pattern: API-key-only requests bypass the
     JWT ownership check.
   - `serve_note_image()` — same pattern: requests without a JWT skip the
     "is this really the owning patient or doctor" check.
   These exist specifically because the portals call the backend
   server-to-server using only the shared API key, not a per-user JWT. They
   are a real, scoped authorization gap, not a hypothetical one.

8. **`requirements.txt` lists five packages that are never imported anywhere
   in the codebase**, confirmed with `grep -rl "import fastapi\|import
   uvicorn\|import starlette\|import cv2\|import numpy\|import whois"`
   returning **zero matches**: `fastapi`, `uvicorn`, `starlette`,
   `opencv-python` (imports as `cv2`), `numpy`, `python-whois`. These bloat
   the image, slow every rebuild, and widen the attack surface for no
   benefit.

9. **`.env.example` ships `FLASK_ENV=development` as the default**, and has no
   entry at all for `MEDVAULT_ALLOWED_ORIGINS` or `BEHIND_TLS_PROXY` — so
   anyone who copies `.env.example` to `.env` and fills in only the values
   that are visibly blank (`SERVER_API_KEY`, `JWT_SECRET`) will, without
   realizing it, deploy in development mode with the plaintext-HTTP CORS
   defaults from point 2 above.

### 1.3 What is already good (do not touch / do not re-fix)

- `docker-compose.yml`'s `postgres` service already has a correct
  `healthcheck:` using `pg_isready`.
- `MEDVAULT_ALLOWED_ORIGINS` (CORS whitelist) is **already** environment-
  configurable in both `server/server.py` and `portals/auth_utils.py` — do
  not rebuild this, just make sure it gets set correctly in `.env` (Step 6).
- The JWT/session/crypto logic itself (Argon2id, AES-256-GCM, 4096-bit RSA,
  atomic JSON writes, rate limiting, refresh-token rotation) is solid and
  **out of scope for this prompt** — do not modify `common/crypto_utils.py`
  or `common/secure_key_store.py`.
- `Dockerfile` and the Gunicorn commands in `docker-compose.yml` are correct
  and tested — do not change the `command:` lines.

---

## 2. STEP-BY-STEP FIX PLAN — OVERVIEW

Do these in order. Each has its own detailed section below.

| Step | What | Files touched |
|---|---|---|
| 1 | Centralize API-key retrieval so all 4 services read `SERVER_API_KEY` correctly | `portals/patient_portal.py`, `portals/doctor_portal.py`, `portals/landing.py` |
| 2 | Replace hardcoded `127.0.0.1` cross-service URLs with env vars, defaulting to Docker service names | `portals/auth_utils.py`, `portals/landing.py`, `server/server.py` |
| 3 | Remove `network_mode: host`, use a proper Docker bridge network with service names | `docker-compose.yml` |
| 4 | Add an nginx reverse proxy for TLS termination | `docker-compose.yml`, new `nginx/nginx.conf`, new `nginx/Dockerfile` |
| 5 | Add healthchecks to all app services and fix `depends_on` conditions | `docker-compose.yml`, `server/server.py`, `portals/*.py` |
| 6 | Fix `.env.example` defaults and make prod-mode fail fast instead of degrade silently | `.env.example`, `server/server.py` |
| 7 | Close the three remaining API-key-only auth bypasses | `server/server.py` |
| 8 | Remove the five unused dependencies | `requirements.txt` |
| 9 | Final verification checklist | (all) |

---

## 3. STEP 1 — Fix API-key retrieval in the three broken portals

**Why:** see finding 1.3 above. Right now three of four services will
silently send an empty `X-API-Key` header the moment the project is run in a
real production configuration.

**What to do:**

1. Open `portals/auth_utils.py`. Find the correct, already-working pattern at
   lines 136-140 (search for `[C1] Prefer SERVER_API_KEY env var`). Copy that
   exact logic into a new shared function in this same file, right below the
   existing `ALLOWED_ORIGINS` block:

   ```python
   import os as _os

   def get_server_api_key() -> str:
       """
       Single source of truth for the shared backend API key.
       Prefers the SERVER_API_KEY environment variable. Falls back to
       server/api_key.txt only when FLASK_ENV=development, matching the
       backend's own fallback behavior in server/server.py.
       """
       key = _os.environ.get("SERVER_API_KEY", "")
       if key:
           return key
       if _os.environ.get("FLASK_ENV", "production") == "development":
           _root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
           _kf = _os.path.join(_root, "server", "api_key.txt")
           if _os.path.exists(_kf):
               with open(_kf, "r") as _f:
                   return _f.read().strip()
       return ""
   ```

2. In `portals/landing.py`, find the `_api_key()` function (around line 79).
   Replace its body so it calls the new shared helper instead of reading the
   file directly:

   **Find:**
   ```python
   def _api_key():
       kf = os.path.join(ROOT, "server", "api_key.txt")
       return open(kf).read().strip() if os.path.exists(kf) else ""
   ```

   **Replace with:**
   ```python
   from auth_utils import get_server_api_key

   def _api_key():
       return get_server_api_key()
   ```

   (If `auth_utils` is not already imported at the top of `portals/landing.py`,
   add `from auth_utils import get_server_api_key` near the top instead of
   inline — check the top of the file for an existing `from auth_utils
   import ...` line and add to it rather than creating a duplicate import.)

3. Do the exact same replacement in `portals/patient_portal.py` (its
   `_api_key()` is around line 51) and `portals/doctor_portal.py` (around
   line 59).

4. Search the whole repo for any other place that opens `api_key.txt`
   directly instead of calling this helper:
   ```
   grep -rn "api_key.txt" --include="*.py" .
   ```
   Any hit inside `portals/` or `client/` or `doctor/` that isn't inside
   `server/server.py` itself (which is allowed to manage its own key file)
   should be routed through `get_server_api_key()` the same way.

**Verify:**
```bash
grep -rn "def _api_key" portals/*.py
# every result should show a one-line function calling get_server_api_key()
```
Then, with a real Postgres running and `.env` containing `SERVER_API_KEY=test123`
and `FLASK_ENV=production` and **no** `server/api_key.txt` file present,
start all four services and confirm a login through the landing page
succeeds end-to-end (this proves portal→backend calls are authenticating
correctly without the file fallback).

---

## 4. STEP 2 — Replace hardcoded `127.0.0.1` URLs with configurable ones

**Why:** see finding 1.2. This is the actual root cause that forced
`network_mode: host` — fix this first so Step 3 (removing host networking)
is safe.

**What to do:**

1. `portals/auth_utils.py` line 19:

   **Find:**
   ```python
   LANDING_URL = "http://127.0.0.1:5003"
   ```

   **Replace with:**
   ```python
   import os
   LANDING_URL = os.environ.get("LANDING_URL", "http://127.0.0.1:5003")
   ```
   (If `import os` already exists near the top of the file, don't duplicate
   it — just add the `LANDING_URL = os.environ.get(...)` line in place of the
   hardcoded string.)

2. `portals/landing.py` line 1472:

   **Find:**
   ```python
   DOCTOR_PORTAL = "http://127.0.0.1:5002"
   ```

   **Replace with:**
   ```python
   DOCTOR_PORTAL = os.environ.get("DOCTOR_PORTAL_URL", "http://127.0.0.1:5002")
   ```

3. `server/server.py` around line 2964 (inside the Content-Security-Policy
   string in the `security_headers()` function):

   **Find:**
   ```python
   f"connect-src 'self' http://127.0.0.1:5000; "
   ```

   **Replace with:**
   ```python
   f"connect-src 'self' {os.environ.get('BACKEND_PUBLIC_URL', 'http://127.0.0.1:5000')}; "
   ```

4. Now add the four new environment variables to `docker-compose.yml`, in
   the `env_file: .env` block of each relevant service (or directly under
   `environment:` if you prefer — either works with Compose). Add to the
   **backend**, **patient_portal**, **doctor_portal**, and **landing**
   services:
   ```yaml
   environment:
     SERVER_BASE: http://backend:5000
     LANDING_URL: http://landing:5003
     DOCTOR_PORTAL_URL: http://doctor_portal:5002
     BACKEND_PUBLIC_URL: http://backend:5000
   ```
   (`SERVER_BASE` already works today because `landing.py`, `patient_portal.py`,
   and `doctor_portal.py` already read it from the environment — only add it
   here for clarity/completeness alongside the three new ones.)

**Verify:**
```bash
grep -rn "127\.0\.0\.1\|localhost" portals/*.py server/server.py | grep -v "app.run\|print("
```
Every remaining hit should now be inside a `.get(..., "http://127.0.0.1:...")`
default value, never a bare hardcoded assignment used at runtime.

---

## 5. STEP 3 — Remove `network_mode: host`, use a real bridge network

**Why:** see finding 1.1. Now that Step 2 makes every cross-service URL
configurable, the services can talk to each other by Docker service name
instead of sharing the host network.

**What to do:**

1. Open `docker-compose.yml`. For **each** of the 5 services (`postgres`,
   `backend`, `patient_portal`, `doctor_portal`, `landing`), delete the line
   `network_mode: host`.

2. Add a `ports:` mapping to each service that previously relied on host
   networking to expose a port, and add a shared network at the bottom:

   ```yaml
   services:
     postgres:
       image: postgres:16
       restart: unless-stopped
       environment:
         POSTGRES_USER: ${POSTGRES_USER}
         POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
         POSTGRES_DB: ${POSTGRES_DB}
       volumes:
         - pgdata:/var/lib/postgresql/data
       healthcheck:
         test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
         interval: 5s
         timeout: 5s
         retries: 10
       networks:
         - medvault_net

     backend:
       build: .
       restart: unless-stopped
       depends_on:
         postgres:
           condition: service_healthy
       env_file: .env
       environment:
         DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
       volumes:
         - .:/app
       working_dir: /app/server
       command: gunicorn --bind 0.0.0.0:5000 server:app --workers 3 --timeout 60
       networks:
         - medvault_net

     patient_portal:
       build: .
       restart: unless-stopped
       depends_on:
         backend:
           condition: service_healthy
       env_file: .env
       environment:
         SERVER_BASE: http://backend:5000
         LANDING_URL: http://landing:5003
       volumes:
         - .:/app
       working_dir: /app/portals
       command: gunicorn --bind 0.0.0.0:5001 patient_portal:app --workers 2 --timeout 60
       networks:
         - medvault_net

     doctor_portal:
       build: .
       restart: unless-stopped
       depends_on:
         backend:
           condition: service_healthy
       env_file: .env
       environment:
         SERVER_BASE: http://backend:5000
         LANDING_URL: http://landing:5003
       volumes:
         - .:/app
       working_dir: /app/portals
       command: gunicorn --bind 0.0.0.0:5002 doctor_portal:app --workers 2 --timeout 60
       networks:
         - medvault_net

     landing:
       build: .
       restart: unless-stopped
       depends_on:
         backend:
           condition: service_healthy
         doctor_portal:
           condition: service_healthy
       env_file: .env
       environment:
         SERVER_BASE: http://backend:5000
         DOCTOR_PORTAL_URL: http://doctor_portal:5002
       volumes:
         - .:/app
       working_dir: /app/portals
       command: gunicorn --bind 0.0.0.0:5003 landing:app --workers 2 --timeout 60
       networks:
         - medvault_net

   volumes:
     pgdata:

   networks:
     medvault_net:
       driver: bridge
   ```

   Note: the `condition: service_healthy` entries above **require Step 5**
   (healthchecks on `backend`, `doctor_portal`) to be done — if you do this
   step before Step 5, Compose will error saying the dependency has no
   healthcheck. Either do Step 5 first, or come back and re-check this file
   after Step 5.

3. Note that with a bridge network, `DATABASE_URL` should point at `postgres`
   (the service name), not `localhost` or `127.0.0.1`. Update `.env` (not
   `.env.example` — your actual local `.env`) accordingly:
   ```
   DATABASE_URL=postgresql://medvault_user:your_password@postgres:5432/medvault
   ```

**Verify:**
```bash
grep -n "network_mode" docker-compose.yml
# should print nothing — zero matches
docker compose config
# should parse with no errors
```

---

## 6. STEP 4 — Add an nginx reverse proxy for HTTPS

**Why:** see finding 1.4. Nothing in this repo terminates TLS today.

**What to do:**

1. Create a new directory `nginx/` at the repo root.

2. Create `nginx/nginx.conf`:
   ```nginx
   events {}

   http {
       upstream landing_upstream {
           server landing:5003;
       }
       upstream patient_upstream {
           server patient_portal:5001;
       }
       upstream doctor_upstream {
           server doctor_portal:5002;
       }
       upstream backend_upstream {
           server backend:5000;
       }

       server {
           listen 80;
           server_name _;
           return 301 https://$host$request_uri;
       }

       server {
           listen 443 ssl;
           server_name _;

           ssl_certificate     /etc/nginx/certs/fullchain.pem;
           ssl_certificate_key /etc/nginx/certs/privkey.pem;
           ssl_protocols TLSv1.2 TLSv1.3;

           location /api/ {
               proxy_pass http://backend_upstream/;
               proxy_set_header Host $host;
               proxy_set_header X-Real-IP $remote_addr;
               proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
               proxy_set_header X-Forwarded-Proto $scheme;
           }

           location /doctor/ {
               proxy_pass http://doctor_upstream/;
               proxy_set_header Host $host;
               proxy_set_header X-Forwarded-Proto $scheme;
           }

           location /patient/ {
               proxy_pass http://patient_upstream/;
               proxy_set_header Host $host;
               proxy_set_header X-Forwarded-Proto $scheme;
           }

           location / {
               proxy_pass http://landing_upstream/;
               proxy_set_header Host $host;
               proxy_set_header X-Forwarded-Proto $scheme;
           }
       }
   }
   ```
   This is a starting point — the exact `location` prefixes should match
   however the four Flask apps actually expect to be reached (check each
   app's routes for any path-prefix assumptions before finalizing). Flag this
   to the user rather than guessing silently if routes don't cleanly map to
   `/api/`, `/doctor/`, `/patient/`.

3. Add a `nginx` service to `docker-compose.yml`:
   ```yaml
     nginx:
       image: nginx:alpine
       restart: unless-stopped
       depends_on:
         - landing
         - patient_portal
         - doctor_portal
         - backend
       ports:
         - "80:80"
         - "443:443"
       volumes:
         - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
         - ./certs:/etc/nginx/certs:ro
       networks:
         - medvault_net
   ```

4. For a real domain, use **certbot** (Let's Encrypt) to populate `./certs/`
   with `fullchain.pem` and `privkey.pem` — this requires a real public
   domain name pointed at the server's IP; document this requirement to the
   user rather than trying to fake it. For local/demo testing without a
   domain, generate a self-signed cert:
   ```bash
   mkdir -p certs
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout certs/privkey.pem -out certs/fullchain.pem \
     -subj "/CN=localhost"
   ```
   and tell the user their browser will show a certificate warning, which is
   expected for self-signed certs.

5. Add `BEHIND_TLS_PROXY=true` to `.env.example` (this makes
   `server/server.py`'s existing HSTS logic — see finding 1.4 — turn on).

**Verify:**
```bash
docker compose up -d nginx
curl -vk https://localhost/ 2>&1 | grep "HTTP/"
# should show a response over HTTPS (self-signed warning is expected in curl -k mode)
```

---

## 7. STEP 5 — Add healthchecks and fix `depends_on`

**Why:** see findings 1.5 and 1.6. Right now Compose has no way to know a
service is actually ready, only that its container process has started.

**What to do:**

1. Each of the four Flask apps needs a lightweight `/health` (or `/healthz`)
   route that returns HTTP 200 only when the app can actually serve traffic.
   For the **backend**, this should also confirm the DB pool is alive. Add
   this to `server/server.py` (put it near the other route definitions, not
   at the very top before Flask is initialized):
   ```python
   @app.route("/health")
   def health_check():
       try:
           with db_cursor(commit=False) as cur:
               cur.execute("SELECT 1")
           return jsonify({"status": "ok"}), 200
       except Exception as e:
           return jsonify({"status": "error", "detail": str(e)}), 503
   ```

2. Add a simpler version (no DB check needed) to each portal —
   `portals/patient_portal.py`, `portals/doctor_portal.py`,
   `portals/landing.py`:
   ```python
   @app.route("/health")
   def health_check():
       return jsonify({"status": "ok"}), 200
   ```
   (Make sure `jsonify` is already imported in each file — it should be,
   since they're all Flask apps handling JSON; if not, add `from flask import
   jsonify` to the existing Flask import line rather than a new import line.)

3. Add a `healthcheck:` block to `backend`, `patient_portal`,
   `doctor_portal`, and `landing` in `docker-compose.yml`:
   ```yaml
       healthcheck:
         test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"]
         interval: 10s
         timeout: 5s
         retries: 5
         start_period: 15s
   ```
   (Change the port number in the `urlopen` URL to match each service — 5000
   for backend, 5001 for patient_portal, 5002 for doctor_portal, 5003 for
   landing.)

4. Go back to the `depends_on:` blocks written in Step 3 and confirm every
   `condition: service_healthy` now has a matching `healthcheck:` on the
   depended-upon service. `backend` depends on `postgres` (already has a
   healthcheck). `patient_portal`, `doctor_portal`, `landing` depend on
   `backend` (now has one from this step). `landing` additionally depends on
   `doctor_portal` (now has one from this step).

**Verify:**
```bash
docker compose up -d
sleep 20
docker compose ps
# every service should show "healthy" in the STATUS column, not just "Up"
```

---

## 8. STEP 6 — Fix `.env.example` defaults, fail fast in production mode

**Why:** see findings 1.6 and 1.9. A blank/misconfigured production
environment should refuse to start, not limp along and 500 on every DB
request.

**What to do:**

1. Rewrite `.env.example` to:
   ```
   # Set to "production" for any real deployment. "development" enables
   # dev-only fallbacks (reading api_key.txt from disk, verbose OTP logging)
   # that must never be used outside a local machine.
   FLASK_ENV=production

   DATABASE_URL=postgresql://medvault_user:CHANGE_ME@postgres:5432/medvault
   POSTGRES_USER=medvault_user
   POSTGRES_PASSWORD=CHANGE_ME
   POSTGRES_DB=medvault

   # Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
   SERVER_API_KEY=

   # Generate with: python3 -c "import secrets; print(secrets.token_hex(64))"
   JWT_SECRET=

   # Comma-separated list of origins allowed to call the backend/portals.
   # Use your real domain(s) in production, e.g.:
   # MEDVAULT_ALLOWED_ORIGINS=https://medvault.example.com
   MEDVAULT_ALLOWED_ORIGINS=http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003

   # Set to "true" once nginx (or another TLS-terminating proxy) is in front
   # of this stack, so HSTS headers are safe to send.
   BEHIND_TLS_PROXY=false
   ```

2. In `server/server.py`, change the swallowed `init_db()` failure (finding
   1.6) so that it is only swallowed in development mode:

   **Find:**
   ```python
   try:
       init_db()
       print("[DB] PostgreSQL connected ✓")
   except RuntimeError as _db_err:
       print(f"[DB] WARNING: {_db_err}")
       print("[DB] Server will start but DB operations will fail until DATABASE_URL is set.")
   ```

   **Replace with:**
   ```python
   try:
       init_db()
       print("[DB] PostgreSQL connected ✓")
   except RuntimeError as _db_err:
       if os.environ.get("FLASK_ENV", "production") == "development":
           print(f"[DB] WARNING: {_db_err}")
           print("[DB] Server will start but DB operations will fail until DATABASE_URL is set.")
       else:
           # In any non-development environment, a broken DB connection at
           # startup must stop the process — not serve traffic that will
           # 500 on every request.
           raise
   ```

3. Similarly, check `_get_jwt_secret()` (around line 461) and the
   `SERVER_API_KEY` block (around line 88) — both already print a `[WARN]`
   when falling back to an auto-generated dev secret. Add the same
   production-mode hard-fail there: if `FLASK_ENV` is not `development` and
   no `JWT_SECRET`/`SERVER_API_KEY` env var is set, `raise RuntimeError(...)`
   instead of only printing a warning and continuing. This matches the
   pattern already used for `api_key.txt` in point 3 of Section 1.2 — extend
   the same fail-fast logic to the JWT secret path for consistency.

**Verify:**
```bash
FLASK_ENV=production DATABASE_URL=postgresql://bad:bad@nowhere:5432/x python3 server/server.py
# should crash immediately with a clear RuntimeError, not print a warning and hang
```

---

## 9. STEP 7 — Close the remaining API-key-only auth bypasses

**Why:** see finding 1.7. These three endpoints still trust a shared API key
alone (no per-user JWT) for backward compatibility with the old portal calls.
Steps 1-3 just made every portal-to-backend call capable of also carrying a
JWT for the logged-in user, so this compatibility path can now be retired.

**What to do (for each of the three endpoints named in finding 1.7):**

1. Find each function in `server/server.py`: `doctor_notes_for_patient()`,
   `get_profile_photo()`, `serve_note_image()`.

2. In each, locate the `TODO` comment describing the API-key-only fallback
   and the `if` branch that allows the request through without a JWT. Change
   the logic so a missing/invalid JWT always returns HTTP 401, matching how
   every other JWT-protected endpoint in the file already behaves — copy the
   pattern from a neighboring, already-strict endpoint in the same file
   rather than inventing a new one.

3. Grep the portals to confirm every caller of these three endpoints already
   sends a `Authorization: Bearer <jwt>` header, not just `X-API-Key`:
   ```bash
   grep -n "doctor_notes_for_patient\|get_profile_photo\|serve_note_image" -r portals/
   ```
   For each call site found, confirm the request includes the logged-in
   user's JWT (check how nearby, already-JWT-only endpoints are called from
   the same file, and copy that pattern). If any call site is missing this,
   add the JWT header there **before** tightening the backend check, or the
   portal itself will break.

**Verify:**
```bash
FLASK_ENV=development DATABASE_URL=<your test db url> python3 -m pytest tests/ -v
# all tests should still pass — if any fail here, a portal call site was
# missed in the step above and needs its JWT header added
```

---

## 10. STEP 8 — Remove unused dependencies

**Why:** see finding 1.8. Zero import sites found for these five packages.

**What to do:**

1. Open `requirements.txt` and delete these lines: `fastapi==0.115.5`,
   `uvicorn==0.32.1`, `starlette==0.41.3`, `opencv-python==4.11.0.86`,
   `numpy==2.2.6`, `python-whois==0.9.4`.

2. Before finalizing, re-run the grep from finding 1.8 one more time to be
   certain nothing new was missed:
   ```bash
   grep -rln "import fastapi\|import uvicorn\|import starlette\|import cv2\|import numpy\|import whois" --include="*.py" .
   ```
   This must return nothing before you delete the lines.

**Verify:**
```bash
pip install -r requirements.txt --break-system-packages -q
FLASK_ENV=development DATABASE_URL=<your test db url> python3 -m pytest tests/ -v
# should still be 99 passed — proves nothing actually depended on the removed packages
```

---

## 11. STEP 9 — FINAL VERIFICATION CHECKLIST

Do not report this task as complete until every item below is checked, in a
fresh environment (ideally: destroy all containers/volumes and start clean).

```bash
docker compose down -v
docker compose up -d --build
sleep 30
docker compose ps
```

- [ ] Every service in `docker compose ps` shows `healthy`, not just `Up`.
- [ ] `docker compose config` shows no `network_mode: host` anywhere.
- [ ] `curl -k https://localhost/` returns the landing page over HTTPS.
- [ ] `curl http://localhost/` (port 80) redirects to `https://`.
- [ ] With `.env` set to `FLASK_ENV=production`, `SERVER_API_KEY=<a real
      value>`, and **no** `server/api_key.txt` file present anywhere, a full
      patient registration → doctor access request → doctor views patient
      data flow works end-to-end through the UI.
- [ ] Stopping the `postgres` container and restarting `backend` causes
      `backend` to **fail to start** (not silently serve broken responses) —
      confirming Step 6's fail-fast change works.
- [ ] `python3 -m pytest tests/ -v` still shows all tests passing.
- [ ] `grep -rn "network_mode\|127\.0\.0\.1" docker-compose.yml` shows no
      hardcoded host-only assumptions remain in the compose file itself
      (URLs inside app code defaults are fine — only `docker-compose.yml`
      needs to be clean).
- [ ] `requirements.txt` no longer lists `fastapi`, `uvicorn`, `starlette`,
      `opencv-python`, `numpy`, or `python-whois`.

If every box above is checked, report back with a short summary of what
changed and paste the final `docker compose ps` output showing all services
healthy. If any box cannot be checked, stop and report exactly which one and
why, rather than marking the task done anyway.
