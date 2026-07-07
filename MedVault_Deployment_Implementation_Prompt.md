# MedVault — Make It Deployable (Docker + Gunicorn + Persistent Postgres) — Implementation Prompt

> **How to use this file:** Paste this entire document as the first message to a new
> Claude Code / coding-agent session with access to the MedVault codebase (the
> `medical-data-decentralisation-main` folder). It is self-contained and written so
> that every step can be executed literally, in order, without needing to make
> judgment calls. Every claim about the current code below has been verified
> against the actual source and, where noted, tested live by actually running the
> code. Do not skip ahead — later steps assume earlier steps are done.
>
> **If any command in this file produces an error that isn't covered in the
> "Troubleshooting" section at the end, STOP and show the exact error text rather
> than guessing a fix.**

---

## 0. THE GOAL, IN ONE SENTENCE

Turn MedVault from "four Python scripts you run by hand on one Windows machine"
into "one command (`docker compose up -d`) that starts a real, persistent,
production-style deployment on any Linux server," with no plaintext debug mode,
no dev-only web server, and no risk of losing patient/doctor keys on restart.

This is what was previously called **"Tier 1" deployment** — good enough to put a
real link in a conference submission or CV, demo live, and trust to survive a
restart. It is *not* a claim that this becomes suitable for real patient data —
that would need a further security hardening pass (JWT/API-key auth
unification, rate limiting review, TLS everywhere) that is explicitly **out of
scope for this task**. Say so explicitly if asked, don't oversell it.

---

## 1. CURRENT STATE — VERIFIED AGAINST SOURCE (AND LIVE-TESTED)

Read this whole section before changing anything. Every fact here was checked
against the actual files, not assumed.

### 1.1 What exists today

Four independent Flask apps, started by `START.py` as raw OS subprocesses:

| Service | File | Port | Purpose |
|---|---|---|---|
| Backend API | `server/server.py` | 5000 | All crypto-relay, DB access, JWT auth. Only service that talks to Postgres directly via a connection pool (`server/db.py`). |
| Patient Portal | `portals/patient_portal.py` | 5001 | Patient-facing UI + API |
| Doctor Portal | `portals/doctor_portal.py` | 5002 | Doctor-facing UI + API |
| Landing Page | `portals/landing.py` | 5003 | Public entry point (login/register), talks to the Doctor Portal and Backend server-to-server |

All four call `Flask(__name__)` and expose a module-level `app` object — confirmed
by grep, this matters later for how we launch them with Gunicorn.

### 1.2 The exact blockers (each one verified by reading the code or, where marked
LIVE-TESTED, by actually running it)

1. **Dev server, not production server.**
   `server/server.py:3230`: `app.run(debug=True, port=5000, use_reloader=False)`
   `portals/landing.py:3652`: `app.run(host="127.0.0.1", port=5003, debug=True, ...)`
   Flask's own documentation says never to use `app.run()` in production — it's
   single-process-ish and not hardened.

2. **`debug=True` on two of the four services.** This exposes the Werkzeug
   interactive debugger — if a request ever triggers a server-side exception,
   anyone hitting that endpoint can potentially execute arbitrary Python on the
   server. This is a real vulnerability to ship live, not a style nit.

3. **Bound to `127.0.0.1` only.** `portals/patient_portal.py:616` and
   `portals/doctor_portal.py:583` explicitly bind `host="127.0.0.1"`. On a real
   server this means the process only accepts connections from itself — nothing
   external (or in a different container) can reach it at all.

4. **No `Dockerfile`, no `docker-compose.yml`, no process manager.** Confirmed:
   there is nothing containerization-related in the repo today. `START.py`/
   `STOP.py` spawn/track raw subprocesses with a JSON PID file — this doesn't map
   to how real hosting works (containers, health checks, auto-restart).

5. **`gunicorn` is not in `requirements.txt`.** Confirmed by reading the file —
   only Flask + supporting libraries are listed, no production WSGI server.

6. **LIVE-TESTED, IMPORTANT: `init_db()` only runs correctly if Postgres is
   already up when the backend starts.** `server/server.py` calls `init_db()` at
   *import time* (line 153, not inside `if __name__ == "__main__"` — so it *does*
   run under Gunicorn, that part is fine). But if Postgres isn't reachable yet at
   that exact moment, it prints a warning and continues running with a broken DB
   layer — every DB-touching request then 500s with `RuntimeError: Database not
   initialized`. This was reproduced live: starting the backend before Postgres
   was ready caused exactly this failure; restarting the backend after Postgres
   was confirmed up fixed it immediately. **This means container startup order
   matters and must be enforced** — see §3.3.

7. **LIVE-TESTED, GOOD NEWS: no code changes are needed to run under Gunicorn.**
   `gunicorn --bind 0.0.0.0:5000 server:app` and
   `gunicorn --bind 0.0.0.0:5003 landing:app` were both tested directly against
   this codebase and worked correctly, including a full real patient→doctor
   data-sharing flow end-to-end. The `app.run(...)` lines never execute under
   Gunicorn (they're only inside `if __name__ == "__main__":`), so leaving them
   as-is is actually fine — Gunicorn ignores them entirely. **We will still turn
   off `debug=True` on those lines as defensive cleanup (§3.1), but it is not
   required for Gunicorn to work.**

8. **Hardcoded `127.0.0.1` URLs used for cross-service communication, in three
   different roles that must be told apart:**
   - `BACKEND = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")` — already
     reads an env var, appears in `server.py`, `landing.py`, `patient_portal.py`,
     `doctor_portal.py`. **Already fine, no fix needed**, as long as we set
     `SERVER_BASE` correctly in `.env` (§3.4).
   - `DOCTOR_PORTAL = "http://127.0.0.1:5002"` in `portals/landing.py:1382` — used
     **only** for server-to-server calls (`landing.py` fetching data from
     `doctor_portal.py`'s API, confirmed by checking every call site: lines 1604,
     1727, 1947, 1988 are all `requests`/`http` library calls, never a browser
     redirect). This is currently **not** read from an env var — needs fixing.
   - `LANDING = "http://127.0.0.1:5003"` in `patient_portal.py:28` and
     `doctor_portal.py:31` — used **only** for `redirect(LANDING)`, i.e. telling
     the *browser* where to go. Confirmed by checking call sites (lines 74, 130,
     131) — every use is inside a Flask `redirect(...)` call. This is a
     completely different kind of URL than `DOCTOR_PORTAL` above: it must be
     reachable **by the end user's browser**, not just by other containers.

   **Why this distinction matters for deployment:** if you get these two kinds of
   URLs mixed up (e.g. put a Docker-internal hostname into a browser redirect),
   the browser will fail to connect because it can't resolve an internal Docker
   service name. Section §3.4 handles this correctly by using **Docker "host"
   networking**, which sidesteps this whole class of mistake — explained fully
   there.

9. **No persistent storage plan.** Multiple different local directories store
   real key material and patient/doctor records outside the database:
   - `server/server.py`: `PATIENTS_DIR = SERVER_BASE_DIR/Patients`
   - `portals/landing.py` and `portals/doctor_portal.py`: `DOCTORS_DIR = ROOT/doctor/Doctors`
   - `portals/patient_portal.py`: `USERS_DIR = ROOT/client/Users`
   - `common/secure_key_store.py`: private keys stored under
     `$LOCALAPPDATA/MedVault/keys` (falls back to `$HOME/AppData/Local/MedVault/keys`
     on Linux — confirmed by reading the code and running it: it printed
     `[SecureKeyStore] Windows DPAPI not available...` and worked correctly on Linux).
   - `server/jwt_secret.txt`, `server/api_key.txt`, `server/flask_secret.key` — all
     auto-generated on first run if the matching env var isn't set, and then
     depended on for every subsequent run.

   If any of these live only *inside* a container's writable layer instead of on
   a persisted volume/bind-mount, **every container restart or redeploy silently
   and permanently loses that data** — including cryptographic keys, which would
   permanently lock everyone out of their own encrypted records. This is the
   single most important thing to get right in this whole task.

10. **`SERVER_API_KEY` / `JWT_SECRET` auto-generate as a fallback if unset**
    (`server/server.py:83-98` and `:457-465`). Fine for local dev, dangerous to
    leave implicit in production — we will make the `.env` set them explicitly
    (§3.4) so this fallback path is never actually exercised in the deployed
    version.

### 1.3 What is explicitly NOT a blocker (don't "fix" these — they're fine)

- `SERVER_BASE` env var pattern — already correct, reused across all four files.
- `MEDVAULT_ALLOWED_ORIGINS` CORS whitelist in `portals/auth_utils.py` and
  `server/server.py` — already reads from an env var with sane localhost
  defaults. Just needs the right value set in `.env` for the real deployment.
- The core cryptography (`common/crypto_utils.py`) — untouched by this task.
- Frontend templates/JS — confirmed (via grep) to use only relative fetch URLs
  like `fetch('/patient/record')`, never hardcoded absolute origins. This means
  the browser only ever talks to whichever port served the current page — no
  frontend changes needed.
- `common/secure_key_store.py`'s Linux fallback path — already works correctly
  without code changes, confirmed by actually running it.

---

## 2. THE DEPLOYMENT ARCHITECTURE WE ARE BUILDING

**One Linux server** (a $5–6/month VPS from any provider — DigitalOcean,
Hetzner, Linode, AWS Lightsail all work identically for this; get any Ubuntu
22.04 or 24.04 VPS and note its public IP address) running:

- **Docker + Docker Compose** (the only two things that need installing on the
  server itself — everything else runs inside containers).
- **5 containers**, all using Docker's **`network_mode: host`** setting:
  1. `postgres` — the database, with its data directory on a named Docker
     volume so it survives restarts.
  2. `backend` — `server/server.py`, run via Gunicorn.
  3. `patient_portal` — `portals/patient_portal.py`, run via Gunicorn.
  4. `doctor_portal` — `portals/doctor_portal.py`, run via Gunicorn.
  5. `landing` — `portals/landing.py`, run via Gunicorn.

**Why `network_mode: host` specifically (read this, it's the key design
decision):** Normally, Docker Compose gives every container its own private
network where containers reach each other by service name (e.g.
`http://backend:5000`), not `127.0.0.1`. That would require finding and fixing
*every one* of the `127.0.0.1` references identified in §1.2 point 8 — including
correctly telling apart the two different kinds of URLs (browser-facing vs.
server-to-server). That's a lot of surface area for something to go subtly
wrong, especially for someone newer to this.

`network_mode: host` instead makes each container share the **host machine's own
network stack directly** — so inside every container, `127.0.0.1` means exactly
what it already means throughout this codebase: "this same machine." Every
existing hardcoded `127.0.0.1:PORT` reference — `BACKEND`, `LANDING`,
`DOCTOR_PORTAL`, all of them — keeps working completely unchanged. We only need
to fix **one** of them (`DOCTOR_PORTAL`, to make it env-configurable for
consistency — see §3.4), and even that fix keeps `127.0.0.1` as the default.

The tradeoff, stated honestly: `network_mode: host` means container ports are
not isolated from the host's own network — this is a reasonable, common choice
for a single-server deployment like this one, but it's a deliberate
simplicity-for-safety tradeoff, not the "most correct" Docker networking
pattern. That's fine for this project's current stage.

**Persistence strategy:** rather than hunting down and separately mounting six
different scattered local-storage paths (§1.2 point 9), we bind-mount the
**entire project folder** into each app container at `/app`. Since every one of
those paths (`PATIENTS_DIR`, `DOCTORS_DIR`, `USERS_DIR`, `jwt_secret.txt`,
`api_key.txt`, `flask_secret.key`) is computed *relative to the project folder*,
mounting the whole folder automatically makes all of them persistent, with no
per-path bookkeeping. For `secure_key_store.py`'s key directory, we set the
`LOCALAPPDATA` environment variable to point *inside* the same mounted project
folder, so those keys are covered by the same bind mount too.

---

## 3. STEP-BY-STEP EXECUTION

Do these in order. Each step says exactly which file to touch and how, or what
new file to create with its full contents.

### 3.1 Turn off debug mode (defensive cleanup, 2 tiny edits)

**File:** `server/server.py`, near the very end of the file.

Find this exact line:
```python
    app.run(debug=True, port=5000, use_reloader=False)
```
Replace it with:
```python
    app.run(debug=False, port=5000, use_reloader=False)
```

**File:** `portals/landing.py`, near the very end of the file.

Find this exact line:
```python
    app.run(host="127.0.0.1", port=5003, debug=True, use_reloader=False, threaded=True)
```
Replace it with:
```python
    app.run(host="127.0.0.1", port=5003, debug=False, use_reloader=False, threaded=True)
```

(As established in §1.2 point 7, these lines never execute under Gunicorn
anyway — we're changing them purely so that if anyone ever runs
`python server.py` or `python landing.py` directly again, debug mode isn't
silently on.)

### 3.2 Add Gunicorn to requirements

**File:** `requirements.txt`

Add this as a new line anywhere in the file (e.g. at the end):
```
gunicorn==26.0.0
```
(This exact version was installed and tested successfully against this
codebase — use exactly this version, don't substitute a different one without
re-testing.)

### 3.3 Fix the one hardcoded server-to-server URL

**File:** `portals/landing.py`

Find this exact line (around line 1382):
```python
DOCTOR_PORTAL = "http://127.0.0.1:5002"
```
Replace it with:
```python
DOCTOR_PORTAL = os.environ.get("DOCTOR_PORTAL_BASE", "http://127.0.0.1:5002")
```

This makes it consistent with the `BACKEND` pattern already used elsewhere in
the same file, while keeping the exact same default behavior if the env var
isn't set (which is what happens for local dev / running via `START.py`
unchanged).

### 3.4 Write the production `.env` file

**Do not commit this file to git — it already matches an entry in
`.gitignore` (`*.env`), so it's safe by default. Just create it on the server
directly, or copy it there separately from your git repo.**

**File to create:** `.env` in the project root (same folder as `START.py`).

```
# ── Database ──────────────────────────────────────────────────────────────
# With network_mode: host, "localhost" here correctly reaches the Postgres
# container, because it shares the host's network stack.
DATABASE_URL=postgresql://medvault_user:REPLACE_WITH_A_STRONG_PASSWORD@localhost:5432/medvault

# ── Secrets — MUST be set explicitly. Do not leave these blank in production. ──
# Generate each of these on your own machine by running:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
# Run it twice — once for each line below — and paste the two different results in.
SERVER_API_KEY=REPLACE_WITH_OUTPUT_OF_THE_COMMAND_ABOVE
JWT_SECRET=REPLACE_WITH_A_DIFFERENT_OUTPUT_OF_THE_COMMAND_ABOVE

FLASK_ENV=production

# ── Service URLs ─────────────────────────────────────────────────────────
# These all stay as 127.0.0.1 because of network_mode: host — see §2 above
# for why. Do not change these to Docker service names.
SERVER_BASE=http://127.0.0.1:5000
DOCTOR_PORTAL_BASE=http://127.0.0.1:5002

# ── CORS — set this to your server's actual public IP or domain ─────────────
# Example if your server's public IP is 203.0.113.10:
#   MEDVAULT_ALLOWED_ORIGINS=http://203.0.113.10:5001,http://203.0.113.10:5002,http://203.0.113.10:5003
MEDVAULT_ALLOWED_ORIGINS=REPLACE_WITH_YOUR_SERVERS_PUBLIC_IP_AND_PORTS

# ── Points secure_key_store.py's key directory inside the persisted mount ──
LOCALAPPDATA=/app/persistent_data/localappdata

# ── Postgres container's own settings (used by the postgres container itself) ──
POSTGRES_USER=medvault_user
POSTGRES_PASSWORD=REPLACE_WITH_THE_SAME_STRONG_PASSWORD_AS_ABOVE
POSTGRES_DB=medvault
```

**Two things the executing agent must actually do here, not skip:**
1. Actually run `python3 -c "import secrets; print(secrets.token_hex(32))"`
   twice and paste the two different real outputs into `SERVER_API_KEY` and
   `JWT_SECRET`. Do not leave the placeholder text in the file.
2. Replace `REPLACE_WITH_YOUR_SERVERS_PUBLIC_IP_AND_PORTS` with the server's
   actual public IP address (ask the person running this task for it if it
   isn't already known, or find it by running `curl -4 ifconfig.me` on the
   server itself) and the same value used for `POSTGRES_PASSWORD` must match
   in the `DATABASE_URL` line above it.

### 3.5 Create the shared Dockerfile

**File to create:** `Dockerfile` in the project root.

```dockerfile
FROM python:3.12-slim

# Build tools included defensively — some Python packages (e.g. argon2-cffi,
# cryptography) may need to compile from source on certain server CPU
# architectures if a prebuilt wheel isn't available.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only requirements first so Docker can cache this layer and skip
# re-installing every dependency every time you rebuild after a code change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The actual application code is bind-mounted in by docker-compose.yml at
# runtime (see §2 for why) — nothing else needs to be copied here.

# No CMD here on purpose — each service in docker-compose.yml specifies its
# own command, since server.py/landing.py/patient_portal.py/doctor_portal.py
# each need a different Gunicorn target.
```

### 3.6 Create the Docker Compose file

**File to create:** `docker-compose.yml` in the project root.

```yaml
services:
  postgres:
    image: postgres:16
    network_mode: host
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
      # With network_mode: host, tell Postgres to listen on this port
      # explicitly, matching DATABASE_URL's :5432 in .env.
      PGPORT: 5432
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 10

  backend:
    build: .
    network_mode: host
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    env_file: .env
    volumes:
      - .:/app
    working_dir: /app/server
    command: gunicorn --bind 0.0.0.0:5000 server:app --workers 3 --timeout 60

  patient_portal:
    build: .
    network_mode: host
    restart: unless-stopped
    depends_on:
      - backend
    env_file: .env
    volumes:
      - .:/app
    working_dir: /app/portals
    command: gunicorn --bind 0.0.0.0:5001 patient_portal:app --workers 2 --timeout 60

  doctor_portal:
    build: .
    network_mode: host
    restart: unless-stopped
    depends_on:
      - backend
    env_file: .env
    volumes:
      - .:/app
    working_dir: /app/portals
    command: gunicorn --bind 0.0.0.0:5002 doctor_portal:app --workers 2 --timeout 60

  landing:
    build: .
    network_mode: host
    restart: unless-stopped
    depends_on:
      - backend
      - doctor_portal
    env_file: .env
    volumes:
      - .:/app
    working_dir: /app/portals
    command: gunicorn --bind 0.0.0.0:5003 landing:app --workers 2 --timeout 60

volumes:
  pgdata:
```

**Why `depends_on: condition: service_healthy` for `postgres`, matters — do not
remove it:** this is the direct fix for the real, live-reproduced failure in
§1.2 point 6. It forces Docker Compose to wait until Postgres actually reports
itself ready (via the `healthcheck` block) before starting `backend`, so
`init_db()` never runs against a database that isn't listening yet.

### 3.7 Create a `.dockerignore` file (keeps builds fast, not strictly required but do it anyway)

**File to create:** `.dockerignore` in the project root.

```
__pycache__/
*.pyc
.git/
.env
*.log
medvault_pids.json
```

### 3.8 Create the persisted key-store folder ahead of time

Run this once on the server, from the project root (same folder as
`docker-compose.yml`):

```bash
mkdir -p persistent_data/localappdata
```

This matches the `LOCALAPPDATA=/app/persistent_data/localappdata` line in
`.env` from §3.4, and since the whole project folder is bind-mounted (§3.6),
this directory — and everything `secure_key_store.py` writes inside it — will
persist across every container restart and redeploy.

---

## 4. HOW TO ACTUALLY RUN IT ON THE SERVER

Run these commands in order, on the Linux server, from inside the project
folder (the one containing `docker-compose.yml`).

### 4.1 Install Docker (skip if already installed — check with `docker --version` first)

```bash
curl -fsSL https://get.docker.com | sh
```

### 4.2 Build and start everything

```bash
docker compose up -d --build
```

This will take a few minutes the first time (downloading the Postgres image
and installing Python dependencies). Subsequent runs are much faster.

### 4.3 Check that all five containers are actually running

```bash
docker compose ps
```

Expected output: five rows, all showing `running` (or `Up`) in their status
column — `postgres`, `backend`, `patient_portal`, `doctor_portal`, `landing`.
If any row is missing or shows `Exited`, go to the Troubleshooting section
below before continuing.

### 4.4 Check the backend actually connected to the database

```bash
docker compose logs backend | grep DB
```

Expected output includes the line:
```
[DB] PostgreSQL connected ✓
```
If instead you see `[DB] WARNING: ... Connection refused`, the backend started
before Postgres was ready — this should not happen given the `healthcheck` in
§3.6, but if it does, run `docker compose restart backend` and check again.

### 4.5 Open the firewall

Most VPS providers block incoming ports by default. Open the ones this app
needs (**not** 5000 — that's server-to-server only, per §1.2 point 8, and does
not need to be reachable from outside):

```bash
sudo ufw allow 5001/tcp
sudo ufw allow 5002/tcp
sudo ufw allow 5003/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

(If your provider uses a different firewall system — e.g. a cloud-console
"security group" instead of `ufw` — open the same three ports there instead.)

### 4.6 Test it from your own browser

Go to `http://YOUR_SERVER_PUBLIC_IP:5003` — this should load the MedVault
landing page. If it doesn't load, see Troubleshooting.

### 4.7 Run the real end-to-end data-flow test against the deployed version

Copy `demo_flow.py` (already in the project root from earlier testing) onto
the server if it isn't there already, then run it **from inside the backend
container** so it has the same Python environment:

```bash
docker compose exec backend python /app/demo_flow.py
```

Expected: the same successful output seen during local testing, ending with
the decrypted medical record printed and the line:
```
DONE — server relayed only ciphertext + wrapped keys throughout.
It never held K_data, a private key, or the plaintext record.
```
If this passes, the deployment is genuinely working end-to-end, not just
"pages load."

---

## 5. WHAT NOT TO CHANGE

- Do not touch `common/crypto_utils.py`, `common/secure_key_store.py`, or any
  of the actual cryptographic logic — none of that is in scope here.
- Do not remove or "clean up" `START.py`/`STOP.py` — keep them for local
  development; they're unrelated to this deployment path and still useful for
  quick local testing on a laptop.
- Do not attempt to unify the JWT-vs-API-key authentication inconsistency
  noted elsewhere — that's a separate, already-identified task, explicitly out
  of scope here.
- Do not add TLS/HTTPS in this pass — that's a legitimate next step (e.g. via
  a reverse proxy like Caddy or Nginx with Let's Encrypt, or a
  provider-managed load balancer) but is intentionally deferred so this task
  stays scoped and testable on its own. Running over plain HTTP on a
  known-public IP is acceptable for a demo/CV link; say so explicitly if this
  gets shared as "done," so nobody mistakes it for handling real patient data
  safely.
- Do not change any of the database schema files (`server/schema.sql`,
  `server/schema_additions.sql`) — they're applied automatically and correctly
  by `init_db()` already.

---

## 6. TROUBLESHOOTING

**`docker compose ps` shows a container as `Exited`:**
Run `docker compose logs <service_name>` (e.g. `docker compose logs backend`)
and read the last ~20 lines. Common causes:
- Postgres password in `.env`'s `DATABASE_URL` doesn't match `POSTGRES_PASSWORD`
  — go back to §3.4 and make sure both lines use the exact same password.
- A placeholder like `REPLACE_WITH_...` was left in `.env` — go back through
  §3.4 line by line.

**Browser can't reach `http://YOUR_SERVER_IP:5003`:**
- Confirm the container is actually running: `docker compose ps`.
- Confirm the firewall is actually open: run `sudo ufw status` and check port
  5003 is listed as `ALLOW`.
- Confirm you're using the server's **public** IP, not `127.0.0.1` or a
  private/internal IP — from your own laptop, `127.0.0.1` always means your
  own laptop, never the server.

**Page loads but login/register buttons don't work / browser console shows
CORS errors:**
- `MEDVAULT_ALLOWED_ORIGINS` in `.env` almost certainly doesn't match the exact
  URL (including port) the browser is using. Go back to §3.4 and make sure it
  lists `http://YOUR_SERVER_IP:5001`, `:5002`, and `:5003` exactly, then run
  `docker compose restart patient_portal doctor_portal landing backend` to pick
  up the change (Compose does not auto-reload `.env` changes into running
  containers).

**`docker compose up -d --build` itself fails while installing Python
packages:**
- Copy the exact error text. If it mentions a specific package failing to
  build (commonly `argon2-cffi` or `cryptography` on unusual CPU
  architectures), this is what the `gcc`/`python3-dev`/`libpq-dev` lines in
  the Dockerfile (§3.5) are meant to prevent — confirm those lines are present
  exactly as written before trying anything else.

**Any error not covered above:**
Stop, and share the exact command you ran and its exact full output. Do not
guess a fix and apply it silently — an incorrect guess here risks the
persistent-key-loss failure mode described in §1.2 point 9.
