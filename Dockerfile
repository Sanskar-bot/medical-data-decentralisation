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

# Copy the application code into the image. Docker Compose deployments
# (docker-compose.yml) override this at runtime with a bind mount for fast
# local iteration — see that file's `volumes:` entries — but the image
# itself must be self-contained for platforms without a host bind mount,
# such as Railway.
COPY . .

# No CMD here on purpose — each service in docker-compose.yml specifies its
# own command, since server.py/landing.py/patient_portal.py/doctor_portal.py
# each need a different Gunicorn target.
