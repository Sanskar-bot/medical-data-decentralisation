"""
tests/conftest.py - shared pytest fixtures for MedVault.

Safety rule: the tests TRUNCATE tables. They only run when DATABASE_URL
points at a database whose name ends with "_test".
"""
import os
import sys
import time
import uuid

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_DIR = os.path.join(ROOT, "server")
for _p in (ROOT, SERVER_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Environment must be set before server.py is imported anywhere.
os.environ.setdefault("FLASK_ENV", "development")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-0123456789abcdef0123456789abcdef")
os.environ.setdefault("SERVER_API_KEY", "test-api-key")
if os.environ.get("TEST_DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]

_DB_URL = os.environ.get("DATABASE_URL", "")
if not _DB_URL.rstrip("/").split("?")[0].endswith("_test"):
    raise RuntimeError(
        "Refusing to run tests: set TEST_DATABASE_URL to a database whose "
        "name ends with _test (for example "
        "postgresql://medvault_user:pw@127.0.0.1:5432/medvault_test)."
    )

ALL_TABLES = [
    "users", "otp_store", "phone_otp_store", "token_blocklist", "login_history",
    "patients", "doctors", "access_requests", "access_requests_archive",
    "wrapped_keys", "doctor_notes", "records", "images", "access_db",
    "appointments", "emr_profiles", "emr_appointments", "emr_prescriptions",
    "emr_lab_reports", "audit_log", "rate_limits", "conditions", "vitals",
    "encounters", "shares",
    "ipfs_pin_status", "ipfs_orphans", "ipfs_gc_state",
]


@pytest.fixture(scope="session")
def app():
    from server import app as flask_app
    if os.environ.get("IPFS_INTEGRATION") != "1":
        from fake_ipfs import FakeIPFSClient
        flask_app.config["IPFS_CLIENT"] = FakeIPFSClient()
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    from db import db_cursor
    return db_cursor


@pytest.fixture
def clean_db(app):
    """Empty every table. Use in tests that need a known-empty database."""
    from db import db_cursor
    with db_cursor() as cur:
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        existing = {r["tablename"] for r in cur.fetchall()}
        tables = [t for t in ALL_TABLES if t in existing]
        if tables:
            cur.execute("TRUNCATE TABLE " + ", ".join(tables) + " RESTART IDENTITY CASCADE")
    yield


@pytest.fixture
def make_token(app):
    """make_token(user_dict, **extra_claims) -> 'Bearer <jwt>' header dict."""
    from server import _jwt_encode

    def _make(user, **extra):
        claims = {
            "sub": user.get("email") or user["id"],
            "uid": user["id"],
            "role": user["role"],
            "profile_code": user.get("profile_code", ""),
            "doctor_code": user.get("doctor_code", ""),
            "purpose": "access",
            "exp": time.time() + 600,
        }
        claims.update(extra)
        return {"Authorization": "Bearer " + _jwt_encode(claims),
                "Content-Type": "application/json"}
    return _make


@pytest.fixture
def make_user(app):
    """make_user(role) inserts a users row (and patients/doctors row) and returns it."""
    from db import db_cursor

    def _make(role="patient", **overrides):
        uid = str(uuid.uuid4())
        short = uuid.uuid4().hex[:10].upper()
        user = {
            "id": uid,
            "email": f"{role}-{short.lower()}@example.test",
            "username": f"{role}_{short.lower()}",
            "name": f"Test {role} {short}",
            "role": role,
            "profile_code": short if role == "patient" else "",
            "doctor_code": short if role == "doctor" else "",
        }
        user.update(overrides)
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO users (id, email, username, name, role, password_hash,
                                      profile_code, doctor_code)
                   VALUES (%s, %s, %s, %s, %s, 'x', %s, %s)""",
                (user["id"], user["email"], user["username"], user["name"],
                 user["role"], user["profile_code"], user["doctor_code"]))
            if role == "patient":
                cur.execute(
                    """INSERT INTO patients (profile_code, encrypted_record)
                       VALUES (%s, '{"nonce": "n", "ciphertext": "c"}'::jsonb)""",
                    (user["profile_code"],))
            if role == "doctor":
                cur.execute(
                    """INSERT INTO doctors (doctor_code, doctor_id, public_pem)
                       VALUES (%s, %s, 'PEM')""",
                    (user["doctor_code"], str(uuid.uuid4())))
        return user
    return _make


@pytest.fixture
def grant_access(app):
    """grant_access(doctor, patient, status='approved') inserts an access_db row."""
    from db import db_cursor

    def _grant(doctor, patient, status="approved"):
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO access_db (id, doctor_id, doctor_email, patient_id, status, responded_at)
                   VALUES (%s, %s, %s, %s, %s, now())""",
                (str(uuid.uuid4()), doctor["id"], doctor["email"], patient["id"], status))
    return _grant
