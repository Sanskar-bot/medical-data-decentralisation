"""[C1] Public registration must never create admin or doctor accounts."""
import time


def _phone_token(phone):
    from server import _jwt_encode
    return _jwt_encode({"sub": phone, "purpose": "phone_otp_verified",
                        "exp": time.time() + 600})


def _register(client, role, n):
    body = {"phone_verification_token": _phone_token(f"+1555000{n}"),
            "name": "Eve", "username": f"eve{n}", "password": "Password123!",
            "public_key": "PK"}
    if role is not None:
        body["role"] = role
    return client.post("/auth/register", json=body)


def _role_of(db, username):
    with db() as cur:
        cur.execute("SELECT role FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
    return row["role"] if row else None


def test_register_as_admin_is_refused(client, clean_db, db):
    r = _register(client, "admin", 1)
    assert r.status_code == 403
    assert _role_of(db, "eve1") is None


def test_register_as_doctor_is_refused(client, clean_db, db):
    r = _register(client, "doctor", 2)
    assert r.status_code == 403
    assert _role_of(db, "eve2") is None


def test_register_patient_still_works(client, clean_db, db):
    r = _register(client, "patient", 3)
    assert r.status_code == 200
    assert _role_of(db, "eve3") == "patient"


def test_register_without_role_creates_patient(client, clean_db, db):
    r = _register(client, None, 4)
    assert r.status_code == 200
    assert _role_of(db, "eve4") == "patient"
