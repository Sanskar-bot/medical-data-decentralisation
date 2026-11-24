"""[C1] /internal/register_user_db must not create privileged accounts."""
import os


def _post(client, role, n):
    return client.post(
        "/internal/register_user_db",
        headers={"X-API-Key": os.environ["SERVER_API_KEY"]},
        json={"email": f"x{n}@example.test", "username": f"x{n}", "name": "X",
              "password_hash": "pbkdf2:sha256:1$a$b", "role": role},
    )


def test_internal_register_admin_refused(client, clean_db, db):
    r = _post(client, "admin", 1)
    assert r.status_code == 403
    with db() as cur:
        cur.execute("SELECT 1 FROM users WHERE username = 'x1'")
        assert cur.fetchone() is None


def test_internal_register_doctor_refused(client, clean_db):
    assert _post(client, "doctor", 2).status_code == 403


def test_internal_register_patient_ok(client, clean_db):
    assert _post(client, "patient", 3).status_code == 200
