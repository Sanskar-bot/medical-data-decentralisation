"""[C1] Admins are created only by the command-line script."""
import pytest


def test_create_admin_cli(app, clean_db, db, monkeypatch):
    import create_admin
    monkeypatch.setenv("MEDVAULT_ADMIN_PASSWORD", "a-long-admin-password")
    rc = create_admin.main(["--email", "Root@Example.test", "--username", "root", "--name", "Root"])
    assert rc == 0
    with db() as cur:
        cur.execute("SELECT role, password_hash FROM users WHERE username = 'root'")
        row = cur.fetchone()
    assert row["role"] == "admin"
    from werkzeug.security import check_password_hash
    assert check_password_hash(row["password_hash"], "a-long-admin-password")


def test_create_admin_rejects_short_password(app, clean_db):
    import create_admin
    with pytest.raises(ValueError):
        create_admin.create_admin("a@example.test", "a", "A", "short")


def test_create_admin_rejects_duplicate(app, clean_db):
    import create_admin
    create_admin.create_admin("b@example.test", "b", "B", "a-long-admin-password")
    with pytest.raises(ValueError):
        create_admin.create_admin("b@example.test", "b2", "B", "a-long-admin-password")
