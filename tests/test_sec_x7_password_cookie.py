"""[X7] The password must never be placed in the Flask session cookie."""
import base64
import os
import sys
import zlib
from unittest.mock import MagicMock, patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTALS = os.path.join(ROOT, "portals")
if PORTALS not in sys.path:
    sys.path.insert(0, PORTALS)

import landing  # noqa: E402

SECRET_PW = "Sup3r-Secret-Passw0rd"


def _decode_cookie(value):
    payload = value.split(".")[0]
    compressed = payload.startswith(".")
    if value.startswith("."):
        payload = value[1:].split(".")[0]
        compressed = True
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    return zlib.decompress(raw).decode() if compressed else raw.decode()


def test_login_does_not_store_password_in_session():
    landing.app.config["TESTING"] = True
    fake = MagicMock(ok=True, status_code=200, json=lambda: {
        "role": "patient", "name": "P", "email": "p@example.test", "username": "p",
        "user_id": "u1", "profile_code": "PC1", "access_token": "tok"})
    with landing.app.test_client() as c:
        with patch("landing.http.post", return_value=fake):
            r = c.post("/login", json={"email": "p@example.test", "password": SECRET_PW})
        assert r.status_code == 200
        with c.session_transaction() as s:
            assert "_pw_cache" not in s
            assert SECRET_PW not in str(dict(s))
        cookie = c.get_cookie("session")
        assert cookie is not None
        assert SECRET_PW not in _decode_cookie(cookie.value)


def test_cache_password_endpoint_is_gone():
    landing.app.config["TESTING"] = True
    with landing.app.test_client() as c:
        with c.session_transaction() as s:
            s["logged_in"] = True
        r = c.post("/api/cache_password", json={"password": SECRET_PW})
    assert r.status_code == 404
