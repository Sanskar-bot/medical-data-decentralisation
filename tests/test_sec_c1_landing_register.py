"""[C1] The landing page must not offer self-service doctor/admin signup."""
import os
import sys
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTALS = os.path.join(ROOT, "portals")
if PORTALS not in sys.path:
    sys.path.insert(0, PORTALS)

import landing  # noqa: E402


def _client():
    landing.app.config["TESTING"] = True
    return landing.app.test_client()


def test_landing_register_doctor_refused_and_backend_not_called():
    with patch("landing.http.post") as mock_post:
        r = _client().post("/auth/register", json={
            "role": "doctor", "name": "D", "phone": "+1555", "username": "doc1",
            "password": "Password123!"})
    assert r.status_code == 403
    mock_post.assert_not_called()


def test_landing_register_admin_refused():
    with patch("landing.http.post") as mock_post:
        r = _client().post("/auth/register", json={
            "role": "admin", "name": "A", "phone": "+1556", "username": "adm1",
            "password": "Password123!"})
    assert r.status_code == 403
    mock_post.assert_not_called()
