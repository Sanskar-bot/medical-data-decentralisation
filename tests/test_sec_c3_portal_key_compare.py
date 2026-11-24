"""[C3] Portal API-key check must use a constant-time comparison."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTALS = os.path.join(ROOT, "portals")
if PORTALS not in sys.path:
    sys.path.insert(0, PORTALS)

import auth_utils  # noqa: E402
import patient_portal  # noqa: E402


def test_login_required_uses_compare_digest(monkeypatch):
    calls = []
    real = auth_utils.hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(auth_utils.hmac, "compare_digest", spy)
    patient_portal.app.config["TESTING"] = True
    with patient_portal.app.test_client() as c:
        c.get("/api/record/X", headers={"X-API-Key": "wrong-key"})
    assert calls, "hmac.compare_digest was not used"


def test_api_key_alone_is_not_a_patient_session():
    patient_portal.app.config["TESTING"] = True
    with patient_portal.app.test_client() as c:
        r = c.get("/api/record/X", headers={"X-API-Key": auth_utils.get_server_api_key()})
    assert r.status_code == 403
