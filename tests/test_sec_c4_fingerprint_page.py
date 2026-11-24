"""[C4] The approval page receives and renders the fingerprint."""

def test_landing_passes_fingerprint_to_page(app):
    import os, sys
    from unittest.mock import MagicMock, patch
    portals = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "portals")
    if portals not in sys.path:
        sys.path.insert(0, portals)
    import landing
    landing.app.config["TESTING"] = True
    row = {"id": "r1", "status": "pending", "doctor_key_fingerprint": "AAAA BBBB CCCC DDDD EEEE"}
    with landing.app.test_client() as c:
        with c.session_transaction() as s:
            s.update({"logged_in": True, "role": "patient", "profile_code": "NOPE", "jwt_token": "t"})
        with patch("landing.http.get", return_value=MagicMock(ok=True, json=lambda: [row])):
            r = c.get("/patient/requests")
    reqs = r.get_json()["requests"]
    assert reqs[0]["doctor_key_fingerprint"] == "AAAA BBBB CCCC DDDD EEEE"


def test_template_renders_fingerprint():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "portals", "templates", "access_requests.html"), encoding="utf-8").read()
    assert "function fingerprintHtml(r)" in src
    assert "fingerprintHtml(r) +" in src
