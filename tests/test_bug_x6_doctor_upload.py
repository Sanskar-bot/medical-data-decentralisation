"""[X6] Doctor portal image upload must not crash with NameError."""
import io
import os
import sys
from unittest.mock import MagicMock, patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTALS = os.path.join(ROOT, "portals")
if PORTALS not in sys.path:
    sys.path.insert(0, PORTALS)

import doctor_portal  # noqa: E402


def test_upload_image_forwards_to_backend():
    app = doctor_portal.app
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as s:
            s["logged_in"] = True
            s["role"] = "doctor"
        with patch("doctor_portal.http.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=201, json=lambda: {"image_id": "i1"})
            r = c.post("/api/upload_image",
                       data={"record_id": "r1", "image": (io.BytesIO(b"abc"), "x.enc")},
                       headers={"Authorization": "Bearer t"},
                       content_type="multipart/form-data")
    assert r.status_code == 201
    assert mock_post.called
    assert mock_post.call_args.kwargs["headers"]["X-API-Key"] == doctor_portal._api_key()
