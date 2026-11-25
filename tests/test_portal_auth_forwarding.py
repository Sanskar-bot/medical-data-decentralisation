import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# ensure we can import the portals
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
PORTALS_DIR = os.path.join(ROOT, "portals")
if PORTALS_DIR not in sys.path:
    sys.path.insert(0, PORTALS_DIR)

import patient_portal
import doctor_portal
import landing

@pytest.fixture
def patient_client():
    app = patient_portal.app
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test"
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["role"] = "patient"
        yield client

@pytest.fixture
def doctor_client():
    app = doctor_portal.app
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test"
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["role"] = "doctor"
        yield client

@pytest.fixture
def landing_client():
    app = landing.app
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test"
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["role"] = "patient"
            sess["jwt_token"] = "landing_session_token"
        yield client


def test_patient_notes_forwards_jwt(patient_client):
    with patch("patient_portal.http.get") as mock_get:
        mock_get.return_value = MagicMock(ok=True, status_code=200, json=lambda: [])
        patient_client.get("/api/doctor_notes/PAT123", headers={"Authorization": "Bearer faketoken"})
        _, kwargs = mock_get.call_args
        assert "Authorization" in kwargs["headers"]
        assert kwargs["headers"]["Authorization"] == "Bearer faketoken"

def test_patient_note_image_forwards_jwt(patient_client):
    with patch("patient_portal.http.get") as mock_get:
        mock_get.return_value = MagicMock(ok=True, content=b"img")
        patient_client.get("/api/note_images/img.png", headers={"Authorization": "Bearer faketoken2"})
        _, kwargs = mock_get.call_args
        assert "Authorization" in kwargs["headers"]
        assert kwargs["headers"]["Authorization"] == "Bearer faketoken2"


def test_doctor_notes_forwards_jwt(doctor_client):
    with patch("doctor_portal.http.get") as mock_get:
        mock_get.return_value = MagicMock(ok=True, status_code=200, json=lambda: [])
        doctor_client.get("/api/doctor_notes/PAT123", headers={"Authorization": "Bearer faketoken_doc"})
        _, kwargs = mock_get.call_args
        assert "Authorization" in kwargs["headers"]
        assert kwargs["headers"]["Authorization"] == "Bearer faketoken_doc"


def test_doctor_rejects_swapped_registration_ciphertext_before_decryption(doctor_client):
    import base64
    import hashlib
    import json

    from common.crypto_utils import generate_rsa_keypair, rsa_serialize_public, rsa_sign

    patient_private, patient_public = generate_rsa_keypair(2048)
    original = {"nonce": base64.b64encode(b"0" * 12).decode(),
                "ciphertext": base64.b64encode(b"original encrypted bytes").decode()}
    signature = rsa_sign(
        patient_private,
        (original["nonce"] + "|" + original["ciphertext"]).encode(),
    )
    swapped = {**original, "ciphertext": base64.b64encode(b"swapped bytes").decode()}
    serialized = json.dumps(swapped, sort_keys=True, separators=(",", ":")).encode()
    response_body = {
        "encrypted_record": swapped,
        "patient_public_pem": rsa_serialize_public(patient_public).decode(),
        "signature": signature,
        # Model a malicious DB update that also replaced the expected hash.
        "ciphertext_sha256": hashlib.sha256(serialized).hexdigest(),
    }

    with patch("doctor_portal.unlock_doctor_private_key", return_value=(None, object())), \
         patch("doctor_portal.http.get", return_value=MagicMock(
             status_code=200, json=lambda: response_body
         )) as mock_get, \
         patch("doctor_portal.rsa_unwrap_key") as unwrap, \
         patch("doctor_portal.aesgcm_decrypt") as decrypt:
        response = doctor_client.post("/api/fetch_record", json={
            "doctor_code": "DOC-TEST", "patient_code": "PAT-TEST", "password": "pw",
        })

    assert response.status_code == 502
    assert response.get_json()["error"] == "invalid_patient_signature"
    assert mock_get.call_count == 1  # wrapped keys were never fetched
    unwrap.assert_not_called()
    decrypt.assert_not_called()

def test_doctor_note_image_forwards_jwt(doctor_client):
    with patch("doctor_portal.http.get") as mock_get:
        mock_get.return_value = MagicMock(ok=True, content=b"img")
        doctor_client.get("/api/note_images/img.png", headers={"Authorization": "Bearer faketoken2_doc"})
        _, kwargs = mock_get.call_args
        assert "Authorization" in kwargs["headers"]
        assert kwargs["headers"]["Authorization"] == "Bearer faketoken2_doc"


def test_landing_patient_notes_forwards_jwt(landing_client):
    with patch("landing.http.get") as mock_get:
        mock_get.return_value = MagicMock(ok=True, json=lambda: {})
        landing_client.get("/patient/notes")
        # the route calls the backend internally, should use the session token
        _, kwargs = mock_get.call_args
        assert "Authorization" in kwargs["headers"]
        assert kwargs["headers"]["Authorization"] == "Bearer landing_session_token"
