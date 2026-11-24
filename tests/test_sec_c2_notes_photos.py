"""[C2][H9][M4] Notes, note images and profile photos."""
import os
import uuid

import pytest

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}


def _note(db, patient, doctor):
    nid = str(uuid.uuid4())
    with db() as cur:
        cur.execute("INSERT INTO doctor_notes (note_id, patient_code, doctor_code, note_text) "
                    "VALUES (%s, %s, %s, 'n')", (nid, patient["profile_code"], doctor["doctor_code"]))
    return nid


def test_patient_reads_own_notes(client, clean_db, make_user, make_token):
    p = make_user("patient")
    r = client.get(f"/doctor_notes/patient/{p['profile_code']}", headers={**make_token(p), **API})
    assert r.status_code == 200


def test_granted_doctor_reads_notes_admin_does_not(client, clean_db, make_user, make_token, grant_access):
    p, d, a = make_user("patient"), make_user("doctor"), make_user("admin")
    grant_access(d, p)
    url = f"/doctor_notes/patient/{p['profile_code']}"
    assert client.get(url, headers={**make_token(d), **API}).status_code == 200
    assert client.get(url, headers={**make_token(a), **API}).status_code == 403


@pytest.fixture
def note_image(app, db, make_user):
    import server
    p, d = make_user("patient"), make_user("doctor")
    nid = _note(db, p, d)
    files = []
    for name in (f"note_{nid}.png", f"note_{uuid.uuid4()}.png"):
        path = os.path.join(server.NOTE_IMAGES_DIR, name)
        with open(path, "wb") as fh:
            fh.write(b"img")
        files.append((name, path))
    yield p, d, files
    for _, path in files:
        os.remove(path)


def test_note_image_access(client, clean_db, make_user, make_token, note_image):
    p, d, files = note_image
    (good, _), (orphan, _) = files
    other = make_user("patient")
    assert client.get(f"/note_images/{good}", headers={**make_token(p), **API}).status_code == 200
    assert client.get(f"/note_images/{good}", headers={**make_token(d), **API}).status_code == 200
    assert client.get(f"/note_images/{good}", headers={**make_token(other), **API}).status_code == 403
    assert client.get(f"/note_images/{orphan}", headers={**make_token(other), **API}).status_code == 404
    assert client.get(f"/note_images/{good}", headers=API).status_code == 401


def test_profile_photo_needs_grant(client, clean_db, make_user, make_token, grant_access):
    import server
    p, d, stranger = make_user("patient"), make_user("doctor"), make_user("doctor")
    grant_access(d, p)
    path = os.path.join(server.UPLOADS_DIR, "profiles", f"{p['id']}_profile.png")
    with open(path, "wb") as fh:
        fh.write(b"img")
    try:
        url = f"/profile/photo/{p['id']}"
        assert client.get(url, headers={**make_token(p), **API}).status_code == 200
        assert client.get(url, headers={**make_token(d), **API}).status_code == 200
        assert client.get(url, headers={**make_token(stranger), **API}).status_code == 403
    finally:
        os.remove(path)
