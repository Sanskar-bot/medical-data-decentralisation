"""[C2][H6][X3] Legacy record routes: no implicit access, no admin access."""
import os
import uuid

API = {"X-API-Key": os.environ["SERVER_API_KEY"]}


def _implicit_rx(db, patient, doctor):
    with db() as cur:
        cur.execute("INSERT INTO emr_prescriptions (id, patient_id, doctor_id, medications) "
                    "VALUES (%s, %s, %s, '[]')", (str(uuid.uuid4()), patient["profile_code"], doctor["doctor_code"]))


def test_old_prescription_gives_no_record_access(client, clean_db, db, make_user, make_token):
    p, d = make_user("patient"), make_user("doctor")
    _implicit_rx(db, p, d)
    hdr = {**make_token(d), **API}
    assert client.get(f"/get_patient_data/{p['profile_code']}", headers=hdr).status_code == 403
    assert client.get(f"/wrapped_key/{p['profile_code']}", headers=hdr).status_code == 403


def test_old_prescription_gives_no_note_write(client, clean_db, db, make_user, make_token):
    p, d = make_user("patient"), make_user("doctor")
    _implicit_rx(db, p, d)
    r = client.post("/doctor_notes/add", headers=make_token(d),
                    json={"patient_code": p["profile_code"], "note_text": "hi"})
    assert r.status_code == 403


def test_granted_doctor_and_owner_still_read(client, clean_db, make_user, make_token, grant_access):
    p, d = make_user("patient"), make_user("doctor")
    grant_access(d, p)
    for who in (p, d):
        r = client.get(f"/get_patient_data/{p['profile_code']}", headers={**make_token(who), **API})
        assert r.status_code == 200, who["role"]


def test_admin_denied_on_record(client, clean_db, make_user, make_token):
    p, a = make_user("patient"), make_user("admin")
    r = client.get(f"/get_patient_data/{p['profile_code']}", headers={**make_token(a), **API})
    assert r.status_code == 403
