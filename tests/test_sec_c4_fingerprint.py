"""[C4] Patients see a fingerprint of the requesting doctor's key."""
import hashlib


def test_patient_requests_include_fingerprint(client, clean_db, db, make_user, make_token, grant_access):
    p, d = make_user("patient"), make_user("doctor")
    with db() as cur:
        cur.execute("UPDATE doctors SET public_pem = 'DOCTOR-PEM' WHERE doctor_code = %s", (d["doctor_code"],))
    grant_access(d, p, status="pending")
    r = client.get("/access/patient_requests", headers=make_token(p))
    assert r.status_code == 200
    rows = r.get_json()
    assert len(rows) == 1
    h = hashlib.sha256(b"DOCTOR-PEM").hexdigest()[:20].upper()
    assert rows[0]["doctor_key_fingerprint"] == " ".join(h[i:i + 4] for i in range(0, 20, 4))
