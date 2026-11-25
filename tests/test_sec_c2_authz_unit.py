"""[C2] Unit tests for the single authorization function."""
import uuid

import pytest


def _p(user):
    return {"uid": user["id"], "role": user["role"],
            "profile_code": user.get("profile_code", ""),
            "doctor_code": user.get("doctor_code", "")}


def test_patient_own_data_only(app, clean_db, make_user):
    from authz import authorize_patient_access as ok
    a, b = make_user("patient"), make_user("patient")
    assert ok(_p(a), a["id"]) is True
    assert ok(_p(a), a["profile_code"]) is True
    assert ok(_p(a), b["id"]) is False
    assert ok(_p(a), b["profile_code"]) is False


def test_doctor_needs_approved_grant(app, clean_db, make_user, grant_access):
    from authz import authorize_patient_access as ok
    p, d = make_user("patient"), make_user("doctor")
    assert ok(_p(d), p["id"]) is False
    grant_access(d, p, status="pending")
    assert ok(_p(d), p["id"]) is False


def test_doctor_with_grant_allowed_by_id_and_code(app, clean_db, make_user, grant_access):
    from authz import authorize_patient_access as ok
    p, d = make_user("patient"), make_user("doctor")
    grant_access(d, p)
    assert ok(_p(d), p["id"]) is True
    assert ok(_p(d), p["profile_code"]) is True


def test_revoked_grant_denied(app, clean_db, make_user, grant_access):
    from authz import authorize_patient_access as ok
    p, d = make_user("patient"), make_user("doctor")
    grant_access(d, p, status="revoked")
    assert ok(_p(d), p["id"]) is False


def test_wrapped_key_grant_respects_expiry(app, clean_db, db, make_user):
    from authz import authorize_patient_access as ok
    p, d = make_user("patient"), make_user("doctor")
    with db() as cur:
        cur.execute("INSERT INTO wrapped_keys (profile_code, doctor_code, wrapped_key, temp_key_expires_at) "
                    "VALUES (%s, %s, 'WK', now() + interval '1 hour')", (p["profile_code"], d["doctor_code"]))
    assert ok(_p(d), p["id"]) is True
    with db() as cur:
        cur.execute("UPDATE wrapped_keys SET temp_key_expires_at = now() - interval '1 minute'")
    assert ok(_p(d), p["id"]) is False


def test_implicit_access_from_old_prescription_is_gone(app, clean_db, db, make_user):
    from authz import authorize_patient_access as ok
    p, d = make_user("patient"), make_user("doctor")
    with db() as cur:
        cur.execute("INSERT INTO emr_prescriptions (id, patient_id, doctor_id, medications) "
                    "VALUES (%s, %s, %s, '[]')", (str(uuid.uuid4()), p["profile_code"], d["doctor_code"]))
    assert ok(_p(d), p["profile_code"]) is False


def test_authored_lab_report_does_not_grant_patient_wide_access(app, clean_db, db, make_user):
    from authz import authorize_patient_access as ok
    p, d = make_user("patient"), make_user("doctor")
    with db() as cur:
        cur.execute("INSERT INTO emr_lab_reports (id, patient_id, doctor_id, report_type) "
                    "VALUES (%s, %s, %s, 'CBC')",
                    (str(uuid.uuid4()), p["profile_code"], d["doctor_code"]))
    assert ok(_p(d), p["profile_code"]) is False


@pytest.mark.xfail(strict=True, reason="access_db has no expiry until Task 4")
def test_old_approved_access_db_grant_should_be_denied(app, clean_db, db, make_user):
    """Task 4 will add and enforce approval expiry; this documents the gap."""
    from authz import authorize_patient_access as ok
    p, d = make_user("patient"), make_user("doctor")
    with db() as cur:
        cur.execute("""
            INSERT INTO access_db (id, doctor_id, doctor_email, patient_id, status, responded_at)
            VALUES (%s, %s, %s, %s, 'approved', now() - interval '25 hours')
        """, (str(uuid.uuid4()), d["id"], d["email"], p["id"]))
    assert ok(_p(d), p["id"]) is False


def test_admin_receptionist_and_unknown_denied(app, clean_db, make_user):
    from authz import authorize_patient_access as ok
    p = make_user("patient")
    for role in ("admin", "receptionist"):
        u = make_user(role)
        assert ok(_p(u), p["id"]) is False
    assert ok({"uid": "x", "role": "superuser"}, p["id"]) is False
    assert ok({}, p["id"]) is False
    assert ok(None, p["id"]) is False
    assert ok(_p(p), "") is False
