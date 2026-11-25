"""
server/authz.py - the ONE function that decides who may read or write a
patient's clinical data in MedVault.  [C2]

Deny by default. Access is allowed only when:
  * the caller is a patient and the data is their own; or
  * the caller is a doctor holding an approved grant for this patient:
      - an access_db row (doctor users.id, patient users.id or profile_code,
        status 'approved'); or
      - an unexpired wrapped_keys row (doctor_code, patient profile_code) from
        the legacy key-sharing flow.
Every other role (admin, receptionist, unknown) is denied.
ASSUMES DECISION admin=A (administrators have no clinical access).

There is NO "implicit" access: having written a prescription or lab report
for a patient in the past does not grant access.  [H6]
"""
from db import db_cursor
from common.access_expiry import active_wrapped_key_sql


def resolve_patient(identifier):
    """Return {"id": ..., "profile_code": ...} for a users.id or a profile_code.

    Unknown identifiers are returned unchanged in both fields so that a grant
    stored under that exact value still matches.
    """
    ident = (identifier or "").strip()
    if not ident:
        return {"id": "", "profile_code": ""}
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT id, profile_code FROM users "
            "WHERE id = %s OR (profile_code = %s AND profile_code <> '') LIMIT 1",
            (ident, ident),
        )
        row = cur.fetchone()
    if row:
        return {"id": str(row["id"]), "profile_code": row["profile_code"] or ""}
    return {"id": ident, "profile_code": ident}


def _doctor_code_for(payload):
    code = (payload.get("doctor_code") or "").strip()
    if code:
        return code
    uid = (payload.get("uid") or "").strip()
    if not uid:
        return ""
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT doctor_code FROM users WHERE id = %s LIMIT 1", (uid,))
        row = cur.fetchone()
    return (row["doctor_code"] or "") if row else ""


def doctor_has_grant(payload, patient):
    """True if the doctor in *payload* holds an approved grant for *patient*."""
    uid = (payload.get("uid") or "").strip()
    keys = [k for k in {patient["id"], patient["profile_code"]} if k]
    if not keys:
        return False
    with db_cursor(commit=False) as cur:
        if uid:
            cur.execute(
                "SELECT 1 FROM access_db WHERE doctor_id = %s "
                "AND patient_id = ANY(%s) AND status = 'approved' LIMIT 1",
                (uid, keys),
            )
            if cur.fetchone():
                return True
        code = _doctor_code_for(payload)
        if code and patient["profile_code"]:
            cur.execute(
                "SELECT 1 FROM wrapped_keys WHERE doctor_code = %s AND profile_code = %s "
                f"AND {active_wrapped_key_sql()} LIMIT 1",
                (code, patient["profile_code"]),
            )
            if cur.fetchone():
                return True
    return False


def authorize_patient_access(payload, patient_identifier):
    """Return True only if *payload* (a decoded access token) may access the patient."""
    if not payload or not patient_identifier:
        return False
    role = payload.get("role")
    patient = resolve_patient(patient_identifier)
    if role == "patient":
        uid = (payload.get("uid") or "").strip()
        code = (payload.get("profile_code") or "").strip()
        if uid and uid == patient["id"]:
            return True
        return bool(code) and code == patient["profile_code"]
    if role == "doctor":
        return doctor_has_grant(payload, patient)
    return False
