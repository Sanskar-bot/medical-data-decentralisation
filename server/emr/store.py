"""
emr/store.py — PostgreSQL-backed storage for EMR entities.

Public API is identical to the original JSON-file version.
emr/routes.py requires zero changes.

The _read(name) function is a compatibility shim required by
admin_stats in emr/routes.py which calls store._read("appointments") etc.
"""
import sys
import os
import json
from datetime import datetime

# Ensure server/ is on the path so we can import db
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from db import db_cursor
from emr.models import compute_age as _compute_age


# ── Timestamp serialiser ──────────────────────────────────────────────────────

def _serial(row: dict) -> dict:
    """Convert any datetime/date values in a row dict to ISO strings."""
    out = {}
    for k, v in row.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        elif hasattr(v, "isoformat"):   # date objects
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


# ── Patient Profiles ──────────────────────────────────────────────────────────

def get_profile(patient_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_profiles WHERE patient_id = %s",
            (patient_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        d = _serial(dict(row))
        # Ensure list/dict fields are native Python objects, not strings
        for field in ("medical_history", "allergies", "past_visits"):
            v = d.get(field)
            if isinstance(v, str):
                try:
                    d[field] = json.loads(v)
                except (ValueError, TypeError):
                    d[field] = []
            elif v is None:
                d[field] = []
        ec = d.get("emergency_contact")
        if isinstance(ec, str):
            try:
                d["emergency_contact"] = json.loads(ec)
            except (ValueError, TypeError):
                d["emergency_contact"] = {}
        elif ec is None:
            d["emergency_contact"] = {}
        # patient_metadata: always return as dict, never None or string
        pm = d.get("patient_metadata")
        if isinstance(pm, str):
            try:
                d["patient_metadata"] = json.loads(pm)
            except (ValueError, TypeError):
                d["patient_metadata"] = {}
        elif pm is None:
            d["patient_metadata"] = {}
        # Bug 2: always inject computed age from date_of_birth
        dob = d.get("date_of_birth")
        if dob:
            computed = _compute_age(str(dob))
            if computed is not None:
                d["age"] = computed
        return d



def upsert_profile(profile: dict):
    pid = profile["patient_id"]

    def _jsonify(v):
        if isinstance(v, (list, dict)):
            return json.dumps(v)
        return v or "[]"

    def _jsonify_obj(v):
        if isinstance(v, dict):
            return json.dumps(v)
        return v or "{}"

    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO emr_profiles (
                patient_id, name, age, date_of_birth, gender, blood_group,
                medical_history, allergies, emergency_contact,
                past_visits, patient_metadata, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (patient_id) DO UPDATE SET
                name              = EXCLUDED.name,
                age               = EXCLUDED.age,
                date_of_birth     = EXCLUDED.date_of_birth,
                gender            = EXCLUDED.gender,
                blood_group       = EXCLUDED.blood_group,
                medical_history   = EXCLUDED.medical_history,
                allergies         = EXCLUDED.allergies,
                emergency_contact = EXCLUDED.emergency_contact,
                past_visits       = EXCLUDED.past_visits,
                patient_metadata  = emr_profiles.patient_metadata || EXCLUDED.patient_metadata,
                updated_at        = now()
        """, (
            pid,
            profile.get("name", ""),
            profile.get("age", ""),
            profile.get("date_of_birth") or None,
            profile.get("gender", ""),
            profile.get("blood_group", ""),
            _jsonify(profile.get("medical_history", [])),
            _jsonify(profile.get("allergies", [])),
            _jsonify_obj(profile.get("emergency_contact", {})),
            _jsonify(profile.get("past_visits", [])),
            _jsonify_obj(profile.get("patient_metadata", {})),
        ))



def list_profiles() -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM emr_profiles ORDER BY created_at DESC")
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = _serial(dict(row))
            for field in ("medical_history", "allergies", "past_visits"):
                v = d.get(field)
                if isinstance(v, str):
                    try:
                        d[field] = json.loads(v)
                    except (ValueError, TypeError):
                        d[field] = []
                elif v is None:
                    d[field] = []
            ec = d.get("emergency_contact")
            if isinstance(ec, str):
                try:
                    d["emergency_contact"] = json.loads(ec)
                except (ValueError, TypeError):
                    d["emergency_contact"] = {}
            elif ec is None:
                d["emergency_contact"] = {}
            result.append(d)
        return result


# ── Compatibility shim — required by admin_stats in emr/routes.py ─────────────

_TABLE_MAP = {
    "appointments":  "emr_appointments",
    "prescriptions": "emr_prescriptions",
    "lab_reports":   "emr_lab_reports",
    "profiles":      "emr_profiles",
    "conditions":    "conditions",
    "encounters":    "encounters",
}


def _read(name: str) -> list | dict:
    """
    Compatibility shim: emr/routes.py admin_stats calls store._read("appointments") etc.
    Returns a list of dicts (or dict for 'profiles').
    """
    table = _TABLE_MAP.get(name)
    if not table:
        return [] if name != "profiles" else {}
    try:
        with db_cursor(commit=False) as cur:
            cur.execute(f"SELECT * FROM {table}")
            rows = cur.fetchall()
            if name == "profiles":
                return {r["patient_id"]: _serial(dict(r)) for r in rows}
            return [_serial(dict(r)) for r in rows]
    except Exception:
        return [] if name != "profiles" else {}


# ── Appointments ──────────────────────────────────────────────────────────────

def add_appointment(appt: dict):
    meds = appt.get("medications")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO emr_appointments
                (id, patient_id, doctor_id, date_time, reason, status, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            appt.get("id", str(__import__("uuid").uuid4())),
            appt["patient_id"],
            appt["doctor_id"],
            appt.get("date_time", ""),
            appt.get("reason", ""),
            appt.get("status", "scheduled"),
            appt.get("notes", ""),
        ))


def get_appointment(appt_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM emr_appointments WHERE id = %s", (appt_id,))
        row = cur.fetchone()
        return _serial(dict(row)) if row else None


def update_appointment(appt_id: str, updates: dict) -> dict | None:
    ALLOWED = {"date_time", "reason", "status", "notes", "updated_at"}
    set_parts = []
    params = []
    for field, value in updates.items():
        if field not in ALLOWED:
            continue
        set_parts.append(f"{field} = %s")
        params.append(value)
    if not set_parts:
        return get_appointment(appt_id)
    # always update updated_at
    if "updated_at" not in [p.split(" ")[0] for p in set_parts]:
        set_parts.append("updated_at = now()")
    params.append(appt_id)
    with db_cursor() as cur:
        cur.execute(
            f"UPDATE emr_appointments SET {', '.join(set_parts)} WHERE id = %s RETURNING *",
            params
        )
        row = cur.fetchone()
        return _serial(dict(row)) if row else None


def delete_appointment(appt_id: str) -> bool:
    with db_cursor() as cur:
        cur.execute("DELETE FROM emr_appointments WHERE id = %s", (appt_id,))
        return cur.rowcount > 0


def appointments_for_patient(pid: str) -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_appointments WHERE patient_id = %s ORDER BY created_at DESC",
            (pid,)
        )
        return [_serial(dict(r)) for r in cur.fetchall()]


def appointments_for_doctor(did: str) -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_appointments WHERE doctor_id = %s ORDER BY created_at DESC",
            (did,)
        )
        return [_serial(dict(r)) for r in cur.fetchall()]


# ── Prescriptions ─────────────────────────────────────────────────────────────

def add_prescription(rx: dict):
    medications = rx.get("medications", [])
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO emr_prescriptions
                (id, patient_id, doctor_id, doctor_email, diagnosis,
                 medications, notes, encounter_id, condition_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            rx.get("id", str(__import__("uuid").uuid4())),
            rx["patient_id"],
            rx["doctor_id"],
            rx.get("doctor_email", ""),
            rx.get("diagnosis", ""),
            json.dumps(medications) if isinstance(medications, list) else medications,
            rx.get("notes", ""),
            rx.get("encounter_id") or None,
            rx.get("condition_id") or None,
        ))


def get_prescription(rx_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM emr_prescriptions WHERE id = %s", (rx_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = _serial(dict(row))
        meds = d.get("medications")
        if isinstance(meds, str):
            try:
                d["medications"] = json.loads(meds)
            except (ValueError, TypeError):
                d["medications"] = []
        return d


def prescriptions_for_patient(pid: str) -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_prescriptions WHERE patient_id = %s ORDER BY created_at DESC",
            (pid,)
        )
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = _serial(dict(row))
            meds = d.get("medications")
            if isinstance(meds, str):
                try:
                    d["medications"] = json.loads(meds)
                except (ValueError, TypeError):
                    d["medications"] = []
            result.append(d)
        return result


def prescriptions_for_doctor(did: str) -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_prescriptions WHERE doctor_id = %s ORDER BY created_at DESC",
            (did,)
        )
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = _serial(dict(row))
            meds = d.get("medications")
            if isinstance(meds, str):
                try:
                    d["medications"] = json.loads(meds)
                except (ValueError, TypeError):
                    d["medications"] = []
            result.append(d)
        return result


# ── Lab Reports ───────────────────────────────────────────────────────────────

def add_lab_report(report: dict):
    results = report.get("results", {})
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO emr_lab_reports
                (id, patient_id, doctor_id, doctor_email, report_type,
                 results, file_hash, notes, encounter_id, condition_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            report.get("id", str(__import__("uuid").uuid4())),
            report["patient_id"],
            report.get("doctor_id", ""),
            report.get("doctor_email", ""),
            report["report_type"],
            json.dumps(results) if isinstance(results, dict) else results,
            report.get("file_hash", ""),
            report.get("notes", ""),
            report.get("encounter_id") or None,
            report.get("condition_id") or None,
        ))


def get_lab_report(report_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM emr_lab_reports WHERE id = %s", (report_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = _serial(dict(row))
        res = d.get("results")
        if isinstance(res, str):
            try:
                d["results"] = json.loads(res)
            except (ValueError, TypeError):
                d["results"] = {}
        return d


def lab_reports_for_patient(pid: str) -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_lab_reports WHERE patient_id = %s ORDER BY created_at DESC",
            (pid,)
        )
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = _serial(dict(row))
            res = d.get("results")
            if isinstance(res, str):
                try:
                    d["results"] = json.loads(res)
                except (ValueError, TypeError):
                    d["results"] = {}
            result.append(d)
        return result


# ── Conditions (Problem List) ─────────────────────────────────────────────────

def add_condition(cond: dict):
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO conditions
                (id, patient_id, description, icd10_code, status,
                 onset_date, resolved_date, recorded_by,
                 encounter_id, notes, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            cond.get("id", str(__import__("uuid").uuid4())),
            cond["patient_id"],
            cond["description"],
            cond.get("icd10_code", ""),
            cond.get("status", "active"),
            cond.get("onset_date") or None,
            cond.get("resolved_date") or None,
            cond["recorded_by"],
            cond.get("encounter_id") or None,
            cond.get("notes", ""),
            cond.get("created_at"),
            cond.get("updated_at"),
        ))


def get_condition(condition_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM conditions WHERE id = %s", (condition_id,))
        row = cur.fetchone()
        return _serial(dict(row)) if row else None


def update_condition(condition_id: str, updates: dict) -> dict | None:
    """Allowed update fields mirror update_appointment's ALLOWED-set pattern."""
    ALLOWED = {"status", "resolved_date", "notes", "updated_at"}
    set_parts = []
    params = []
    for field, value in updates.items():
        if field not in ALLOWED:
            continue
        set_parts.append(f"{field} = %s")
        params.append(value)
    if not set_parts:
        return get_condition(condition_id)
    if "updated_at" not in [p.split(" ")[0] for p in set_parts]:
        set_parts.append("updated_at = now()")
    params.append(condition_id)
    with db_cursor() as cur:
        cur.execute(
            f"UPDATE conditions SET {', '.join(set_parts)} WHERE id = %s RETURNING *",
            params,
        )
        row = cur.fetchone()
        return _serial(dict(row)) if row else None


def conditions_for_patient(patient_id: str, status: str | None = None) -> list[dict]:
    """Return all conditions for a patient, optionally filtered by status."""
    with db_cursor(commit=False) as cur:
        if status:
            cur.execute(
                "SELECT * FROM conditions WHERE patient_id = %s AND status = %s "
                "ORDER BY onset_date DESC NULLS LAST, created_at DESC",
                (patient_id, status),
            )
        else:
            cur.execute(
                "SELECT * FROM conditions WHERE patient_id = %s "
                "ORDER BY onset_date DESC NULLS LAST, created_at DESC",
                (patient_id,),
            )
        return [_serial(dict(r)) for r in cur.fetchall()]


# ── Encounters ────────────────────────────────────────────────────────────────

def add_encounter(enc: dict):
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO encounters
                (id, patient_id, doctor_id, appointment_id,
                 appointment_source, status, reason, summary,
                 started_at, completed_at, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            enc.get("id", str(__import__("uuid").uuid4())),
            enc["patient_id"],
            enc["doctor_id"],
            enc.get("appointment_id") or None,
            enc.get("appointment_source", ""),
            enc.get("status", "in_progress"),
            enc.get("reason", ""),
            enc.get("summary", ""),
            enc.get("started_at"),
            enc.get("completed_at") or None,
            enc.get("created_at"),
            enc.get("updated_at"),
        ))


def get_encounter(encounter_id: str) -> dict | None:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM encounters WHERE id = %s", (encounter_id,))
        row = cur.fetchone()
        return _serial(dict(row)) if row else None


def update_encounter(encounter_id: str, updates: dict) -> dict | None:
    """Allowed fields mirror update_appointment's ALLOWED-set pattern."""
    ALLOWED = {"status", "summary", "completed_at", "updated_at"}
    set_parts = []
    params = []
    for field, value in updates.items():
        if field not in ALLOWED:
            continue
        set_parts.append(f"{field} = %s")
        params.append(value)
    if not set_parts:
        return get_encounter(encounter_id)
    if "updated_at" not in [p.split(" ")[0] for p in set_parts]:
        set_parts.append("updated_at = now()")
    params.append(encounter_id)
    with db_cursor() as cur:
        cur.execute(
            f"UPDATE encounters SET {', '.join(set_parts)} WHERE id = %s RETURNING *",
            params,
        )
        row = cur.fetchone()
        return _serial(dict(row)) if row else None


def encounters_for_patient(patient_id: str) -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM encounters WHERE patient_id = %s ORDER BY started_at DESC",
            (patient_id,),
        )
        return [_serial(dict(r)) for r in cur.fetchall()]


def encounters_for_doctor(doctor_id: str) -> list[dict]:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM encounters WHERE doctor_id = %s ORDER BY started_at DESC",
            (doctor_id,),
        )
        return [_serial(dict(r)) for r in cur.fetchall()]


def get_encounter_bundle(encounter_id: str) -> dict:
    """
    Return a complete encounter bundle: the encounter row, its linked
    appointment (from the appropriate table based on appointment_source),
    plus all notes, prescriptions, and lab reports tagged with this
    encounter_id.

    Uses four simple SELECTs composed in Python — consistent with this
    file's existing style; no JOIN mega-query.
    """
    enc = get_encounter(encounter_id)
    if not enc:
        return {
            "encounter":     None,
            "appointment":   None,
            "notes":         [],
            "prescriptions": [],
            "lab_reports":   [],
        }

    # ── Appointment — fetch from the correct table ────────────────────────────
    appointment = None
    appt_id  = enc.get("appointment_id")
    appt_src = enc.get("appointment_source", "")
    if appt_id:
        with db_cursor(commit=False) as cur:
            if appt_src == "legacy":
                cur.execute(
                    "SELECT * FROM appointments WHERE id = %s", (appt_id,)
                )
            else:   # 'emr' or unset — default to emr_appointments
                cur.execute(
                    "SELECT * FROM emr_appointments WHERE id = %s", (appt_id,)
                )
            row = cur.fetchone()
            if row:
                appointment = _serial(dict(row))

    # ── Notes ─────────────────────────────────────────────────────────────────
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM doctor_notes WHERE encounter_id = %s ORDER BY created_at ASC",
            (encounter_id,),
        )
        notes = [_serial(dict(r)) for r in cur.fetchall()]

    # ── Prescriptions ─────────────────────────────────────────────────────────
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_prescriptions WHERE encounter_id = %s ORDER BY created_at ASC",
            (encounter_id,),
        )
        prescriptions = []
        for row in cur.fetchall():
            d = _serial(dict(row))
            meds = d.get("medications")
            if isinstance(meds, str):
                try:
                    d["medications"] = json.loads(meds)
                except (ValueError, TypeError):
                    d["medications"] = []
            prescriptions.append(d)

    # ── Lab Reports ───────────────────────────────────────────────────────────
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM emr_lab_reports WHERE encounter_id = %s ORDER BY created_at ASC",
            (encounter_id,),
        )
        lab_reports = []
        for row in cur.fetchall():
            d = _serial(dict(row))
            res = d.get("results")
            if isinstance(res, str):
                try:
                    d["results"] = json.loads(res)
                except (ValueError, TypeError):
                    d["results"] = {}
            lab_reports.append(d)

    return {
        "encounter":     enc,
        "appointment":   appointment,
        "notes":         notes,
        "prescriptions": prescriptions,
        "lab_reports":   lab_reports,
    }
