"""
emr/models.py — Data schemas and validation for EMR entities.

Each model is a plain dict factory with a validate() function.
Keeps the project's existing coding style (no ORM, no dataclasses).
"""

import uuid
from datetime import datetime, timezone


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _require(data: dict, fields: list[str]) -> list[str]:
    """Return list of missing required field names."""
    return [f for f in fields if not data.get(f)]


# ── Patient Profile ──────────────────────────────────────────────────────────

BLOOD_GROUPS = {"A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-", ""}
GENDERS      = {"male", "female", "other", "prefer_not_to_say", ""}

def validate_patient_profile(data: dict) -> list[str]:
    """Return list of validation error strings (empty = valid)."""
    errors = []
    if not data.get("patient_id"):
        errors.append("patient_id is required")
    gender = (data.get("gender") or "").lower()
    if gender and gender not in GENDERS:
        errors.append(f"invalid gender: {gender}")
    bg = (data.get("blood_group") or "").upper()
    if bg and bg not in BLOOD_GROUPS:
        errors.append(f"invalid blood_group: {bg}")
    age = data.get("age")
    if age is not None:
        try:
            age_int = int(age)
            if age_int < 0 or age_int > 150:
                errors.append("age must be between 0 and 150")
        except (ValueError, TypeError):
            errors.append("age must be a number")
    return errors


def new_patient_profile(data: dict) -> dict:
    """Create a normalised patient profile dict."""
    return {
        "patient_id":        data["patient_id"],
        "name":              (data.get("name") or "").strip(),
        "age":               data.get("age", ""),
        "gender":            (data.get("gender") or "").lower(),
        "blood_group":       (data.get("blood_group") or "").upper(),
        "medical_history":   data.get("medical_history", []),
        "allergies":         data.get("allergies", []),
        "emergency_contact": data.get("emergency_contact", {}),
        "past_visits":       data.get("past_visits", []),
        "created_at":        _now_iso(),
        "updated_at":        _now_iso(),
    }


# ── Appointment ───────────────────────────────────────────────────────────────

APPOINTMENT_STATUSES = {"scheduled", "completed", "cancelled", "no_show"}

def validate_appointment(data: dict) -> list[str]:
    errors = _require(data, ["patient_id", "doctor_id", "date_time"])
    status = (data.get("status") or "scheduled").lower()
    if status not in APPOINTMENT_STATUSES:
        errors.append(f"invalid status: {status}")
    if data.get("date_time"):
        try:
            datetime.fromisoformat(data["date_time"])
        except ValueError:
            errors.append("date_time must be ISO 8601 format")
    return errors


def new_appointment(data: dict) -> dict:
    return {
        "id":         str(uuid.uuid4()),
        "patient_id": data["patient_id"],
        "doctor_id":  data["doctor_id"],
        "date_time":  data["date_time"],
        "reason":     (data.get("reason") or "").strip(),
        "status":     (data.get("status") or "scheduled").lower(),
        "notes":      (data.get("notes") or "").strip(),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }


# ── Prescription ──────────────────────────────────────────────────────────────

def validate_prescription(data: dict) -> list[str]:
    errors = _require(data, ["patient_id", "doctor_id", "medications"])
    meds = data.get("medications")
    if meds is not None:
        if not isinstance(meds, list) or len(meds) == 0:
            errors.append("medications must be a non-empty list")
        else:
            for i, m in enumerate(meds):
                if not isinstance(m, dict) or not m.get("name"):
                    errors.append(f"medications[{i}] must have a 'name'")
    return errors


def new_prescription(data: dict) -> dict:
    meds = []
    for m in data.get("medications", []):
        meds.append({
            "name":      (m.get("name") or "").strip(),
            "dosage":    (m.get("dosage") or "").strip(),
            "frequency": (m.get("frequency") or "").strip(),
            "duration":  (m.get("duration") or "").strip(),
        })
    return {
        "id":         str(uuid.uuid4()),
        "patient_id": data["patient_id"],
        "doctor_id":  data["doctor_id"],
        "doctor_email": data.get("doctor_email", ""),
        "diagnosis":  (data.get("diagnosis") or "").strip(),
        "medications": meds,
        "notes":      (data.get("notes") or "").strip(),
        "created_at": _now_iso(),
    }


# ── Lab Report ────────────────────────────────────────────────────────────────

def validate_lab_report(data: dict) -> list[str]:
    errors = _require(data, ["patient_id", "report_type"])
    return errors


def new_lab_report(data: dict) -> dict:
    return {
        "id":          str(uuid.uuid4()),
        "patient_id":  data["patient_id"],
        "doctor_id":   data.get("doctor_id", ""),
        "doctor_email": data.get("doctor_email", ""),
        "report_type": (data.get("report_type") or "").strip(),
        "results":     data.get("results", {}),
        "file_hash":   data.get("file_hash", ""),
        "notes":       (data.get("notes") or "").strip(),
        "created_at":  _now_iso(),
    }
