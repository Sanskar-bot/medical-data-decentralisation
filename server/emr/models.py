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


def _norm_allergy_list(value) -> list[str]:
    """
    Normalise an allergy value to a clean, deduplicated list[str].

    Accepts:
      - list[str]  — already the right type; cleaned in-place
      - str        — comma-separated, e.g. "Penicillin, Sulfa drugs"
      - None / ""  — returns []

    Rules:
      - Each item is stripped of surrounding whitespace.
      - Empty strings after stripping are dropped.
      - Deduplication is case-insensitive; the first occurrence's original
        casing is preserved.
    """
    if not value:
        return []

    if isinstance(value, list):
        items = [str(v).strip() for v in value]
    elif isinstance(value, str):
        items = [v.strip() for v in value.split(",")]
    else:
        # Unexpected type — coerce to string and treat as single item
        items = [str(value).strip()]

    seen_lower: set[str] = set()
    result: list[str] = []
    for item in items:
        if not item:
            continue
        key = item.lower()
        if key not in seen_lower:
            seen_lower.add(key)
            result.append(item)
    return result


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
        # Normalise allergies — accept both list and comma-string from callers
        "allergies":         _norm_allergy_list(data.get("allergies", [])),
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
            "dosage":    (m.get("dosage") or m.get("dose") or "").strip(),
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


# ── Allergy / Drug-Interaction Safety ─────────────────────────────────────────
#
# IMPORTANT — scope disclaimer:
#   ALLERGY_CROSS_REACTIVITY is a conservative, well-known clinical list
#   designed to catch obvious prescribing misses (e.g. prescribing Amoxicillin
#   to a patient with a recorded Penicillin allergy).  It is NOT a substitute
#   for a licensed drug-interaction database (e.g. First Databank, Multum,
#   DrugBank).  Do not extend its scope without clinical review.
#
ALLERGY_CROSS_REACTIVITY: dict[str, list[str]] = {
    # Penicillin family — all beta-lactam penicillins share cross-reactivity
    "penicillin": [
        "amoxicillin", "ampicillin", "augmentin", "piperacillin",
        "ticarcillin", "oxacillin", "nafcillin", "dicloxacillin",
        "flucloxacillin", "phenoxymethylpenicillin", "cloxacillin",
    ],
    # Cephalosporins — 1–10 % cross-reactivity with penicillin allergy
    "cephalosporin": [
        "cephalexin", "cefazolin", "cefuroxime", "cefdinir", "cefixime",
        "ceftriaxone", "cefepime", "ceftazidime", "cefaclor", "cefprozil",
        "cefotaxime", "cefpodoxime",
    ],
    # Sulfa drugs
    "sulfa": [
        "sulfamethoxazole", "bactrim", "septra", "sulfasalazine",
        "sulfadiazine", "sulfadoxine", "co-trimoxazole", "trimethoprim-sulfamethoxazole",
    ],
    "sulfonamide": [
        "sulfamethoxazole", "bactrim", "septra", "sulfasalazine",
        "sulfadiazine", "co-trimoxazole",
    ],
    # NSAIDs
    "nsaid": [
        "ibuprofen", "naproxen", "diclofenac", "aspirin", "ketorolac",
        "indomethacin", "celecoxib", "meloxicam", "piroxicam",
        "etodolac", "mefenamic acid", "sulindac",
    ],
    "aspirin": [
        "ibuprofen", "naproxen", "diclofenac", "ketorolac",
        "indomethacin", "celecoxib", "meloxicam", "piroxicam",
    ],
    # Opioids — codeine-derived cross-reactivity
    "codeine": [
        "morphine", "hydrocodone", "oxycodone", "hydromorphone",
        "dihydrocodeine",
    ],
    "opioid": [
        "codeine", "morphine", "hydrocodone", "oxycodone", "hydromorphone",
        "fentanyl", "tramadol", "buprenorphine", "methadone",
    ],
    # Latex — some medications use latex stoppers; also topical sensitisers
    "latex": [
        "latex", "rubber",  # unlikely medication names, but catch labelling
    ],
    # Iodine / iodinated contrast — relevant for thyroid meds, antiseptics
    "iodine": [
        "povidone-iodine", "iodinated contrast", "lugol", "amiodarone",
        "levothyroxine",  # contains iodine; include as moderate risk
    ],
    "contrast": [
        "iodinated contrast", "omnipaque", "visipaque", "optiray",
        "iohexol", "iodixanol",
    ],
    # Egg allergy — relevant for propofol and some vaccines
    "egg": [
        "propofol", "ketamine",  # propofol emulsion contains egg lecithin
    ],
    # Shellfish → protamine (extracted from fish sperm, not shellfish, but
    # the clinical cross-reactivity concern is documented and widely taught)
    "shellfish": [
        "protamine",
    ],
}


def check_allergy_conflicts(
    allergies: list[str],
    medications: list[dict],
) -> list[dict]:
    """
    Check a list of medications against a patient's recorded allergies.

    Parameters
    ----------
    allergies  : list[str]  — patient's recorded allergy terms (may be empty)
    medications: list[dict] — each dict must have at least a "name" key

    Returns
    -------
    list[dict] — one entry per detected conflict:
        {
            "medication":   <name as entered>,
            "allergy":      <allergy as recorded>,
            "matched_term": <substring that triggered the match>,
            "severity":     "high" | "moderate",
        }

    Behaviour
    ---------
    - Direct substring match (allergy term in medication name or vice-versa)
      → severity "high".
    - Match only via ALLERGY_CROSS_REACTIVITY table → severity "moderate".
    - Deduplicates identical (medication, allergy) pairs.
    - Never raises; never mutates inputs; no DB / network access.
    """
    if not allergies or not medications:
        return []

    conflicts: list[dict] = []
    seen: set[tuple[str, str]] = set()   # (med_name_lower, allergy_lower)

    for med in medications:
        med_name = (med.get("name") or "").strip()
        if not med_name:
            continue
        med_lower = med_name.lower()

        for allergy in allergies:
            allergy_str = str(allergy).strip()
            if not allergy_str:
                continue
            allergy_lower = allergy_str.lower()

            dedup_key = (med_lower, allergy_lower)
            if dedup_key in seen:
                continue

            severity = None
            matched_term = None

            # ── Direct match: allergy term appears in med name or vice-versa
            if allergy_lower in med_lower or med_lower in allergy_lower:
                severity = "high"
                matched_term = allergy_lower if allergy_lower in med_lower else med_lower

            # ── Cross-reactivity match
            if severity is None:
                for trigger, cross_meds in ALLERGY_CROSS_REACTIVITY.items():
                    # Check if this allergy matches the trigger term
                    if trigger in allergy_lower or allergy_lower in trigger:
                        # Check if this medication matches any cross-reactive drug
                        for cross_med in cross_meds:
                            if cross_med in med_lower or med_lower in cross_med:
                                severity = "moderate"
                                matched_term = cross_med
                                break
                    if severity:
                        break

                # Also check if the allergy itself names a drug that is
                # cross-reactive in the reverse direction
                if severity is None:
                    for trigger, cross_meds in ALLERGY_CROSS_REACTIVITY.items():
                        for cross_med in cross_meds:
                            if cross_med in allergy_lower or allergy_lower in cross_med:
                                if trigger in med_lower or med_lower in trigger:
                                    severity = "moderate"
                                    matched_term = trigger
                                    break
                        if severity:
                            break

            if severity:
                seen.add(dedup_key)
                conflicts.append({
                    "medication":   med_name,
                    "allergy":      allergy_str,
                    "matched_term": matched_term,
                    "severity":     severity,
                })

    return conflicts


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


# ── Condition (Problem List) ──────────────────────────────────────────────────

CONDITION_STATUSES = {"active", "resolved", "inactive"}

def validate_condition(data: dict) -> list[str]:
    """Return list of validation error strings (empty = valid)."""
    errors = _require(data, ["patient_id", "description", "recorded_by"])
    status = (data.get("status") or "active").lower()
    if status not in CONDITION_STATUSES:
        errors.append(f"invalid status: {status!r}; must be one of {sorted(CONDITION_STATUSES)}")
    for date_field in ("onset_date", "resolved_date"):
        val = data.get(date_field)
        if val and str(val).strip():
            try:
                datetime.fromisoformat(str(val).strip())
            except ValueError:
                errors.append(f"{date_field} must be an ISO date string (e.g. 2024-01-15)")
    return errors


def new_condition(data: dict) -> dict:
    """Create a normalised condition dict."""
    return {
        "id":            str(uuid.uuid4()),
        "patient_id":    data["patient_id"],
        "description":   (data.get("description") or "").strip(),
        "icd10_code":    (data.get("icd10_code") or "").strip(),
        "status":        (data.get("status") or "active").lower(),
        "onset_date":    (data.get("onset_date") or "").strip() or None,
        "resolved_date": (data.get("resolved_date") or "").strip() or None,
        "recorded_by":   (data.get("recorded_by") or "").strip(),
        "encounter_id":  data.get("encounter_id") or None,
        "notes":         (data.get("notes") or "").strip(),
        "created_at":    _now_iso(),
        "updated_at":    _now_iso(),
    }


# ── Encounter ─────────────────────────────────────────────────────────────────

ENCOUNTER_STATUSES   = {"in_progress", "completed", "cancelled"}
APPOINTMENT_SOURCES  = {"", "legacy", "emr"}

def validate_encounter(data: dict) -> list[str]:
    """Return list of validation error strings (empty = valid)."""
    errors = _require(data, ["patient_id", "doctor_id"])
    status = (data.get("status") or "in_progress").lower()
    if status not in ENCOUNTER_STATUSES:
        errors.append(f"invalid status: {status!r}; must be one of {sorted(ENCOUNTER_STATUSES)}")
    appt_src = (data.get("appointment_source") or "").lower()
    if appt_src not in APPOINTMENT_SOURCES:
        errors.append(
            f"invalid appointment_source: {appt_src!r}; "
            f"must be one of {sorted(APPOINTMENT_SOURCES)}"
        )
    return errors


def new_encounter(data: dict) -> dict:
    """Create a normalised encounter dict."""
    return {
        "id":                 str(uuid.uuid4()),
        "patient_id":         data["patient_id"],
        "doctor_id":          data["doctor_id"],
        "appointment_id":     data.get("appointment_id") or None,
        "appointment_source": (data.get("appointment_source") or "").lower(),
        "status":             (data.get("status") or "in_progress").lower(),
        "reason":             (data.get("reason") or "").strip(),
        "summary":            (data.get("summary") or "").strip(),
        "started_at":         _now_iso(),
        "completed_at":       data.get("completed_at") or None,
        "created_at":         _now_iso(),
        "updated_at":         _now_iso(),
    }
