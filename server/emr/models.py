"""
emr/models.py — Data schemas and validation for EMR entities.

Each model is a plain dict factory with a validate() function.
Keeps the project's existing coding style (no ORM, no dataclasses).
"""

import re
import uuid
from datetime import date, datetime, timezone


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def compute_age(dob_str: str) -> int | None:
    """
    Compute current age in whole years from an ISO-8601 date string (YYYY-MM-DD).

    Returns None if *dob_str* is absent, blank, or unparseable.
    Returns 0 for a date of birth in the future (edge case guard).
    """
    if not dob_str:
        return None
    try:
        dob = date.fromisoformat(str(dob_str).strip())
    except (ValueError, TypeError):
        return None
    today = date.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    return max(0, age)



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

    # date_of_birth is the preferred field (replaces free-text age).
    # 'age' is still accepted for backward-compatibility but is soft-deprecated.
    dob = data.get("date_of_birth")
    if dob and str(dob).strip():
        try:
            parsed_dob = date.fromisoformat(str(dob).strip())
            if parsed_dob > date.today():
                errors.append("date_of_birth cannot be in the future")
        except (ValueError, TypeError):
            errors.append("date_of_birth must be a valid ISO date (YYYY-MM-DD)")
    else:
        # Legacy age integer field — only validated when date_of_birth is absent
        age = data.get("age")
        if age is not None and str(age).strip():
            try:
                age_int = int(age)
                if age_int < 0 or age_int > 150:
                    errors.append("age must be between 0 and 150")
            except (ValueError, TypeError):
                errors.append("age must be a number")
    return errors


def new_patient_profile(data: dict) -> dict:
    """Create a normalised patient profile dict."""
    dob_raw = (data.get("date_of_birth") or "").strip()
    # Back-compat: if caller only sends age (integer), keep it as-is
    age_raw = data.get("age", "")
    # Compute age from DOB when available, otherwise keep legacy value
    computed_age = compute_age(dob_raw) if dob_raw else (
        int(age_raw) if str(age_raw).strip().isdigit() else age_raw
    )
    return {
        "patient_id":        data["patient_id"],
        "name":              (data.get("name") or "").strip(),
        # Structured demographic — preferred over legacy 'age' text
        "date_of_birth":     dob_raw or None,
        # 'age' is kept for display convenience and backward-compat;
        # always derived from date_of_birth when present
        "age":               computed_age,
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
                else:
                    # Validate structured fields when explicitly provided
                    if m.get("dosage_value") is not None:
                        try:
                            v = float(m["dosage_value"])
                            if v <= 0:
                                errors.append(f"medications[{i}].dosage_value must be positive")
                        except (TypeError, ValueError):
                            errors.append(f"medications[{i}].dosage_value must be a number")
                    if m.get("duration_days") is not None:
                        try:
                            d = int(m["duration_days"])
                            if d <= 0:
                                errors.append(f"medications[{i}].duration_days must be a positive integer")
                        except (TypeError, ValueError):
                            errors.append(f"medications[{i}].duration_days must be an integer")
    return errors


# ── Medication standardization helpers (Bug 4) ────────────────────────────────
#
# These parsers are heuristic and intentionally conservative — they never
# mutate or discard the original free-text fields; they only ADD structured
# fields alongside them.  All parsing failures silently return None so the
# prescription is always saved.

# Frequency normalizer: maps common abbreviations/phrases → canonical form
FREQUENCY_NORMALIZER: dict[str, tuple[str, float]] = {
    # (canonical_name, approximate times_per_day)
    "od": ("once_daily", 1),
    "qd": ("once_daily", 1),
    "qdaily": ("once_daily", 1),
    "once daily": ("once_daily", 1),
    "once a day": ("once_daily", 1),
    "every day": ("once_daily", 1),
    "daily": ("once_daily", 1),
    "1x/day": ("once_daily", 1),
    "1x daily": ("once_daily", 1),
    "bd": ("twice_daily", 2),
    "bid": ("twice_daily", 2),
    "b.i.d": ("twice_daily", 2),
    "b.i.d.": ("twice_daily", 2),
    "twice daily": ("twice_daily", 2),
    "twice a day": ("twice_daily", 2),
    "2x/day": ("twice_daily", 2),
    "2x daily": ("twice_daily", 2),
    "every 12 hours": ("twice_daily", 2),
    "q12h": ("twice_daily", 2),
    "tid": ("three_times_daily", 3),
    "t.i.d": ("three_times_daily", 3),
    "t.i.d.": ("three_times_daily", 3),
    "three times daily": ("three_times_daily", 3),
    "three times a day": ("three_times_daily", 3),
    "3x/day": ("three_times_daily", 3),
    "3x daily": ("three_times_daily", 3),
    "every 8 hours": ("three_times_daily", 3),
    "q8h": ("three_times_daily", 3),
    "qid": ("four_times_daily", 4),
    "q.i.d": ("four_times_daily", 4),
    "q.i.d.": ("four_times_daily", 4),
    "four times daily": ("four_times_daily", 4),
    "four times a day": ("four_times_daily", 4),
    "4x/day": ("four_times_daily", 4),
    "every 6 hours": ("four_times_daily", 4),
    "q6h": ("four_times_daily", 4),
    "qhs": ("at_bedtime", 1),
    "hs": ("at_bedtime", 1),
    "at bedtime": ("at_bedtime", 1),
    "nocte": ("at_bedtime", 1),
    "prn": ("as_needed", 0),
    "as needed": ("as_needed", 0),
    "when needed": ("as_needed", 0),
    "every 4 hours": ("every_4_hours", 6),
    "q4h": ("every_4_hours", 6),
    "weekly": ("weekly", 1/7),
    "once weekly": ("weekly", 1/7),
    "monthly": ("monthly", 1/30),
}

# Route aliases: maps common abbreviations → canonical form
ROUTE_ALIASES: dict[str, str] = {
    "po": "oral", "oral": "oral", "by mouth": "oral", "p.o.": "oral",
    "iv": "intravenous", "i.v.": "intravenous", "intravenous": "intravenous",
    "im": "intramuscular", "i.m.": "intramuscular", "intramuscular": "intramuscular",
    "sc": "subcutaneous", "sq": "subcutaneous", "subcut": "subcutaneous",
    "subcutaneous": "subcutaneous", "s.c.": "subcutaneous",
    "sl": "sublingual", "sublingual": "sublingual",
    "top": "topical", "topical": "topical",
    "inh": "inhaled", "inhaled": "inhaled", "inhalation": "inhaled",
    "pr": "rectal", "rectal": "rectal",
    "nasal": "nasal", "intranasal": "nasal",
    "otic": "otic", "ophthalmic": "ophthalmic", "eye": "ophthalmic",
    "td": "transdermal", "transdermal": "transdermal", "patch": "transdermal",
}

# Dosage unit canonicalization
_DOSAGE_UNITS = {
    "mg": "mg", "milligram": "mg", "milligrams": "mg",
    "g": "g", "gram": "g", "grams": "g",
    "mcg": "mcg", "microgram": "mcg", "micrograms": "mcg", "ug": "mcg",
    "ml": "ml", "milliliter": "ml", "milliliters": "ml", "millilitre": "ml",
    "l": "l", "liter": "l", "litre": "l",
    "iu": "IU", "units": "units", "unit": "units",
    "meq": "mEq", "mmol": "mmol", "percent": "%", "%": "%",
    "tablet": "tablet", "tablets": "tablet",
    "capsule": "capsule", "capsules": "capsule",
    "drop": "drop", "drops": "drop",
    "puff": "puff", "puffs": "puff",
    "patch": "patch",
}


def parse_dosage(text: str) -> dict | None:
    """
    Parse a free-text dosage string into structured fields.

    Examples:
        "500mg"   -> {"value": 500.0, "unit": "mg"}
        "0.5 g"   -> {"value": 0.5,   "unit": "g"}
        "5 ml"    -> {"value": 5.0,   "unit": "ml"}
        "2 tabs"  -> {"value": 2.0,   "unit": "tablet"}

    Returns None if the string cannot be parsed.
    """
    if not text:
        return None
    text = text.strip()
    # Pattern: optional number + optional space + unit
    m = re.match(
        r'^([0-9]+(?:\.[0-9]+)?)\s*'
        r'([a-zA-Z%]+)',
        text,
    )
    if not m:
        return None
    try:
        value = float(m.group(1))
    except ValueError:
        return None
    unit_raw = m.group(2).lower()
    unit = _DOSAGE_UNITS.get(unit_raw)
    if not unit:
        # Unknown unit — preserve as-is (lowercase)
        unit = unit_raw
    return {"value": value, "unit": unit}


def parse_frequency(text: str) -> dict | None:
    """
    Normalize a frequency string to a canonical form.

    Returns:
        {"normalized": "twice_daily", "times_per_day": 2}
    or None if not recognized.
    """
    if not text:
        return None
    key = text.strip().lower()
    # Remove trailing punctuation before lookup
    key_clean = key.rstrip(".").strip()
    match = FREQUENCY_NORMALIZER.get(key_clean) or FREQUENCY_NORMALIZER.get(key)
    if match:
        return {"normalized": match[0], "times_per_day": match[1]}
    return None


def parse_duration(text: str) -> dict | None:
    """
    Parse a duration string into days.

    Examples:
        "7 days"   -> {"days": 7}
        "2 weeks"  -> {"days": 14}
        "1 month"  -> {"days": 30}
        "3 months" -> {"days": 90}

    Returns None if not parseable.
    """
    if not text:
        return None
    text = text.strip().lower()
    m = re.match(r'^([0-9]+(?:\.[0-9]+)?)\s*(day|days|week|weeks|month|months|year|years)', text)
    if not m:
        return None
    try:
        num = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2)
    if unit in ("day", "days"):
        days = num
    elif unit in ("week", "weeks"):
        days = num * 7
    elif unit in ("month", "months"):
        days = num * 30
    elif unit in ("year", "years"):
        days = num * 365
    else:
        return None
    return {"days": round(days)}


def _enrich_medication(m: dict) -> dict:
    """
    Enrich a raw medication dict with structured parsed fields.

    Raw free-text fields (name, dosage, frequency, duration) are preserved
    unchanged.  Structured fields are added alongside them.
    Never raises — parsing failures silently leave structured fields absent.
    """
    name     = (m.get("name")      or "").strip()
    dosage   = (m.get("dosage")    or m.get("dose") or "").strip()
    freq     = (m.get("frequency") or "").strip()
    duration = (m.get("duration")  or "").strip()
    route    = (m.get("route")     or "").strip().lower()

    enriched: dict = {
        # Canonical free-text fields (backward-compatible)
        "name":         name,
        "dosage":       dosage,
        "frequency":    freq,
        "duration":     duration,
        "instructions": (m.get("instructions") or "").strip(),
        "refills":      int(m.get("refills", 0) or 0),
    }

    # Structured dosage
    parsed_dosage = parse_dosage(dosage)
    if parsed_dosage:
        enriched["dosage_value"] = parsed_dosage["value"]
        enriched["dosage_unit"]  = parsed_dosage["unit"]
    elif m.get("dosage_value") is not None:
        # Caller explicitly provided structured dosage
        enriched["dosage_value"] = m["dosage_value"]
        enriched["dosage_unit"]  = m.get("dosage_unit", "")

    # Structured frequency
    parsed_freq = parse_frequency(freq)
    if parsed_freq:
        enriched["frequency_normalized"] = parsed_freq["normalized"]
        enriched["times_per_day"]        = parsed_freq["times_per_day"]
    elif m.get("frequency_normalized"):
        enriched["frequency_normalized"] = m["frequency_normalized"]
        enriched["times_per_day"]        = m.get("times_per_day")

    # Structured duration
    parsed_dur = parse_duration(duration)
    if parsed_dur:
        enriched["duration_days"] = parsed_dur["days"]
    elif m.get("duration_days") is not None:
        enriched["duration_days"] = m["duration_days"]

    # Normalized route
    canonical_route = ROUTE_ALIASES.get(route)
    if canonical_route:
        enriched["route"] = canonical_route
    elif route:
        enriched["route"] = route

    return enriched


def new_prescription(data: dict) -> dict:
    meds = [_enrich_medication(m) for m in data.get("medications", [])]
    return {
        "id":           str(uuid.uuid4()),
        "patient_id":   data["patient_id"],
        "doctor_id":    data["doctor_id"],
        "doctor_email": data.get("doctor_email", ""),
        "doctor_name":  data.get("doctor_name", ""),
        "diagnosis":    (data.get("diagnosis") or "").strip(),
        "medications":  meds,
        "notes":        (data.get("notes") or "").strip(),
        "created_at":   _now_iso(),
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
