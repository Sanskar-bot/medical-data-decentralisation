"""
emr/routes.py — Flask Blueprint with all EMR API endpoints.

Reuses the auth decorators and helpers defined in server.py:
  _require_jwt, rate_limited, audit, load_json, save_json

The blueprint is registered by server.py with:
    from emr.routes import emr_bp
    app.register_blueprint(emr_bp)
"""

import os
import json
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, jsonify

# ── EMR sub-modules ───────────────────────────────────────────────────────────
from . import models, store

emr_bp = Blueprint("emr", __name__, url_prefix="/emr")

# ── Late-bound references to server.py helpers ────────────────────────────────
# These are resolved at request-time via current_app so there's no circular
# import.  server.py attaches them to app.config during blueprint registration.

def _get_helper(name):
    from flask import current_app
    return current_app.config.get(f"EMR_{name}")


def _require_jwt_deco(roles=None):
    """Wrap server.py's _require_jwt so it works inside the blueprint."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            fn = _get_helper("require_jwt")
            if fn is None:
                return jsonify({"error": "auth not configured"}), 500
            # _require_jwt returns a decorator; we need to call it
            inner = fn(roles=roles)(f)
            return inner(*args, **kwargs)
        # Flask needs a unique endpoint name
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def _audit(action, actor="", target="", detail=""):
    fn = _get_helper("audit")
    if fn:
        fn(action, actor=actor, target=target, detail=detail)


def _resolve_pid(patient_id: str) -> str:
    """
    Resolve *patient_id* to the canonical users.id UUID.

    Accepts both a UUID and a profile_code (short alphanumeric).  Falls back
    to the original value when the resolver is unavailable or returns None,
    so this is always safe to call.
    """
    fn = _get_helper("resolve_patient_uuid")
    if fn:
        resolved = fn(patient_id)
        if resolved:
            return resolved
    return patient_id


def _rate_limited(max_calls=10, window=60):
    """Lazy wrapper for server.py's rate_limited.  Defers helper lookup to
    request-time so it works even when the blueprint is imported outside an
    app context (e.g. during tests or at module load)."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            fn = _get_helper("rate_limited")
            if fn:
                # Apply the real rate limiter at request time
                inner = fn(max_calls=max_calls, window=window)(f)
                return inner(*args, **kwargs)
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
#   PATIENT PROFILE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@emr_bp.route("/patient/<patient_id>/profile", methods=["GET"])
@_require_jwt_deco()
def get_patient_profile(patient_id):
    """Fetch extended EMR profile for a patient."""
    p = request.jwt_payload
    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    # Patient can only see own profile; doctors and admins can see any
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        # Also accept a match against the raw profile_code claim
        if p.get("profile_code") and p.get("profile_code") != request.view_args.get("patient_id"):
            return jsonify({"error": "forbidden"}), 403

    profile = store.get_profile(patient_id)
    if not profile:
        return jsonify({"error": "profile_not_found",
                        "hint": "Use PUT to create the profile first"}), 404
    return jsonify(profile), 200


@emr_bp.route("/patient/<patient_id>/profile", methods=["PUT"])
@_require_jwt_deco()
@_rate_limited(max_calls=10, window=60)
def upsert_patient_profile(patient_id):
    """Create or update a patient's extended EMR profile."""
    p = request.jwt_payload
    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403

    body = request.get_json(force=True) or {}
    body["patient_id"] = patient_id

    errors = models.validate_patient_profile(body)
    if errors:
        return jsonify({"error": "validation_failed", "details": errors}), 400

    existing = store.get_profile(patient_id)
    if existing:
        # Partial update — merge incoming fields into existing
        for key in ("name", "age", "gender", "blood_group",
                     "medical_history", "emergency_contact",
                     "past_visits"):
            if key in body:
                existing[key] = body[key]
        # Allergies require normalisation: the browser may send a
        # comma-separated string; we always persist a list.
        if "allergies" in body:
            existing["allergies"] = models._norm_allergy_list(body["allergies"])
        existing["updated_at"] = models._now_iso()
        store.upsert_profile(existing)
        _audit("emr_profile_updated", actor=p.get("sub", ""), target=patient_id)
        return jsonify(existing), 200
    else:
        profile = models.new_patient_profile(body)
        store.upsert_profile(profile)
        _audit("emr_profile_created", actor=p.get("sub", ""), target=patient_id)
        return jsonify(profile), 201


# ═══════════════════════════════════════════════════════════════════════════════
#   APPOINTMENT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@emr_bp.route("/appointments", methods=["POST"])
@_require_jwt_deco(roles=["doctor", "admin"])
@_rate_limited(max_calls=20, window=60)
def create_appointment():
    body = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    # Auto-fill doctor_id from JWT if not provided
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("uid", "")

    errors = models.validate_appointment(body)
    if errors:
        return jsonify({"error": "validation_failed", "details": errors}), 400

    appt = models.new_appointment(body)
    store.add_appointment(appt)
    _audit("appointment_created", actor=jwt_p.get("sub", ""),
           target=body["patient_id"], detail=f"id={appt['id']}")
    return jsonify(appt), 201


@emr_bp.route("/appointments/patient/<patient_id>", methods=["GET"])
@_require_jwt_deco()
def list_patient_appointments(patient_id):
    p = request.jwt_payload
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403
    appts = store.appointments_for_patient(patient_id)
    appts.sort(key=lambda a: a.get("date_time", ""), reverse=True)
    return jsonify(appts), 200


@emr_bp.route("/appointments/doctor/<doctor_id>", methods=["GET"])
@_require_jwt_deco(roles=["doctor", "admin"])
def list_doctor_appointments(doctor_id):
    p = request.jwt_payload
    if p.get("role") == "doctor" and p.get("uid") != doctor_id:
        return jsonify({"error": "forbidden"}), 403
    appts = store.appointments_for_doctor(doctor_id)
    appts.sort(key=lambda a: a.get("date_time", ""), reverse=True)
    return jsonify(appts), 200


@emr_bp.route("/appointments/<appointment_id>", methods=["PUT"])
@_require_jwt_deco(roles=["doctor", "admin"])
def update_appointment(appointment_id):
    body = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    existing = store.get_appointment(appointment_id)
    if not existing:
        return jsonify({"error": "appointment_not_found"}), 404

    # Only the assigned doctor or admin can update
    if jwt_p.get("role") == "doctor" and existing["doctor_id"] != jwt_p.get("uid"):
        return jsonify({"error": "forbidden"}), 403

    # Allowed update fields
    allowed = {"date_time", "reason", "status", "notes"}
    updates = {k: v for k, v in body.items() if k in allowed}
    updates["updated_at"] = models._now_iso()

    # Validate status if changing
    if "status" in updates:
        s = updates["status"].lower()
        if s not in models.APPOINTMENT_STATUSES:
            return jsonify({"error": f"invalid status: {s}"}), 400
        updates["status"] = s

    result = store.update_appointment(appointment_id, updates)
    _audit("appointment_updated", actor=jwt_p.get("sub", ""),
           target=existing["patient_id"], detail=f"id={appointment_id}")
    return jsonify(result), 200


@emr_bp.route("/appointments/<appointment_id>", methods=["DELETE"])
@_require_jwt_deco(roles=["doctor", "admin"])
def delete_appointment(appointment_id):
    jwt_p = request.jwt_payload

    existing = store.get_appointment(appointment_id)
    if not existing:
        return jsonify({"error": "appointment_not_found"}), 404

    if jwt_p.get("role") == "doctor" and existing["doctor_id"] != jwt_p.get("uid"):
        return jsonify({"error": "forbidden"}), 403

    store.delete_appointment(appointment_id)
    _audit("appointment_deleted", actor=jwt_p.get("sub", ""),
           target=existing["patient_id"], detail=f"id={appointment_id}")
    return jsonify({"message": "deleted", "id": appointment_id}), 200


# ═══════════════════════════════════════════════════════════════════════════════
#   E-PRESCRIPTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@emr_bp.route("/prescriptions", methods=["POST"])
@_require_jwt_deco(roles=["doctor", "admin"])
@_rate_limited(max_calls=20, window=60)
def create_prescription():
    body  = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    # Use doctor_code claim (not uid which is now UUID)
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
    body["doctor_email"] = jwt_p.get("sub", "")
    if not body.get("doctor_name"):
        body["doctor_name"] = ""  # Will be filled by caller if available

    errors = models.validate_prescription(body)
    if errors:
        return jsonify({"error": "validation_failed", "details": errors}), 400

    # ── Allergy / interaction safety check ───────────────────────────────────
    # Fetch the patient's EMR profile (None if they haven't created one yet).
    # A missing profile is not an error — it simply means no allergies are
    # recorded, so no conflicts are possible.
    patient_profile = store.get_profile(body["patient_id"])
    recorded_allergies = []
    if patient_profile:
        raw = patient_profile.get("allergies", [])
        recorded_allergies = models._norm_allergy_list(raw)

    conflicts = models.check_allergy_conflicts(
        recorded_allergies,
        body.get("medications", []),
    )

    if conflicts:
        override = body.get("override_allergy_check") is True
        if not override:
            # Return 409 Conflict — this is a clinical conflict, not a
            # malformed request (400).  The doctor can override via the UI.
            return jsonify({
                "error":     "allergy_conflict",
                "conflicts": conflicts,
            }), 409

        # Override was explicitly acknowledged — save and audit.
        conflict_summary = "; ".join(
            f"{c['medication']} vs {c['allergy']} allergy ({c['severity']})"
            for c in conflicts
        )
        _audit(
            "prescription_allergy_override",
            actor=jwt_p.get("sub", ""),
            target=body["patient_id"],
            detail=conflict_summary,
        )
    # ── End safety check ──────────────────────────────────────────────────────

    # ── Optional condition_id validation ──────────────────────────────────────
    condition_id = body.get("condition_id") or None
    if condition_id:
        cond = store.get_condition(condition_id)
        if not cond or cond["patient_id"] != body["patient_id"]:
            return jsonify({"error": "condition_not_found_for_patient"}), 400

    # ── Optional encounter_id validation ──────────────────────────────────────
    encounter_id = body.get("encounter_id") or None
    if encounter_id:
        enc = store.get_encounter(encounter_id)
        if not enc or enc["patient_id"] != body["patient_id"]:
            return jsonify({"error": "encounter_patient_mismatch"}), 400

    rx = models.new_prescription(body)
    rx["encounter_id"] = encounter_id
    rx["condition_id"] = condition_id
    store.add_prescription(rx)
    _audit("prescription_created", actor=jwt_p.get("sub", ""),
           target=body["patient_id"], detail=f"id={rx['id']}")
    return jsonify(rx), 201


@emr_bp.route("/prescriptions/patient/<patient_id>", methods=["GET"])
@_require_jwt_deco()
def list_patient_prescriptions(patient_id):
    p = request.jwt_payload
    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    # Patient can only view own prescriptions
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403
    rxs = store.prescriptions_for_patient(patient_id)
    rxs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return jsonify(rxs), 200


@emr_bp.route("/prescriptions/<prescription_id>", methods=["GET"])
@_require_jwt_deco()
def get_prescription(prescription_id):
    p  = request.jwt_payload
    rx = store.get_prescription(prescription_id)
    if not rx:
        return jsonify({"error": "prescription_not_found"}), 404
    # Patient can only fetch own prescriptions
    patient_code = p.get("profile_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != rx["patient_id"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(rx), 200


# ═══════════════════════════════════════════════════════════════════════════════
#   LAB REPORT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@emr_bp.route("/lab-reports", methods=["POST"])
@_require_jwt_deco(roles=["doctor", "admin"])
@_rate_limited(max_calls=20, window=60)
def create_lab_report():
    body  = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    # Use doctor_code claim (not uid which is now UUID)
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
    body["doctor_email"] = jwt_p.get("sub", "")
    if not body.get("doctor_name"):
        body["doctor_name"] = ""

    errors = models.validate_lab_report(body)
    if errors:
        return jsonify({"error": "validation_failed", "details": errors}), 400

    # ── Optional encounter_id validation ──────────────────────────────────────
    encounter_id = body.get("encounter_id") or None
    if encounter_id:
        enc = store.get_encounter(encounter_id)
        if not enc or enc["patient_id"] != body["patient_id"]:
            return jsonify({"error": "encounter_patient_mismatch"}), 400

    condition_id = body.get("condition_id") or None
    if condition_id:
        cond = store.get_condition(condition_id)
        if not cond or cond["patient_id"] != body["patient_id"]:
            return jsonify({"error": "condition_not_found_for_patient"}), 400

    report = models.new_lab_report(body)
    report["encounter_id"] = encounter_id
    report["condition_id"] = condition_id
    store.add_lab_report(report)
    _audit("lab_report_created", actor=jwt_p.get("sub", ""),
           target=body["patient_id"], detail=f"id={report['id']}")
    return jsonify(report), 201


@emr_bp.route("/lab-reports/patient/<patient_id>", methods=["GET"])
@_require_jwt_deco()
def list_patient_lab_reports(patient_id):
    p = request.jwt_payload
    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    # Patient can only view own lab reports
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403
    reports = store.lab_reports_for_patient(patient_id)
    reports.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return jsonify(reports), 200


@emr_bp.route("/lab-reports/<report_id>", methods=["GET"])
@_require_jwt_deco()
def get_lab_report(report_id):
    p      = request.jwt_payload
    report = store.get_lab_report(report_id)
    if not report:
        return jsonify({"error": "lab_report_not_found"}), 404
    patient_code = p.get("profile_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != report["patient_id"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(report), 200


# ═══════════════════════════════════════════════════════════════════════════════
#   ADMIN ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@emr_bp.route("/admin/users", methods=["GET"])
@_require_jwt_deco(roles=["admin"])
def admin_list_users():
    """List all registered users (admin only)."""
    fn = _get_helper("load_users")
    if not fn:
        return jsonify({"error": "not configured"}), 500
    users = fn()
    safe = []
    for email, u in users.items():
        safe.append({
            "id":    u.get("id"),
            "name":  u.get("name"),
            "email": email,
            "role":  u.get("role"),
            "created_at": u.get("created_at"),
            "last_login": u.get("last_login"),
            "locked":     u.get("locked", False),
        })
    return jsonify(safe), 200


@emr_bp.route("/admin/users/<user_id>/role", methods=["PUT"])
@_require_jwt_deco(roles=["admin"])
@_rate_limited(max_calls=5, window=60)
def admin_change_role(user_id):
    """Change a user's role (admin only)."""
    body = request.get_json(force=True) or {}
    new_role = body.get("role", "")
    if new_role not in ("patient", "doctor", "admin"):
        return jsonify({"error": "invalid role"}), 400

    fn_load = _get_helper("load_users")
    fn_save = _get_helper("save_users")
    if not fn_load or not fn_save:
        return jsonify({"error": "not configured"}), 500

    users = fn_load()
    target = None
    for email, u in users.items():
        if u.get("id") == user_id:
            target = u
            target_email = email
            break
    if not target:
        return jsonify({"error": "user_not_found"}), 404

    target["role"] = new_role
    fn_save(users)
    jwt_p = request.jwt_payload
    _audit("admin_role_change", actor=jwt_p.get("sub", ""),
           target=target_email, detail=f"new_role={new_role}")
    return jsonify({"message": "role_updated", "user_id": user_id, "role": new_role}), 200


@emr_bp.route("/admin/stats", methods=["GET"])
@_require_jwt_deco(roles=["admin"])
def admin_stats():
    """Return high-level system statistics."""
    fn = _get_helper("load_users")
    users = fn() if fn else {}

    profiles      = store.list_profiles()
    appointments  = store._read("appointments")
    prescriptions = store._read("prescriptions")
    lab_reports   = store._read("lab_reports")

    role_counts = {}
    for u in users.values():
        r = u.get("role", "unknown")
        role_counts[r] = role_counts.get(r, 0) + 1

    return jsonify({
        "total_users":        len(users),
        "users_by_role":      role_counts,
        "emr_profiles":       len(profiles),
        "total_appointments": len(appointments),
        "total_prescriptions":len(prescriptions),
        "total_lab_reports":  len(lab_reports),
    }), 200


# ═══════════════════════════════════════════════════════════════════════════════
#   CONDITIONS (PROBLEM LIST) ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@emr_bp.route("/conditions", methods=["POST"])
@_require_jwt_deco(roles=["doctor", "admin"])
@_rate_limited(max_calls=20, window=60)
def create_condition():
    body  = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    # Auto-fill recorded_by from JWT, matching how create_prescription fills doctor_id
    if not body.get("recorded_by"):
        body["recorded_by"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
    if not body.get("patient_id"):
        return jsonify({"error": "patient_id is required"}), 400

    errors = models.validate_condition(body)
    if errors:
        return jsonify({"error": "validation_failed", "details": errors}), 400

    # If an encounter_id is given, verify it belongs to the same patient
    encounter_id = body.get("encounter_id") or None
    if encounter_id:
        enc = store.get_encounter(encounter_id)
        if not enc or enc["patient_id"] != body["patient_id"]:
            return jsonify({"error": "encounter_patient_mismatch"}), 400

    cond = models.new_condition(body)
    store.add_condition(cond)
    _audit("condition_created", actor=jwt_p.get("sub", ""),
           target=body["patient_id"], detail=f"id={cond['id']}")
    return jsonify(cond), 201


@emr_bp.route("/conditions/patient/<patient_id>", methods=["GET"])
@_require_jwt_deco()
def list_patient_conditions(patient_id):
    p = request.jwt_payload
    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403
    status_filter = request.args.get("status") or None
    conds = store.conditions_for_patient(patient_id, status=status_filter)
    return jsonify(conds), 200


@emr_bp.route("/conditions/<condition_id>", methods=["PUT"])
@_require_jwt_deco(roles=["doctor", "admin"])
def update_condition(condition_id):
    body  = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    existing = store.get_condition(condition_id)
    if not existing:
        return jsonify({"error": "condition_not_found"}), 404

    # Only the recording doctor or admin can update
    if jwt_p.get("role") == "doctor":
        recorder = existing["recorded_by"]
        doctor_id = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
        if recorder != doctor_id:
            return jsonify({"error": "forbidden"}), 403

    allowed = {"status", "resolved_date", "notes"}
    updates = {k: v for k, v in body.items() if k in allowed}

    if "status" in updates:
        s = updates["status"].lower()
        if s not in models.CONDITION_STATUSES:
            return jsonify({"error": f"invalid status: {s}"}), 400
        updates["status"] = s
        # Auto-set resolved_date when resolving
        if s == "resolved" and not updates.get("resolved_date") and not existing.get("resolved_date"):
            from datetime import date
            updates["resolved_date"] = date.today().isoformat()

    updates["updated_at"] = models._now_iso()
    result = store.update_condition(condition_id, updates)
    _audit("condition_updated", actor=jwt_p.get("sub", ""),
           target=existing["patient_id"], detail=f"id={condition_id}")
    return jsonify(result), 200


# ═══════════════════════════════════════════════════════════════════════════════
#   ENCOUNTER ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@emr_bp.route("/encounters", methods=["POST"])
@_require_jwt_deco(roles=["doctor", "admin"])
@_rate_limited(max_calls=20, window=60)
def create_encounter():
    body  = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    # Auto-fill doctor_id from JWT
    if not body.get("doctor_id"):
        body["doctor_id"] = jwt_p.get("doctor_code") or jwt_p.get("uid", "")

    errors = models.validate_encounter(body)
    if errors:
        return jsonify({"error": "validation_failed", "details": errors}), 400

    # If appointment_id given, verify it exists in the correct table
    appt_id  = body.get("appointment_id") or None
    appt_src = (body.get("appointment_source") or "").lower()
    if appt_id:
        if appt_src == "legacy":
            existing_appt = store.get_appointment(appt_id)  # won't find legacy rows
            # For legacy table, fall back to a direct lookup
            from db import db_cursor
            with db_cursor(commit=False) as cur:
                cur.execute("SELECT id FROM appointments WHERE id = %s", (appt_id,))
                if not cur.fetchone():
                    return jsonify({"error": "appointment_not_found"}), 400
        else:
            # Default: check emr_appointments
            if not store.get_appointment(appt_id):
                return jsonify({"error": "appointment_not_found"}), 400

    enc = models.new_encounter(body)
    store.add_encounter(enc)
    _audit("encounter_created", actor=jwt_p.get("sub", ""),
           target=body["patient_id"], detail=f"id={enc['id']}")
    return jsonify(enc), 201


@emr_bp.route("/encounters/patient/<patient_id>", methods=["GET"])
@_require_jwt_deco()
def list_patient_encounters(patient_id):
    p = request.jwt_payload
    patient_id = _resolve_pid(patient_id)  # accept profile_code OR UUID
    if p.get("role") == "patient" and p.get("uid") != patient_id:
        return jsonify({"error": "forbidden"}), 403
    encs = store.encounters_for_patient(patient_id)
    return jsonify(encs), 200


@emr_bp.route("/encounters/doctor/<doctor_id>", methods=["GET"])
@_require_jwt_deco(roles=["doctor", "admin"])
def list_doctor_encounters(doctor_id):
    p = request.jwt_payload
    if p.get("role") == "doctor" and (p.get("doctor_code") or p.get("uid", "")) != doctor_id:
        return jsonify({"error": "forbidden"}), 403
    encs = store.encounters_for_doctor(doctor_id)
    return jsonify(encs), 200


@emr_bp.route("/encounters/<encounter_id>", methods=["GET"])
@_require_jwt_deco()
def get_encounter(encounter_id):
    p   = request.jwt_payload
    enc = store.get_encounter(encounter_id)
    if not enc:
        return jsonify({"error": "encounter_not_found"}), 404
    patient_code = p.get("profile_code") or p.get("uid", "")
    doctor_id    = p.get("doctor_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != enc["patient_id"]:
        return jsonify({"error": "forbidden"}), 403
    if p.get("role") == "doctor" and doctor_id != enc["doctor_id"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(enc), 200


@emr_bp.route("/encounters/<encounter_id>/bundle", methods=["GET"])
@_require_jwt_deco()
def get_encounter_bundle(encounter_id):
    p   = request.jwt_payload
    enc = store.get_encounter(encounter_id)
    if not enc:
        return jsonify({"error": "encounter_not_found"}), 404
    patient_code = p.get("profile_code") or p.get("uid", "")
    doctor_id    = p.get("doctor_code") or p.get("uid", "")
    if p.get("role") == "patient" and patient_code != enc["patient_id"]:
        return jsonify({"error": "forbidden"}), 403
    if p.get("role") == "doctor" and doctor_id != enc["doctor_id"]:
        return jsonify({"error": "forbidden"}), 403
    bundle = store.get_encounter_bundle(encounter_id)
    return jsonify(bundle), 200


@emr_bp.route("/encounters/<encounter_id>", methods=["PUT"])
@_require_jwt_deco(roles=["doctor", "admin"])
def update_encounter(encounter_id):
    body  = request.get_json(force=True) or {}
    jwt_p = request.jwt_payload

    existing = store.get_encounter(encounter_id)
    if not existing:
        return jsonify({"error": "encounter_not_found"}), 404

    # Only the encounter's doctor or admin can update
    if jwt_p.get("role") == "doctor":
        doctor_id = jwt_p.get("doctor_code") or jwt_p.get("uid", "")
        if existing["doctor_id"] != doctor_id:
            return jsonify({"error": "forbidden"}), 403

    allowed = {"status", "summary", "completed_at"}
    updates = {k: v for k, v in body.items() if k in allowed}

    if "status" in updates:
        s = updates["status"].lower()
        if s not in models.ENCOUNTER_STATUSES:
            return jsonify({"error": f"invalid status: {s}"}), 400
        updates["status"] = s
        # Auto-set completed_at when completing without explicit value
        if s == "completed" and not updates.get("completed_at") and not existing.get("completed_at"):
            updates["completed_at"] = models._now_iso()

    updates["updated_at"] = models._now_iso()
    result = store.update_encounter(encounter_id, updates)
    _audit("encounter_updated", actor=jwt_p.get("sub", ""),
           target=existing["patient_id"], detail=f"id={encounter_id}")
    return jsonify(result), 200
