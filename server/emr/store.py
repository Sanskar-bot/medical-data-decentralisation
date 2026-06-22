"""
emr/store.py — JSON-file-backed storage for EMR entities.

Follows the same atomic-write pattern used elsewhere in server.py
(write to .tmp, flush, fsync, os.replace).
"""

import json
import os
import threading

# Base directory — same as SERVER_BASE_DIR in server.py
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.basename(_BASE) != "server":
    _BASE = os.path.join(_BASE, "server")

EMR_DIR = os.path.join(_BASE, "emr_data")
os.makedirs(EMR_DIR, exist_ok=True)

_LOCKS = {
    "profiles":      threading.Lock(),
    "appointments":  threading.Lock(),
    "prescriptions": threading.Lock(),
    "lab_reports":   threading.Lock(),
}


def _path(name: str) -> str:
    return os.path.join(EMR_DIR, f"emr_{name}.json")


def _read(name: str) -> list | dict:
    path = _path(name)
    if not os.path.exists(path):
        return [] if name != "profiles" else {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return [] if name != "profiles" else {}


def _write(name: str, data):
    path = _path(name)
    tmp  = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ── Patient Profiles (dict keyed by patient_id) ──────────────────────────────

def get_profile(patient_id: str) -> dict | None:
    profiles = _read("profiles")
    return profiles.get(patient_id)


def upsert_profile(profile: dict):
    pid = profile["patient_id"]
    with _LOCKS["profiles"]:
        profiles = _read("profiles")
        if pid in profiles:
            # Merge — preserve created_at, update the rest
            existing = profiles[pid]
            existing.update(profile)
            existing["created_at"] = existing.get("created_at", profile.get("created_at", ""))
        else:
            profiles[pid] = profile
        _write("profiles", profiles)


def list_profiles() -> list[dict]:
    profiles = _read("profiles")
    return list(profiles.values())


# ── Generic list-based store (appointments, prescriptions, lab_reports) ───────

def _list_add(name: str, entry: dict):
    with _LOCKS[name]:
        arr = _read(name)
        arr.append(entry)
        _write(name, arr)


def _list_get(name: str, entry_id: str) -> dict | None:
    arr = _read(name)
    return next((x for x in arr if x.get("id") == entry_id), None)


def _list_update(name: str, entry_id: str, updates: dict) -> dict | None:
    with _LOCKS[name]:
        arr = _read(name)
        entry = next((x for x in arr if x.get("id") == entry_id), None)
        if not entry:
            return None
        entry.update(updates)
        _write(name, arr)
        return entry


def _list_delete(name: str, entry_id: str) -> bool:
    with _LOCKS[name]:
        arr = _read(name)
        new_arr = [x for x in arr if x.get("id") != entry_id]
        if len(new_arr) == len(arr):
            return False
        _write(name, new_arr)
        return True


def _list_filter(name: str, key: str, value: str) -> list[dict]:
    arr = _read(name)
    return [x for x in arr if x.get(key) == value]


# ── Appointments ──────────────────────────────────────────────────────────────

def add_appointment(appt: dict):          _list_add("appointments", appt)
def get_appointment(appt_id: str):        return _list_get("appointments", appt_id)
def update_appointment(appt_id, updates): return _list_update("appointments", appt_id, updates)
def delete_appointment(appt_id: str):     return _list_delete("appointments", appt_id)
def appointments_for_patient(pid: str):   return _list_filter("appointments", "patient_id", pid)
def appointments_for_doctor(did: str):    return _list_filter("appointments", "doctor_id", did)


# ── Prescriptions ─────────────────────────────────────────────────────────────

def add_prescription(rx: dict):           _list_add("prescriptions", rx)
def get_prescription(rx_id: str):         return _list_get("prescriptions", rx_id)
def prescriptions_for_patient(pid: str):  return _list_filter("prescriptions", "patient_id", pid)
def prescriptions_for_doctor(did: str):   return _list_filter("prescriptions", "doctor_id", did)


# ── Lab Reports ───────────────────────────────────────────────────────────────

def add_lab_report(report: dict):         _list_add("lab_reports", report)
def get_lab_report(report_id: str):       return _list_get("lab_reports", report_id)
def lab_reports_for_patient(pid: str):    return _list_filter("lab_reports", "patient_id", pid)
