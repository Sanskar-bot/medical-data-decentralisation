#!/usr/bin/env python3
"""
seed_demo_users.py
==================
Registers 4 demo patients and 3 demo doctors via the running MedVault portals.

Usage:
    python seed_demo_users.py

Requires the landing (port 5003), patient portal (5001/5002), and backend (5000)
to be running BEFORE executing this script.

After running, login credentials are printed to the console.
"""

import requests
import json
import sys

LANDING = "http://127.0.0.1:5003"
session = requests.Session()   # shared cookie jar (not used here — stateless registration)

PATIENTS = [
    {
        "name":     "Ananya Sharma",
        "email":    "ananya.sharma@demo.medvault",
        "username": "ananya_sharma",
        "age":      "28",
        "password": "AnanyaDemo@1",
        "notes":    "Type 2 Diabetes (since 2021), Seasonal Allergies (Pollen). "
                    "Current medications: Metformin 500 mg twice daily, Cetirizine 10 mg (PRN). "
                    "Family history: Father — Hypertension; Mother — T2DM. "
                    "Last HbA1c: 6.8 % (Jan 2026). No known drug allergies. "
                    "Vaccinations: COVID-19 (3 doses), Flu (Oct 2025).",
    },
    {
        "name":     "Rohan Mehta",
        "email":    "rohan.mehta@demo.medvault",
        "username": "rohan_mehta",
        "age":      "42",
        "password": "RohanDemo@2",
        "notes":    "Hypertension (Stage 1, diagnosed 2019), Hypercholesterolaemia. "
                    "Medications: Amlodipine 5 mg OD, Atorvastatin 20 mg OD. "
                    "Smoker (15 pack-years, quit 2022). BMI 27.4. "
                    "Last BP: 132/84 mmHg (Mar 2026). Total Cholesterol 185 mg/dL. "
                    "Allergic to Aspirin (anaphylaxis). ECG: Normal sinus rhythm.",
    },
    {
        "name":     "Priya Nair",
        "email":    "priya.nair@demo.medvault",
        "username": "priya_nair",
        "age":      "34",
        "password": "PriyaDemo@3",
        "notes":    "Hypothyroidism (Hashimoto's Thyroiditis). "
                    "Medications: Levothyroxine 75 mcg OD (morning, fasting). "
                    "TSH last checked: 2.1 mIU/L (Feb 2026) — within normal range. "
                    "Anxiety disorder (mild), on Escitalopram 10 mg. "
                    "Menstrual irregularities — under gynaecological follow-up. "
                    "No food or drug allergies known.",
    },
    {
        "name":     "Arjun Kapoor",
        "email":    "arjun.kapoor@demo.medvault",
        "username": "arjun_kapoor",
        "age":      "55",
        "password": "ArjunDemo@4",
        "notes":    "Coronary Artery Disease (post-CABG 2023), Type 2 Diabetes, CKD Stage 2. "
                    "Medications: Aspirin 75 mg OD, Bisoprolol 5 mg OD, Ramipril 5 mg OD, "
                    "Insulin Glargine 20 units at bedtime, Furosemide 40 mg OD. "
                    "eGFR: 68 mL/min (Apr 2026). HbA1c 7.2%. BP 128/78. "
                    "Allergic to Penicillin (rash). Pacemaker: none. "
                    "Follow-up cardiology appointment scheduled May 2026.",
    },
]

DOCTORS = [
    {
        "name":           "Dr Priya Rajan",
        "email":          "dr.priya.rajan@demo.medvault",
        "username":       "dr_priya_rajan",
        "specialization": "Cardiology",
        "hospital":       "Apollo Hospitals, Chennai",
        "password":       "DocPriya@11",
    },
    {
        "name":           "Dr Suresh Kumar",
        "email":          "dr.suresh.kumar@demo.medvault",
        "username":       "dr_suresh_kumar",
        "specialization": "General Medicine & Diabetology",
        "hospital":       "Fortis Healthcare, Bangalore",
        "password":       "DocSuresh@22",
    },
    {
        "name":           "Dr Meera Iyer",
        "email":          "dr.meera.iyer@demo.medvault",
        "username":       "dr_meera_iyer",
        "specialization": "Endocrinology",
        "hospital":       "AIIMS Delhi",
        "password":       "DocMeera@33",
    },
]


def register(role, payload):
    url = f"{LANDING}/register/{role}"
    try:
        r = requests.post(url, json=payload, timeout=30)
        data = r.json()
        if r.ok:
            return True, data
        else:
            return False, data.get("error", str(data))
    except Exception as e:
        return False, str(e)


def print_separator():
    print("\n" + "─" * 60)


def main():
    results = {"patients": [], "doctors": []}

    print("\n" + "═" * 60)
    print("  MedVault Demo Seed Script")
    print("  Registering patients and doctors against", LANDING)
    print("═" * 60)

    # ── Patients ──────────────────────────────────────────────────
    print("\n📋 REGISTERING PATIENTS\n")
    for p in PATIENTS:
        ok, data = register("patient", p)
        status = "✅ OK" if ok else "❌ FAILED"
        print(f"  {status}  {p['name']} (@{p['username']})")
        if not ok:
            print(f"         → Error: {data}")
        results["patients"].append({**p, "success": ok, "response": data})

    # ── Doctors ───────────────────────────────────────────────────
    print("\n🩺 REGISTERING DOCTORS\n")
    for d in DOCTORS:
        ok, data = register("doctor", d)
        status = "✅ OK" if ok else "❌ FAILED"
        print(f"  {status}  {d['name']} (@{d['username']})")
        if not ok:
            print(f"         → Error: {data}")
        results["doctors"].append({**d, "success": ok, "response": data})

    # ── Summary table ─────────────────────────────────────────────
    print_separator()
    print("\n📌 DEMO CREDENTIALS\n")

    print("PATIENTS:")
    print(f"  {'Name':<22} {'Username':<20} {'Email':<38} Password")
    print(f"  {'─'*22} {'─'*20} {'─'*38} {'─'*14}")
    for p in results["patients"]:
        ok = "✅" if p["success"] else "❌"
        print(f"  {ok} {p['name']:<20} @{p['username']:<19} {p['email']:<38} {p['password']}")

    print("\nDOCTORS:")
    print(f"  {'Name':<22} {'Username':<22} {'Email':<38} Password")
    print(f"  {'─'*22} {'─'*22} {'─'*38} {'─'*14}")
    for d in results["doctors"]:
        ok = "✅" if d["success"] else "❌"
        print(f"  {ok} {d['name']:<20} @{d['username']:<21} {d['email']:<38} {d['password']}")

    print_separator()
    total_ok = sum(1 for u in results["patients"] + results["doctors"] if u["success"])
    total = len(results["patients"]) + len(results["doctors"])
    print(f"\n  {total_ok}/{total} accounts registered successfully.")
    if total_ok < total:
        print("  ⚠️  Some registrations failed — the server may not be running, or accounts already exist.")
    print()


if __name__ == "__main__":
    main()
