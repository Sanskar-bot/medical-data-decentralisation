#!/usr/bin/env python3
"""
Doctor Portal  —  http://127.0.0.1:5002
Serves the doctor-facing web UI and handles all crypto on the doctor's machine.
"""
import json, os, sys, uuid
from datetime import datetime, timezone, timedelta
from base64 import b64encode, b64decode
from flask import Flask, request, jsonify, send_file
import requests as http

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)

from common.crypto_utils import (
    generate_rsa_keypair, rsa_serialize_private, rsa_serialize_public,
    derive_kek_from_password, wrap_key_with_kek, unwrap_key_with_kek,
    rsa_load_private, rsa_unwrap_key, rsa_load_public, rsa_wrap_key,
    aesgcm_decrypt, rsa_verify,
)
from common.secure_key_store import SecureKeyStore

BACKEND     = os.environ.get("SERVER_BASE", "http://127.0.0.1:5000")
DOCTORS_DIR = os.path.join(ROOT, "doctor", "Doctors")
os.makedirs(DOCTORS_DIR, exist_ok=True)

def get_html():
    ui = os.path.join(os.path.dirname(__file__), "doctor_ui.html")
    if os.path.exists(ui):
        return open(ui, encoding="utf-8").read()
    return "<h1>doctor_ui.html not found</h1>"


app = Flask(__name__)

@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type,X-API-Key"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return r

def api_key():
    kf = os.path.join(ROOT, "server", "api_key.txt")
    return open(kf).read().strip() if os.path.exists(kf) else ""

def bh(): return {"X-API-Key": api_key(), "Content-Type": "application/json"}

def doc_dir(code):
    # find by doctor_code inside any subfolder
    for d in os.listdir(DOCTORS_DIR):
        folder = os.path.join(DOCTORS_DIR, d)
        meta   = os.path.join(folder, "doctor_data.json")
        if os.path.exists(meta):
            try:
                m = json.load(open(meta))
                if m.get("doctor_code") == code or m.get("doctor_id","").startswith(code):
                    return folder
            except Exception: pass
    return None

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MedVault — Doctor Portal</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f8f0ff;--surface:#fff;--surface2:#f5efff;
  --purple:#4a1a8a;--purple2:#7c3aed;--purple3:#ede9fe;
  --text:#0d0a1a;--muted:#6b5e8a;--border:#ddd6fe;
  --red:#c0392b;--green:#1a7a4a;--amber:#b7780a;
  --shadow:0 2px 16px rgba(74,26,138,.10);
  --radius:16px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.shell{display:flex;min-height:100vh}

.shell{display:flex;min-height:100vh}
.sidebar{
  background:var(--purple);padding:32px 20px;
  display:flex;flex-direction:column;gap:8px;
  width:260px;min-width:260px;flex-shrink:0;
  position:sticky;top:0;height:100vh;
  overflow-y:auto;
  z-index:10;
}
.logo{display:flex;align-items:center;gap:12px;padding:0 8px 28px;border-bottom:1px solid rgba(255,255,255,.2);margin-bottom:12px}
.logo-icon{width:44px;height:44px;border-radius:12px;background:rgba(255,255,255,.2);display:flex;align-items:center;justify-content:center;font-size:22px}
.logo h1{font-family:'Playfair Display',serif;font-size:18px;color:#fff;line-height:1.2}
.logo small{color:rgba(255,255,255,.65);font-size:11px;font-weight:300}
.nav-label{color:rgba(255,255,255,.45);font-size:10px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;padding:16px 8px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;cursor:pointer;color:rgba(255,255,255,.8);font-size:14px;font-weight:400;transition:background .15s,color .15s;border:none;background:transparent;width:100%;text-align:left}
.nav-btn:hover{background:rgba(255,255,255,.12);color:#fff}
.nav-btn.active{background:rgba(255,255,255,.2);color:#fff;font-weight:600}
.nav-icon{font-size:18px;width:24px;text-align:center}
.profile-pill{margin-top:auto;padding:14px;border-radius:12px;background:rgba(255,255,255,.12)}
.profile-pill .name{color:#fff;font-weight:600;font-size:13px}
.profile-pill .code{color:rgba(255,255,255,.55);font-size:11px;font-family:monospace;margin-top:2px}

.main{
  flex:1;
  min-width:0;
  width:calc(100% - 260px);
  padding:36px 40px;
  overflow-x:hidden;
  box-sizing:border-box;
}
.page{display:none}.page.active{display:block}
.page-header{margin-bottom:28px}
.page-header h2{font-family:'Playfair Display',serif;font-size:28px;color:var(--text)}
.page-header p{color:var(--muted);font-size:14px;margin-top:4px}

.card{background:var(--surface);border-radius:var(--radius);padding:28px;box-shadow:var(--shadow);margin-bottom:20px}
.card-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}

.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}
.stat{background:var(--purple3);border-radius:12px;padding:20px;text-align:center}
.stat .num{font-family:'Playfair Display',serif;font-size:36px;color:var(--purple)}
.stat .lbl{font-size:12px;color:var(--muted);margin-top:4px}

.form-grid{display:grid;gap:16px}
.form-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}
label{display:block;font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
input,textarea,select{width:100%;min-width:0;padding:11px 14px;border:1.5px solid var(--border);border-radius:10px;font-size:14px;font-family:'Inter',sans-serif;background:var(--surface);color:var(--text);transition:border .15s,box-shadow .15s;outline:none}
input:focus,textarea:focus{border-color:var(--purple2);box-shadow:0 0 0 3px rgba(124,58,237,.15)}
textarea{resize:vertical;min-height:80px}

.btn{display:inline-flex;align-items:center;gap:8px;padding:11px 22px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;border:none;transition:all .15s;font-family:'Inter',sans-serif}
.btn-primary{background:var(--purple);color:#fff}
.btn-primary:hover{background:var(--purple2);transform:translateY(-1px);box-shadow:0 4px 14px rgba(74,26,138,.3)}
.btn-outline{background:transparent;color:var(--purple);border:1.5px solid var(--purple)}
.btn-outline:hover{background:var(--purple3)}
.btn-success{background:var(--green);color:#fff}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none!important}

.patient-card{background:var(--surface);border-radius:12px;padding:22px 26px;box-shadow:var(--shadow);margin-bottom:14px;border-left:4px solid var(--purple2)}
.patient-card h4{font-size:16px;font-weight:600;margin-bottom:6px}
.patient-card p{font-size:13px;color:var(--muted)}

.record-field{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)}
.record-field:last-child{border-bottom:none}
.record-key{color:var(--muted);font-weight:600;min-width:140px;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.record-val{color:var(--text);font-size:14px}

.alert{padding:12px 16px;border-radius:10px;font-size:13px;margin-bottom:16px;display:flex;gap:10px;align-items:flex-start}
.alert-success{background:#e8f5ee;color:#1a5c35;border:1px solid #a8d5bc}
.alert-error{background:#fdecea;color:#8b1a1a;border:1px solid #f5b7b1}
.alert-info{background:#ede9fe;color:#4a1a8a;border:1px solid #c4b5fd}
.alert-warn{background:#fff8e1;color:#7a5a00;border:1px solid #ffe082}

.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.badge-pending{background:#fff8e1;color:var(--amber)}
.badge-approved{background:#e8f5ee;color:var(--green)}
.badge-denied{background:#fdecea;color:var(--red)}

.tabs{display:flex;gap:4px;background:var(--surface2);border-radius:10px;padding:4px;margin-bottom:24px;border:1px solid var(--border)}
.tab{flex:1;text-align:center;padding:9px;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;color:var(--muted);transition:all .15s;border:none;background:transparent}
.tab.active{background:var(--surface);color:var(--purple);font-weight:600;box-shadow:0 1px 6px rgba(0,0,0,.08)}

.empty{text-align:center;padding:48px 20px;color:var(--muted)}
.empty-icon{font-size:48px;margin-bottom:12px}
.empty p{font-size:14px}

.spin{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.code-display{font-family:monospace;font-size:22px;font-weight:700;background:var(--purple3);color:var(--purple);padding:16px 24px;border-radius:12px;text-align:center;letter-spacing:.12em;border:2px dashed var(--purple2);margin:12px 0}

.divider{height:1px;background:var(--border);margin:24px 0}

.record-card{background:var(--surface2);border-radius:14px;border:1.5px solid var(--border);overflow:hidden}
.record-header{background:var(--purple);color:#fff;padding:16px 22px;font-family:'Playfair Display',serif;font-size:17px;display:flex;justify-content:space-between;align-items:center}
.record-body{padding:20px 22px}

.access-timer{background:var(--purple3);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px;margin-bottom:20px;font-size:13px;color:var(--purple);border:1px solid var(--border)}

/* ── QR ── */
#qr-canvas-wrap canvas{display:block}
.qr-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}
</style>
</head>
<body>
<div class="shell">

<!-- SIDEBAR -->
<aside class="sidebar">
  <div class="logo">
    <div class="logo-icon">🩺</div>
    <div><h1>MedVault</h1><small>Doctor Portal</small></div>
  </div>

  <span class="nav-label">Menu</span>
  <button class="nav-btn active" onclick="nav('home')" id="nb-home"><span class="nav-icon">🏠</span> Dashboard</button>
  <button class="nav-btn" onclick="nav('register')" id="nb-register"><span class="nav-icon">✨</span> Register</button>
  <button class="nav-btn" onclick="nav('login')" id="nb-login"><span class="nav-icon">🔑</span> Load Profile</button>
  <button class="nav-btn" onclick="nav('request')" id="nb-request"><span class="nav-icon">📨</span> Request Access</button>
  <button class="nav-btn" onclick="nav('records')" id="nb-records"><span class="nav-icon">📋</span> Patient Records</button>
  <button class="nav-btn" onclick="nav('notes')" id="nb-notes"><span class="nav-icon">📝</span> Add Note</button>
  <button class="nav-btn" onclick="nav('qr')" id="nb-qr"><span class="nav-icon">📲</span> My QR Code</button>
  <button class="nav-btn" onclick="nav('about')" id="nb-about"><span class="nav-icon">ℹ️</span> About MedVault</button>

  <div class="profile-pill" id="sidebar-profile" style="display:none">
    <div class="name" id="sp-name">—</div>
    <div class="code" id="sp-code">Doctor Code: —</div>
  </div>
</aside>

<!-- MAIN -->
<main class="main">

  <!-- HOME -->
  <div class="page active" id="page-home">
    <div class="page-header">
      <h2>Doctor Dashboard 🩺</h2>
      <p>Securely access patient records with patient consent.</p>
    </div>
    <div class="stat-grid">
      <div class="stat"><div class="num">🔐</div><div class="lbl">Patient-Controlled Access</div></div>
      <div class="stat"><div class="num">⏱</div><div class="lbl">24-Hour Access Window</div></div>
      <div class="stat"><div class="num">✅</div><div class="lbl">Consent-First System</div></div>
    </div>
    <div class="card" id="home-logged-out">
      <div class="card-title">Get Started</div>
      <p style="color:var(--muted);font-size:14px;margin-bottom:20px">New to MedVault? Create your doctor profile. Already registered? Load your profile to start requesting patient access.</p>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="nav('register')">✨ Register as Doctor</button>
        <button class="btn btn-outline" onclick="nav('login')">🔑 Load My Profile</button>
      </div>
    </div>
    <div class="card" id="home-logged-in" style="display:none">
      <div class="card-title">Your Profile</div>
      <div class="record-field"><div class="record-key">Name</div><div class="record-val" id="hi-name">—</div></div>
      <div class="record-field"><div class="record-key">Doctor Code</div><div class="record-val" id="hi-code">—</div></div>
      <div class="record-field"><div class="record-key">Specialization</div><div class="record-val" id="hi-spec">—</div></div>
      <div class="record-field"><div class="record-key">Hospital</div><div class="record-val" id="hi-hosp">—</div></div>
      <div style="margin-top:20px;display:flex;gap:10px;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="nav('request')">📨 Request Patient Access</button>
        <button class="btn btn-outline" onclick="nav('records')">📋 View Records</button>
        <button class="btn btn-outline" onclick="logout()">↩ Switch Profile</button>
      </div>
    </div>
  </div>

  <!-- REGISTER -->
  <div class="page" id="page-register">
    <div class="page-header">
      <h2>Doctor Registration</h2>
      <p>Your credentials stay on this device. Only your public key goes to the server.</p>
    </div>
    <div id="reg-result"></div>
    <div class="card" id="reg-form-card">
      <div class="card-title">Professional Details</div>
      <div class="form-grid">
        <div class="form-row">
          <div><label>Full Name *</label><input id="r-name" placeholder="Dr. Priya Mehta" /></div>
          <div><label>Specialization</label><input id="r-spec" placeholder="Cardiologist" /></div>
        </div>
        <div class="form-row">
          <div><label>Hospital / Clinic</label><input id="r-hosp" placeholder="Apollo Hospital, Delhi" /></div>
          <div><label>Email</label><input id="r-email" type="email" placeholder="priya@hospital.com" /></div>
        </div>
        <div class="divider"></div>
        <div class="card-title">Protect Your Private Key</div>
        <div class="form-row">
          <div><label>Password *</label><input id="r-pw" type="password" placeholder="Strong password" /></div>
          <div><label>Confirm Password *</label><input id="r-pw2" type="password" placeholder="Repeat password" /></div>
        </div>
        <div><button class="btn btn-primary" id="reg-btn" onclick="register()">✨ Create Doctor Profile</button></div>
      </div>
    </div>
  </div>

  <!-- LOGIN -->
  <div class="page" id="page-login">
    <div class="page-header"><h2>Load Your Profile</h2><p>Enter your doctor code and password.</p></div>
    <div id="login-result"></div>
    <div class="card">
      <div class="form-grid">
        <div><label>Doctor Code</label><input id="l-code" placeholder="e.g. 7e7878c3" /></div>
        <div><label>Password</label><input id="l-pw" type="password" placeholder="Your local password" /></div>
        <button class="btn btn-primary" onclick="loadProfile()">🔑 Load Profile</button>
      </div>
    </div>
  </div>

  <!-- REQUEST ACCESS -->
  <div class="page" id="page-request">
    <div class="page-header"><h2>Request Patient Access</h2><p>The patient will be notified and can approve or deny.</p></div>
    <div id="req-result"></div>
    <div class="card">
      <div class="card-title">Patient Details</div>
      <div class="form-grid">
        <div><label>Patient Profile Code *</label><input id="req-pcode" placeholder="e.g. nurpsuyJ" /></div>
        <div><label>Your Password (to unlock your key)</label><input id="req-pw" type="password" placeholder="Your local password" /></div>
        <div><button class="btn btn-primary" id="req-btn" onclick="requestAccess()">📨 Send Access Request</button></div>
      </div>
    </div>
    <div id="req-status" style="display:none" class="card">
      <div class="card-title">Request Status</div>
      <div id="req-status-body"></div>
    </div>
  </div>

  <!-- PATIENT RECORDS -->
  <div class="page" id="page-records">
    <div class="page-header"><h2>Patient Records</h2><p>View approved patient records. Access expires after 24 hours.</p></div>
    <div id="records-result"></div>
    <div class="card">
      <div class="form-grid">
        <div class="form-row">
          <div><label>Patient Profile Code *</label><input id="view-pcode" placeholder="e.g. nurpsuyJ" /></div>
          <div><label>Your Password</label><input id="view-pw" type="password" placeholder="Your local password" /></div>
        </div>
        <div><button class="btn btn-primary" id="view-btn" onclick="viewRecord()">📋 Fetch & Decrypt Record</button></div>
      </div>
    </div>
    <div id="record-display" style="display:none"></div>
  </div>



  <!-- ADD NOTE PAGE -->
  <div class="page" id="page-notes">
    <div class="page-header">
      <h2>Add Clinical Note 📝</h2>
      <p>Attach notes to a patient profile. Only works while you have active approved access.</p>
    </div>
    <div id="note-alert"></div>
    <div class="alert alert-info" style="margin-bottom:20px">🔒 Every note is stored with your name, doctor code, specialisation, hospital and an exact timestamp. The patient can see the full audit trail.</div>
    <div class="card">
      <div class="card-title">Patient & Visit</div>
      <div class="form-grid">
        <div class="form-row">
          <div><label>Patient Profile Code *</label><input id="note-pcode" placeholder="e.g. pYn0m2GJ" oninput="onNotePatientChange()" /></div>
          <div><label>Your Password *</label><input id="note-pw" type="password" placeholder="Verify your identity" /></div>
        </div>
        <div class="form-row">
          <div>
            <label>Note Type</label>
            <select id="note-type">
              <option value="General">General Observation</option>
              <option value="Diagnosis">Diagnosis</option>
              <option value="Prescription">Prescription / Medication</option>
              <option value="FollowUp">Follow-Up Required</option>
              <option value="LabResult">Lab / Test Result</option>
              <option value="Allergy">Allergy / Adverse Reaction</option>
              <option value="Surgical">Surgical Note</option>
              <option value="Emergency">Emergency Note</option>
            </select>
          </div>
          <div><label>Visit Date</label><input id="note-date" type="date" /></div>
        </div>
        <div>
          <label>Clinical Note *</label>
          <textarea id="note-text" style="min-height:130px" placeholder="Enter clinical observations, diagnosis details, medication instructions, follow-up plan…"></textarea>
        </div>
        <div>
          <label>Attach Photo (optional)</label>
          <input type="file" id="note-image" accept="image/*" onchange="previewNoteImage()" style="display:block;padding:8px 0;font-size:13px">
          <div id="note-img-preview" style="margin-top:10px;display:none">
            <img id="note-img-thumb" src="" style="max-width:220px;max-height:160px;border-radius:10px;border:2px solid var(--border);object-fit:cover">
            <button type="button" onclick="clearNoteImage()" style="display:block;margin-top:6px;background:none;border:1px solid var(--red);color:var(--red);cursor:pointer;font-size:12px;padding:3px 10px;border-radius:6px">✕ Remove photo</button>
          </div>
        </div>
        <div>
          <button class="btn btn-primary" id="note-submit-btn" onclick="submitNote()">📝 Save Note to Patient Profile</button>
        </div>
      </div>
    </div>

    <!-- Notes already added for this patient by this doctor -->
    <div id="my-notes-wrap" style="display:none">
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          <span id="my-notes-title">My notes for this patient</span>
          <button class="btn btn-outline" style="font-size:12px;padding:6px 14px" onclick="loadMyNotes()">↻ Refresh</button>
        </div>
        <div id="my-notes-list"></div>
      </div>
    </div>
  </div>

  <!-- QR PAGE -->
  <div class="page" id="page-qr">
    <div class="page-header">
      <h2>Your Doctor QR Code 📲</h2>
      <p>Show this QR to your patient. They scan it and securely transfer their medical record to you — like a UPI payment but for health data.</p>
    </div>
    <div id="qr-not-logged" class="alert alert-info">ℹ️ Load your doctor profile first to generate your QR code.</div>
    <div id="qr-logged" style="display:none">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;flex-wrap:wrap" class="qr-grid">
        <div class="card" style="text-align:center">
          <div class="card-title">Your Doctor QR</div>
          <div id="qr-canvas-wrap" style="display:inline-block;padding:16px;background:#fff;border-radius:12px;border:2px solid var(--border);margin:8px 0"></div>
          <p style="color:var(--muted);font-size:12px;margin-top:10px">Patient scans this with their Patient Portal</p>
          <button class="btn btn-outline" style="margin-top:14px" onclick="downloadQR()">⬇ Download QR</button>
        </div>
        <div class="card">
          <div class="card-title">How It Works</div>
          <div style="display:flex;flex-direction:column;gap:14px;margin-top:4px">
            <div style="display:flex;gap:12px;align-items:flex-start">
              <div style="width:28px;height:28px;border-radius:50%;background:var(--purple3);color:var(--purple);font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center;flex-shrink:0">1</div>
              <div><div style="font-weight:600;font-size:14px">Doctor shows QR</div><div style="color:var(--muted);font-size:12px;margin-top:2px">Display this QR on your screen or print it</div></div>
            </div>
            <div style="display:flex;gap:12px;align-items:flex-start">
              <div style="width:28px;height:28px;border-radius:50%;background:var(--purple3);color:var(--purple);font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center;flex-shrink:0">2</div>
              <div><div style="font-weight:600;font-size:14px">Patient scans it</div><div style="color:var(--muted);font-size:12px;margin-top:2px">Patient opens their portal → Scan QR tab → scans your code</div></div>
            </div>
            <div style="display:flex;gap:12px;align-items:flex-start">
              <div style="width:28px;height:28px;border-radius:50%;background:var(--purple3);color:var(--purple);font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center;flex-shrink:0">3</div>
              <div><div style="font-weight:600;font-size:14px">Patient enters password</div><div style="color:var(--muted);font-size:12px;margin-top:2px">Like entering a UPI PIN — unlocks and transfers the record</div></div>
            </div>
            <div style="display:flex;gap:12px;align-items:flex-start">
              <div style="width:28px;height:28px;border-radius:50%;background:var(--purple3);color:var(--purple);font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center;flex-shrink:0">4</div>
              <div><div style="font-weight:600;font-size:14px">Doctor gets access</div><div style="color:var(--muted);font-size:12px;margin-top:2px">Record appears instantly in Patient Records with 24h access</div></div>
            </div>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:0">
        <div class="card-title">Your Doctor Code (share manually too)</div>
        <div id="qr-doc-code" style="font-family:monospace;font-size:28px;font-weight:700;background:var(--purple3);color:var(--purple);padding:16px 24px;border-radius:12px;text-align:center;letter-spacing:.15em;border:2px dashed var(--purple2)"></div>
        <p style="color:var(--muted);font-size:12px;margin-top:10px">Patient can also manually type this code in the "Scan QR" section of their portal</p>
      </div>
    </div>
  </div>


  <!-- ABOUT PAGE -->
  <div class="page" id="page-about">
    <div class="page-header">
      <h2>About MedVault ℹ️</h2>
      <p>A consent-first, cryptographically secured medical data platform.</p>
    </div>

    <div class="card" style="background:linear-gradient(135deg,#4a1a8a,#7c3aed);color:#fff;border:none;margin-bottom:20px">
      <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap">
        <div style="font-size:52px">🏥</div>
        <div>
          <div style="font-size:20px;font-weight:800;margin-bottom:6px">MedVault</div>
          <div style="opacity:.85;font-size:14px;max-width:520px">A decentralised health data platform where patients hold the keys to their own records. As a doctor, you access data only after explicit patient consent, for a time-limited 24-hour window.</div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:20px">
      <div class="card-title">🛡 Security Architecture</div>
      <div style="display:flex;flex-direction:column;gap:10px;margin-top:8px">
        <div style="display:flex;gap:12px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:10px">
          <span style="font-size:22px;flex-shrink:0">🔑</span>
          <div><div style="font-weight:700;font-size:14px">RSA-2048 Keypair per Patient</div><div style="font-size:13px;color:var(--muted);margin-top:2px">Each patient generates a keypair locally. You receive a temporary AES key wrapped with your public key — decryptable only by you.</div></div>
        </div>
        <div style="display:flex;gap:12px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:10px">
          <span style="font-size:22px;flex-shrink:0">🔐</span>
          <div><div style="font-weight:700;font-size:14px">AES-256-GCM Record Encryption</div><div style="font-size:13px;color:var(--muted);margin-top:2px">Records are encrypted end-to-end. The server stores only ciphertext and can never read patient data without the patient’s password.</div></div>
        </div>
        <div style="display:flex;gap:12px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:10px">
          <span style="font-size:22px;flex-shrink:0">⏱</span>
          <div><div style="font-weight:700;font-size:14px">24-Hour Time-Limited Access</div><div style="font-size:13px;color:var(--muted);margin-top:2px">Every approved access window has a hard expiry. After 24 hours, access is revoked automatically and you must request fresh consent.</div></div>
        </div>
        <div style="display:flex;gap:12px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:10px">
          <span style="font-size:22px;flex-shrink:0">✍️</span>
          <div><div style="font-weight:700;font-size:14px">Digital Signatures &amp; Integrity</div><div style="font-size:13px;color:var(--muted);margin-top:2px">Patient records are signed with their private key. Any tampering is detectable via signature verification before data is shown.</div></div>
        </div>
        <div style="display:flex;gap:12px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:10px">
          <span style="font-size:22px;flex-shrink:0">📋</span>
          <div><div style="font-weight:700;font-size:14px">Full Audit Trail</div><div style="font-size:13px;color:var(--muted);margin-top:2px">Every action you take — requests, approvals, notes, record fetches — is logged with your doctor code and a UTC timestamp visible to the patient.</div></div>
        </div>
        <div style="display:flex;gap:12px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:10px">
          <span style="font-size:22px;flex-shrink:0">📲</span>
          <div><div style="font-weight:700;font-size:14px">QR Code Identity Verification</div><div style="font-size:13px;color:var(--muted);margin-top:2px">Your QR code encodes your doctor code and name. Patients scan it to link your identity to their portal before approving access — no manual code typing errors.</div></div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">⚙️ Tech Stack</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-top:10px">
        <div style="border:1.5px solid var(--border);border-radius:10px;padding:12px;text-align:center"><div style="font-size:20px">🐍</div><div style="font-size:12px;font-weight:700;margin-top:4px">Python + Flask</div><div style="font-size:11px;color:var(--muted)">Backend API</div></div>
        <div style="border:1.5px solid var(--border);border-radius:10px;padding:12px;text-align:center"><div style="font-size:20px">🔐</div><div style="font-size:12px;font-weight:700;margin-top:4px">cryptography lib</div><div style="font-size:11px;color:var(--muted)">RSA + AES-GCM</div></div>
        <div style="border:1.5px solid var(--border);border-radius:10px;padding:12px;text-align:center"><div style="font-size:20px">🌐</div><div style="font-size:12px;font-weight:700;margin-top:4px">Vanilla JS</div><div style="font-size:11px;color:var(--muted)">Zero dependencies</div></div>
        <div style="border:1.5px solid var(--border);border-radius:10px;padding:12px;text-align:center"><div style="font-size:20px">📲</div><div style="font-size:12px;font-weight:700;margin-top:4px">QRCode.js</div><div style="font-size:11px;color:var(--muted)">Doctor QR identity</div></div>
        <div style="border:1.5px solid var(--border);border-radius:10px;padding:12px;text-align:center"><div style="font-size:20px">🎟</div><div style="font-size:12px;font-weight:700;margin-top:4px">JWT (HS256)</div><div style="font-size:11px;color:var(--muted)">Session tokens</div></div>
        <div style="border:1.5px solid var(--border);border-radius:10px;padding:12px;text-align:center"><div style="font-size:20px">📁</div><div style="font-size:12px;font-weight:700;margin-top:4px">Local JSON</div><div style="font-size:11px;color:var(--muted)">Decentralised store</div></div>
      </div>
      <p style="font-size:12px;color:var(--muted);margin-top:16px;text-align:center">MedVault — Minor Project · © 2026</p>
    </div>
  </div>

</main>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"
  onerror="console.warn('QR lib CDN unavailable')"></script>
<script>
let S = { code:'', name:'', spec:'', hosp:'', logged:false };

function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.getElementById('nb-' + page)?.classList.add('active');
  if (page === 'qr') showQR();
  if (page === 'notes') { initNotesPage(); }
}

function setLoggedIn(code, name, spec, hosp) {
  S = { code, name, spec, hosp, logged:true };
  sessionStorage.setItem('medvault_session', JSON.stringify(S));
  document.getElementById('home-logged-out').style.display = 'none';
  document.getElementById('home-logged-in').style.display = 'block';
  document.getElementById('hi-code').textContent = code;
  document.getElementById('hi-name').textContent = name || '—';
  document.getElementById('hi-spec').textContent = spec || '—';
  document.getElementById('hi-hosp').textContent = hosp || '—';
  document.getElementById('sidebar-profile').style.display = 'block';
  document.getElementById('sp-name').textContent = name || code;
  document.getElementById('sp-code').textContent = 'Code: ' + code;
}

function logout() {
  sessionStorage.removeItem('medvault_session');
  S = { code:'', name:'', spec:'', hosp:'', logged:false };
  document.getElementById('home-logged-out').style.display = 'block';
  document.getElementById('home-logged-in').style.display = 'none';
  document.getElementById('sidebar-profile').style.display = 'none';
  nav('home');
}

async function register() {
  const name = document.getElementById('r-name').value.trim();
  const spec = document.getElementById('r-spec').value.trim();
  const hosp = document.getElementById('r-hosp').value.trim();
  const email= document.getElementById('r-email').value.trim();
  const pw   = document.getElementById('r-pw').value;
  const pw2  = document.getElementById('r-pw2').value;
  if (!name) return alert('Name is required.');
  if (!pw)   return alert('Password is required.');
  if (pw !== pw2) return alert('Passwords do not match.');

  const btn = document.getElementById('reg-btn');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Generating keys...';
  document.getElementById('reg-result').innerHTML = '';

  try {
    const res = await fetch('/api/register', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name, specialization:spec, hospital:hosp, email, password:pw })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Registration failed');

    document.getElementById('reg-result').innerHTML = `
      <div class="alert alert-success">✅ Doctor profile created!</div>
      <div class="card">
        <div class="card-title">Your Doctor Code</div>
        <div class="code-display">${d.doctor_code}</div>
        <p style="color:var(--muted);font-size:13px;margin-top:12px">Save this code — you'll need it to log in.</p>
        <div style="margin-top:16px"><button class="btn btn-primary" onclick="nav('home')">Go to Dashboard →</button></div>
      </div>`;
    document.getElementById('reg-form-card').style.display = 'none';
    setLoggedIn(d.doctor_code, name, spec, hosp);
  } catch(e) {
    document.getElementById('reg-result').innerHTML = `<div class="alert alert-error">❌ ${e.message}</div>`;
  } finally { btn.disabled = false; btn.textContent = '✨ Create Doctor Profile'; }
}

async function loadProfile() {
  const code = document.getElementById('l-code').value.trim();
  const pw   = document.getElementById('l-pw').value;
  if (!code || !pw) return alert('Doctor code and password are required.');
  document.getElementById('login-result').innerHTML = '';
  try {
    const res = await fetch('/api/load_profile', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ doctor_code:code, password:pw })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Failed to load profile');
    setLoggedIn(code, d.name, d.specialization, d.hospital);
    document.getElementById('login-result').innerHTML = `<div class="alert alert-success">✅ Welcome back, ${d.name}!</div>`;
    setTimeout(() => nav('home'), 1200);
  } catch(e) {
    document.getElementById('login-result').innerHTML = `<div class="alert alert-error">❌ ${e.message}</div>`;
  }
}

async function requestAccess() {
  if (!S.logged) return alert('Load your profile first.');
  const pcode = document.getElementById('req-pcode').value.trim();
  const pw    = document.getElementById('req-pw').value;
  if (!pcode) return alert('Patient profile code is required.');
  if (!pw)    return alert('Your password is required.');

  const btn = document.getElementById('req-btn');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Sending request...';
  document.getElementById('req-result').innerHTML = '';

  try {
    const res = await fetch('/api/request_access', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ doctor_code:S.code, patient_code:pcode, password:pw })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Request failed');

    document.getElementById('req-result').innerHTML = `<div class="alert alert-success">✅ Request sent! The patient will be notified.</div>`;
    document.getElementById('req-status').style.display = 'block';
    document.getElementById('req-status-body').innerHTML = `
      <div class="record-field"><div class="record-key">Request ID</div><div class="record-val" style="font-family:monospace;font-size:12px">${d.request_id}</div></div>
      <div class="record-field"><div class="record-key">Patient Code</div><div class="record-val">${pcode}</div></div>
      <div class="record-field"><div class="record-key">Status</div><div class="record-val"><span class="badge badge-pending">⏳ Pending patient approval</span></div></div>
      <p style="color:var(--muted);font-size:13px;margin-top:16px">Once the patient approves, go to <strong>Patient Records</strong> to view the decrypted record.</p>`;
  } catch(e) {
    document.getElementById('req-result').innerHTML = `<div class="alert alert-error">❌ ${e.message}</div>`;
  } finally { btn.disabled = false; btn.textContent = '📨 Send Access Request'; }
}

async function viewRecord() {
  if (!S.logged) return alert('Load your profile first.');
  const pcode = document.getElementById('view-pcode').value.trim();
  const pw    = document.getElementById('view-pw').value;
  if (!pcode || !pw) return alert('Patient code and password are required.');

  const btn = document.getElementById('view-btn');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Fetching & decrypting...';
  document.getElementById('records-result').innerHTML = '';
  document.getElementById('record-display').style.display = 'none';

  try {
    const res = await fetch('/api/fetch_record', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ doctor_code:S.code, patient_code:pcode, password:pw })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Failed to fetch record');

    const rec = d.record;
    const expires = d.expires_at ? new Date(d.expires_at).toLocaleString() : 'Unknown';
    document.getElementById('record-display').style.display = 'block';
    document.getElementById('record-display').innerHTML = `
      <div class="access-timer">⏱ Access expires: <strong>${expires}</strong></div>
      <div class="record-card">
        <div class="record-header">
          <span>🏥 Patient Record</span>
          <span style="font-size:12px;opacity:.8;font-family:Inter,sans-serif">Profile: ${pcode}</span>
        </div>
        <div class="record-body">
          ${Object.entries(rec).filter(([k,v])=>v).map(([k,v])=>`
            <div class="record-field">
              <div class="record-key">${k}</div>
              <div class="record-val">${v}</div>
            </div>`).join('')}
          <div class="record-field">
            <div class="record-key">Signature</div>
            <div class="record-val" style="color:${d.sig_valid?'var(--green)':'var(--red)'}">
              ${d.sig_valid ? '✅ Verified — data has not been tampered' : '⚠️ Signature invalid'}
            </div>
          </div>
        </div>
      </div>`;
  } catch(e) {
    document.getElementById('records-result').innerHTML = `<div class="alert alert-error">❌ ${e.message}</div>`;
  } finally { btn.disabled = false; btn.textContent = '📋 Fetch & Decrypt Record'; }
}

// ═══════════════════════════════════════════════
//  QR CODE
// ═══════════════════════════════════════════════
let _qrGenerated = false;
function showQR() {
  if (!S.logged) {
    document.getElementById('qr-not-logged').style.display = 'block';
    document.getElementById('qr-logged').style.display = 'none';
    return;
  }
  document.getElementById('qr-not-logged').style.display = 'none';
  document.getElementById('qr-logged').style.display = 'block';
  document.getElementById('qr-doc-code').textContent = S.code;
  const wrap = document.getElementById('qr-canvas-wrap');
  wrap.innerHTML = '';  // always clear and regenerate
  const qrData = JSON.stringify({ type:'medvault_doctor', doctor_code:S.code, doctor_name:S.name });
  if (window.QRCode) {
    new QRCode(wrap, { text:qrData, width:220, height:220, colorDark:'#4a1a8a', colorLight:'#ffffff', correctLevel:QRCode.CorrectLevel.H });
    _qrGenerated = true;
  } else {
    // Retry once after 600 ms in case CDN script is still loading
    setTimeout(() => {
      if (window.QRCode && !_qrGenerated) {
        wrap.innerHTML = '';
        new QRCode(wrap, { text:qrData, width:220, height:220, colorDark:'#4a1a8a', colorLight:'#ffffff', correctLevel:QRCode.CorrectLevel.H });
        _qrGenerated = true;
      } else if (!window.QRCode) {
        wrap.innerHTML = `<div style="padding:16px;background:#ede9fe;border-radius:10px;text-align:center"><div style="font-size:11px;color:#4a1a8a;font-family:monospace;word-break:break-all">${qrData}</div><div style="margin-top:8px;font-size:11px;color:#6b5e8a">QR library unavailable — patient can type code manually</div></div>`;
      }
    }, 600);
  }
}
function downloadQR() {
  const canvas = document.querySelector('#qr-canvas-wrap canvas');
  if (!canvas) return alert('QR not generated yet.');
  const a = document.createElement('a');
  a.download = 'doctor_qr_' + S.code + '.png';
  a.href = canvas.toDataURL();
  a.click();
}

// ═══════════════════════════════════════════════
//  DOCTOR NOTES
// ═══════════════════════════════════════════════

const NOTE_TYPE_LABELS = {
  General: 'General Observation', Diagnosis: 'Diagnosis',
  Prescription: 'Prescription / Medication', FollowUp: 'Follow-Up Required',
  LabResult: 'Lab / Test Result', Allergy: 'Allergy / Adverse Reaction',
  Surgical: 'Surgical Note', Emergency: 'Emergency Note',
};

function initNotesPage() {
  // Pre-fill today's date
  const d = document.getElementById('note-date');
  if (d && !d.value) d.value = new Date().toISOString().slice(0, 10);
  document.getElementById('note-alert').innerHTML = '';
  if (!S.logged) {
    document.getElementById('note-alert').innerHTML =
      '<div class="alert alert-warn">⚠️ Load your doctor profile first.</div>';
  }
}

function onNotePatientChange() {
  // hide stale notes when patient code changes
  document.getElementById('my-notes-wrap').style.display = 'none';
}

async function submitNote() {
  if (!S.logged) return alert('Load your profile first.');
  const pcode    = document.getElementById('note-pcode').value.trim();
  const pw       = document.getElementById('note-pw').value;
  const noteType = document.getElementById('note-type').value;
  const noteText = document.getElementById('note-text').value.trim();
  const noteDate = document.getElementById('note-date').value;
  if (!pcode)    return alert('Patient profile code is required.');
  if (!pw)       return alert('Password is required to verify your identity.');
  if (!noteText) return alert('Note text cannot be empty.');

  // Read image if selected
  let image_b64 = '', image_type = '';
  const imgFile = document.getElementById('note-image').files[0];
  if (imgFile) {
    image_type = imgFile.type || 'image/jpeg';
    image_b64  = await new Promise((res) => {
      const reader = new FileReader();
      reader.onload = (e) => res(e.target.result.split(',')[1]);  // strip data URL prefix
      reader.readAsDataURL(imgFile);
    });
  }

  const btn = document.getElementById('note-submit-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Saving note…';
  document.getElementById('note-alert').innerHTML = '';

  try {
    const res = await fetch('/api/add_note', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        patient_code: pcode,
        doctor_code:  S.code,
        password:     pw,
        note_type:    noteType,
        note_text:    noteText,
        visit_date:   noteDate,
        image_b64,
        image_type,
      })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || d.detail || 'Failed');

    document.getElementById('note-alert').innerHTML = `
      <div class="alert alert-success">
        ✅ Note saved! ID: <span style="font-family:monospace;font-size:12px">${d.note_id}</span><br>
        <span style="font-size:12px;opacity:.8">The patient can now see this note with your name and timestamp in their portal.</span>
      </div>`;
    document.getElementById('note-text').value = '';
    clearNoteImage();
    document.getElementById('my-notes-wrap').style.display = 'block';
    loadMyNotes();
  } catch (e) {
    document.getElementById('note-alert').innerHTML =
      `<div class="alert alert-error">❌ ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = '📝 Save Note to Patient Profile';
  }
}

async function loadMyNotes() {
  const pcode = document.getElementById('note-pcode').value.trim();
  if (!pcode) return;
  document.getElementById('my-notes-title').textContent = `My notes for patient ${pcode}`;
  const box = document.getElementById('my-notes-list');
  box.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:12px 0">Loading…</div>';
  try {
    const res = await fetch(`/api/doctor_notes/${pcode}?doctor_code=${S.code}`);
    const notes = await res.json();
    if (!Array.isArray(notes) || !notes.length) {
      box.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:12px 0">No notes added yet for this patient.</div>';
      return;
    }
    box.innerHTML = notes.map(n => `
      <div style="border:1.5px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:12px;background:var(--surface2)">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="background:var(--purple3);color:var(--purple);font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px">${NOTE_TYPE_LABELS[n.note_type] || n.note_type}</span>
            ${n.visit_date ? `<span style="color:var(--muted);font-size:12px">📅 ${n.visit_date}</span>` : ''}
          </div>
          <button onclick="deleteNote('${n.note_id}')"
            style="background:none;border:1px solid var(--red);color:var(--red);cursor:pointer;font-size:12px;padding:3px 10px;border-radius:6px;white-space:nowrap">
            🗑 Delete
          </button>
        </div>
        <p style="font-size:14px;line-height:1.65;white-space:pre-wrap;margin-bottom:10px">${escHtml(n.note_text || n.note || '')}</p>
        ${n.image_filename ? `<img src="/api/note_images/${n.image_filename}" style="max-width:100%;max-height:280px;border-radius:10px;border:1.5px solid var(--border);object-fit:contain;margin-bottom:10px">` : ''}
        <div style="font-size:11px;color:var(--muted)">Added: ${new Date(n.created_at).toLocaleString()}</div>
      </div>`).join('');
  } catch (e) {
    box.innerHTML = `<div class="alert alert-error">❌ ${e.message}</div>`;
  }
}

async function deleteNote(noteId) {
  if (!confirm('Delete this note? This cannot be undone.')) return;
  const pw = prompt('Enter your password to confirm deletion:');
  if (!pw) return;
  try {
    const res = await fetch(`/api/delete_note/${noteId}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ doctor_code: S.code, password: pw })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Delete failed');
    loadMyNotes();
  } catch (e) { alert('❌ ' + e.message); }
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function previewNoteImage() {
  const file = document.getElementById('note-image').files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('note-img-thumb').src = e.target.result;
    document.getElementById('note-img-preview').style.display = 'block';
  };
  reader.readAsDataURL(file);
}

function clearNoteImage() {
  document.getElementById('note-image').value = '';
  document.getElementById('note-img-thumb').src = '';
  document.getElementById('note-img-preview').style.display = 'none';
}

// ═══════════════════════════════════════════════
//  RESTORE SESSION on page load / refresh
// ═══════════════════════════════════════════════
(function restoreSession() {
  try {
    const saved = sessionStorage.getItem('medvault_session');
    if (saved) {
      const s = JSON.parse(saved);
      if (s.logged) setLoggedIn(s.code, s.name, s.spec||'', s.hosp||'');
    }
  } catch(e) { sessionStorage.removeItem('medvault_session'); }
})();
</script>
</body>
</html>"""

# ── API ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return HTML

@app.route("/api/register", methods=["POST","OPTIONS"])
def api_register():
    if request.method == "OPTIONS": return jsonify({}), 200
    d    = request.get_json(force=True)
    name = d.get("name",""); spec = d.get("specialization","")
    hosp = d.get("hospital",""); email = d.get("email",""); pw = d.get("password","")
    if not name: return jsonify({"error":"Name is required"}), 400
    if not pw:   return jsonify({"error":"Password is required"}), 400

    priv, pub = generate_rsa_keypair()
    doctor_id   = str(uuid.uuid4())
    doctor_code = doctor_id[:8]

    priv_pem = rsa_serialize_private(priv)
    pub_pem  = rsa_serialize_public(pub)

    kek, salt = derive_kek_from_password(pw)
    wrapped   = wrap_key_with_kek(kek, priv_pem)

    folder = os.path.join(DOCTORS_DIR, doctor_id)
    os.makedirs(folder, exist_ok=True)

    # Store the KEK-wrapped private key in Windows Credential Manager.
    # The file `doctor_private_wrapped.b64` is intentionally NOT created.
    SecureKeyStore.store_private_key(f"doctor:{doctor_code}", wrapped.encode())
    with open(os.path.join(folder,"key_protection.json"),"w") as f:
        json.dump({"salt_b64": b64encode(salt).decode()}, f, indent=2)
    with open(os.path.join(folder,"doctor_public.pem"),"wb") as f: f.write(pub_pem)
    meta = {"doctor_id":doctor_id,"doctor_code":doctor_code,"name":name,
            "specialization":spec,"hospital":hosp,"email":email}
    with open(os.path.join(folder,"doctor_data.json"),"w") as f:
        json.dump(meta, f, indent=2)

    # register on backend (public key only)
    try:
        http.post(f"{BACKEND}/register_doctor",
            json={"doctor_id":doctor_id,"doctor_code":doctor_code,"public_pem":pub_pem.decode()},
            headers=bh(), timeout=8)
    except Exception as e:
        print(f"[warn] backend register failed: {e}")

    return jsonify({"doctor_code": doctor_code})

@app.route("/api/load_profile", methods=["POST","OPTIONS"])
def api_load_profile():
    if request.method == "OPTIONS": return jsonify({}), 200
    d    = request.get_json(force=True)
    code = d.get("doctor_code","").strip(); pw = d.get("password","")
    folder = doc_dir(code)
    if not folder: return jsonify({"error":"Profile not found on this machine. Register first."}), 404
    kp = json.load(open(os.path.join(folder,"key_protection.json")))
    try:
        salt  = b64decode(kp["salt_b64"])
        kek,_ = derive_kek_from_password(pw, salt=salt)
        wrapped_bytes = SecureKeyStore.load_private_key(f"doctor:{code}")
        priv_pem = unwrap_key_with_kek(kek, wrapped_bytes.decode())
        rsa_load_private(priv_pem)   # validate key is parseable
    except KeyError:
        return jsonify({"error": "Private key not found in credential store. "
                                 "Re-register on this machine."}), 404
    except Exception:
        return jsonify({"error":"Wrong password"}), 401
    meta = json.load(open(os.path.join(folder,"doctor_data.json")))
    return jsonify({"name":meta.get("name",""),"specialization":meta.get("specialization",""),
                    "hospital":meta.get("hospital","")})

@app.route("/api/request_access", methods=["POST","OPTIONS"])
def api_request_access():
    if request.method == "OPTIONS": return jsonify({}), 200
    d         = request.get_json(force=True)
    doc_code  = d.get("doctor_code",""); pat_code = d.get("patient_code",""); pw = d.get("password","")

    folder = doc_dir(doc_code)
    if not folder: return jsonify({"error":"Doctor profile not found on this machine"}), 404

    # load doctor private key
    try:
        kp      = json.load(open(os.path.join(folder,"key_protection.json")))
        salt    = b64decode(kp["salt_b64"])
        kek,_   = derive_kek_from_password(pw, salt=salt)
        wrapped = open(os.path.join(folder,"doctor_private_wrapped.b64")).read().strip()
        priv_pem = unwrap_key_with_kek(kek, wrapped)
        rsa_load_private(priv_pem)
    except Exception:
        return jsonify({"error":"Wrong password"}), 401

    pub_pem = open(os.path.join(folder,"doctor_public.pem"),"rb").read().decode()
    meta    = json.load(open(os.path.join(folder,"doctor_data.json")))

    # fetch patient public key from backend
    try:
        r = http.get(f"{BACKEND}/get_patient_public/{pat_code}", headers=bh(), timeout=8)
        if r.status_code == 404: return jsonify({"error":"Patient not found on server"}), 404
        pat_pub_pem = r.json().get("patient_public_pem","")
        if not pat_pub_pem: return jsonify({"error":"Patient public key missing"}), 500
    except Exception as e:
        return jsonify({"error":f"Cannot reach backend: {e}"}), 502

    # encrypt doctor profile with patient's public key
    profile_bytes = json.dumps({
        "doctor_id": meta.get("doctor_id"), "doctor_code": doc_code,
        "name": meta.get("name"), "specialization": meta.get("specialization"),
        "hospital": meta.get("hospital"), "email": meta.get("email"),
    }, separators=(",",":")).encode()

    pat_pub_obj = rsa_load_public(pat_pub_pem.encode())
    enc_b64     = rsa_wrap_key(pat_pub_obj, profile_bytes)

    try:
        r = http.post(f"{BACKEND}/request_access_simple/{pat_code}",
            json={"doctor_code":doc_code,"doctor_public_pem":pub_pem,
                  "encrypted_doctor_profile_b64":enc_b64},
            headers=bh(), timeout=8)
        rd = r.json()
        if not r.ok: return jsonify({"error":rd.get("error",r.text)}), r.status_code
        return jsonify({"request_id": rd.get("request_id","")})
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/fetch_record", methods=["POST","OPTIONS"])
def api_fetch_record():
    if request.method == "OPTIONS": return jsonify({}), 200
    d        = request.get_json(force=True)
    doc_code = d.get("doctor_code",""); pat_code = d.get("patient_code",""); pw = d.get("password","")

    folder = doc_dir(doc_code)
    if not folder: return jsonify({"error":"Doctor profile not found"}), 404

    # unlock private key from credential store
    try:
        kp       = json.load(open(os.path.join(folder,"key_protection.json")))
        salt     = b64decode(kp["salt_b64"])
        kek,_    = derive_kek_from_password(pw, salt=salt)
        wrapped_bytes = SecureKeyStore.load_private_key(f"doctor:{doc_code}")
        priv_pem = unwrap_key_with_kek(kek, wrapped_bytes.decode())
        priv     = rsa_load_private(priv_pem)
    except KeyError:
        return jsonify({"error": "Private key not found in credential store. "
                                 "Re-register on this machine."}), 404
    except Exception:
        return jsonify({"error":"Wrong password"}), 401

    # fetch encrypted record from backend
    try:
        r = http.get(f"{BACKEND}/get_patient_data/{pat_code}", headers=bh(), timeout=8)
        if r.status_code == 404: return jsonify({"error":"Patient not found"}), 404
        enc_resp = r.json()
    except Exception as e:
        return jsonify({"error":f"Backend error: {e}"}), 502

    # fetch wrapped key
    try:
        rw = http.get(f"{BACKEND}/wrapped_key/{pat_code}", headers=bh(), timeout=8)
        wk_data = rw.json() if rw.ok else {}
    except Exception as e:
        return jsonify({"error":f"Cannot fetch wrapped key: {e}"}), 502

    # find our wrapped key
    wrapped_key_b64 = None; expires_at = None
    wkmap = wk_data.get("wrapped_keys", wk_data)
    if isinstance(wkmap, dict):
        if doc_code in wkmap:
            entry = wkmap[doc_code]
            wrapped_key_b64 = entry.get("wrapped_key") if isinstance(entry, dict) else entry
            expires_at      = entry.get("temp_key_expires_at") if isinstance(entry, dict) else None
        elif len(wkmap) == 1:
            entry = next(iter(wkmap.values()))
            wrapped_key_b64 = entry.get("wrapped_key") if isinstance(entry, dict) else entry
            expires_at      = entry.get("temp_key_expires_at") if isinstance(entry, dict) else None

    if not wrapped_key_b64:
        return jsonify({"error":"No access key found. The patient may not have approved your request yet, or access has expired."}), 403

    # check expiry
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
                return jsonify({"error":"Your access to this patient's record has expired."}), 403
        except Exception: pass

    # unwrap temp key T, then decrypt K_data, then decrypt record
    try:
        enc_rec = enc_resp.get("encrypted_record",{})
        enc_kdata_with_temp = None
        # find encrypted_kdata_with_temp from wrapped keys entry
        if doc_code in wkmap and isinstance(wkmap[doc_code], dict):
            enc_kdata_with_temp = wkmap[doc_code].get("encrypted_kdata_with_temp")
        elif len(wkmap) == 1:
            enc_kdata_with_temp = next(iter(wkmap.values())).get("encrypted_kdata_with_temp") if isinstance(next(iter(wkmap.values())), dict) else None

        T      = rsa_unwrap_key(priv, wrapped_key_b64)
        if enc_kdata_with_temp:
            K_data = aesgcm_decrypt(T, enc_kdata_with_temp["nonce"], enc_kdata_with_temp["ciphertext"])
        else:
            K_data = T  # direct wrap fallback

        plaintext = aesgcm_decrypt(K_data, enc_rec["nonce"], enc_rec["ciphertext"])
        record    = json.loads(plaintext.decode())
    except Exception as e:
        return jsonify({"error":f"Decryption failed: {e}"}), 500

    # verify signature
    sig_valid = False
    try:
        pat_pub_pem = enc_resp.get("patient_public_pem","")
        sig         = enc_resp.get("signature","")
        if pat_pub_pem and sig:
            pat_pub  = rsa_load_public(pat_pub_pem.encode())
            to_verify = (enc_rec["nonce"] + "|" + enc_rec["ciphertext"]).encode()
            sig_valid = rsa_verify(pat_pub, to_verify, sig)
    except Exception: pass

    return jsonify({"record":record, "sig_valid":sig_valid, "expires_at":expires_at})


# ── NEW ENDPOINTS ─────────────────────────────────────────────────────────

@app.route("/api/lookup_patient", methods=["POST","OPTIONS"])
def api_lookup_patient():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.get_json(force=True)
    code = d.get("profile_code","").strip()
    # check backend has this patient
    try:
        r = http.get(f"{BACKEND}/get_patient_public/{code}", headers=bh(), timeout=6)
        if r.ok:
            return jsonify({"found": True, "profile_code": code})
        return jsonify({"found": False}), 404
    except Exception as e:
        return jsonify({"found": False, "error": str(e)}), 502

@app.route("/api/upload_report", methods=["POST","OPTIONS"])
def api_upload_report():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = request.headers.get("Authorization","").replace("Bearer ","")
    d = request.get_json(force=True)
    try:
        r = http.post(f"{BACKEND}/reports/upload",
            json={"patient_id":d.get("patient_id",""),
                  "encrypted_report_blob":d.get("encrypted_report_blob",{}),
                  "encrypted_aes_key":d.get("encrypted_aes_key",""),
                  "file_hash":d.get("file_hash","")},
            headers=bh(token), timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/upload_image", methods=["POST","OPTIONS"])
def api_upload_image():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        files = {"image": (request.files["image"].filename, request.files["image"].stream, "application/octet-stream")}
        data = {k:v for k,v in request.form.items()}
        r = http.post(f"{BACKEND}/images/upload", files=files, data=data,
            headers={"X-API-Key":api_key(),"Authorization":f"Bearer {token}"}, timeout=30)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/doctor_patients")
def api_doctor_patients():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/access/doctor_patients", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502

@app.route("/api/audit_log")
def api_audit_log():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    try:
        r = http.get(f"{BACKEND}/audit/log", headers=bh(token), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error":str(e)}), 502
# ── DOCTOR NOTES ──────────────────────────────────────────────────────────

@app.route("/api/add_note", methods=["POST", "OPTIONS"])
def api_add_note():
    """Doctor adds a clinical note to a patient profile. Server enforces access check."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    body = request.get_json(force=True) or {}

    # Local password verification before sending to backend
    doc_code = body.get("doctor_code", "").strip()
    pw       = body.get("password", "")
    folder   = doc_dir(doc_code)
    if not folder:
        return jsonify({"error": "Doctor profile not found on this machine"}), 404
    try:
        kp      = json.load(open(os.path.join(folder, "key_protection.json")))
        salt    = b64decode(kp["salt_b64"])
        kek, _  = derive_kek_from_password(pw, salt=salt)
        wrapped_bytes = SecureKeyStore.load_private_key(f"doctor:{doc_code}")
        unwrap_key_with_kek(kek, wrapped_bytes.decode())   # validates password
    except KeyError:
        return jsonify({"error": "Private key not found in credential store. "
                                 "Re-register on this machine."}), 404
    except Exception:
        return jsonify({"error": "Wrong password"}), 401

    meta = json.load(open(os.path.join(folder, "doctor_data.json")))
    try:
        r = http.post(f"{BACKEND}/doctor_notes/add",
            json={
                "patient_code":          body.get("patient_code", ""),
                "doctor_code":           doc_code,
                "doctor_name":           meta.get("name", ""),
                "doctor_specialization": meta.get("specialization", ""),
                "doctor_hospital":       meta.get("hospital", ""),
                "note_type":             body.get("note_type", "General"),
                "note":                  body.get("note_text", ""),
                "visit_date":            body.get("visit_date", ""),
                "image_b64":             body.get("image_b64", ""),
                "image_type":            body.get("image_type", ""),
            },
            headers=bh(), timeout=30)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/doctor_notes/<patient_code>")
def api_doctor_notes_list(patient_code):
    """Fetch all notes for a patient; returns filtered list for this doctor."""
    doc_code = request.args.get("doctor_code", "")
    try:
        r = http.get(f"{BACKEND}/doctor_notes/patient/{patient_code}",
                     headers=bh(), timeout=8)
        data  = r.json() if r.ok else {}
        notes = data.get("notes", []) if isinstance(data, dict) else []
        # Filter by doctor_code client side (server returns all notes for patient)
        if doc_code:
            notes = [n for n in notes if n.get("doctor_code") == doc_code]
        # Normalise field name: server stores id as 'id', JS expects 'note_id'
        for n in notes:
            if "note_id" not in n and "id" in n:
                n["note_id"] = n["id"]
        return jsonify(notes), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/delete_note/<note_id>", methods=["DELETE", "OPTIONS"])
def api_delete_note(note_id):
    """Doctor deletes their own note."""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    body     = request.get_json(force=True) or {}
    doc_code = body.get("doctor_code", "").strip()
    pw       = body.get("password", "")

    # Local password check
    folder = doc_dir(doc_code)
    if not folder:
        return jsonify({"error": "Doctor profile not found"}), 404
    try:
        kp      = json.load(open(os.path.join(folder, "key_protection.json")))
        salt    = b64decode(kp["salt_b64"])
        kek, _  = derive_kek_from_password(pw, salt=salt)
        wrapped_bytes = SecureKeyStore.load_private_key(f"doctor:{doc_code}")
        unwrap_key_with_kek(kek, wrapped_bytes.decode())   # validates password
    except KeyError:
        return jsonify({"error": "Private key not found in credential store. "
                                 "Re-register on this machine."}), 404
    except Exception:
        return jsonify({"error": "Wrong password"}), 401

    try:
        r = http.delete(f"{BACKEND}/doctor_notes/{note_id}",
                        json={"doctor_code": doc_code},
                        headers=bh(), timeout=8)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/note_images/<filename>")
def api_note_image(filename):
    """Proxy note images from the backend server for display in the doctor portal."""
    try:
        r = http.get(f"{BACKEND}/note_images/{filename}",
                     headers={"X-API-Key": api_key()}, timeout=10, stream=True)
        if not r.ok:
            return jsonify({"error": "image not found"}), 404
        from flask import Response
        return Response(r.content, content_type=r.headers.get("Content-Type", "image/jpeg"))
    except Exception as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    print("  Doctor Portal → http://127.0.0.1:5002")
    app.run(host="127.0.0.1", port=5002, debug=False)