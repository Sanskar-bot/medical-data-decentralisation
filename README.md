# 🏥 MedVault — Consent-Based Sharing for Encrypted Patient Records

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Framework-lightgrey?logo=flask)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM%20%2B%20RSA--4096-orange)
![Status](https://img.shields.io/badge/Status-Research%20Prototype-blue)

A research prototype of consent-based sharing for encrypted patient records.

---

## 📘 Overview

MedVault is a **research prototype** of consent-based sharing for encrypted patient records.
Patients authorize access to their records via **consent-based cryptographic key sharing**, and doctors can access them **only after explicit patient approval**.

The patient's registration record is encrypted (AES-256-GCM, key wrapped with RSA-4096 OAEP). Most clinical data added later (notes, prescriptions, vitals, lab results) is stored in plaintext. Encryption and key handling currently happen in the portal server.

Encrypted registration records and per-share snapshot ciphertexts are stored in a private, offline Kubo/IPFS node. PostgreSQL stores their CIDs, SHA-256 digests, sizes and package metadata. IPFS is not public or decentralized in this deployment. EMR clinical tables remain plaintext in PostgreSQL, and the application does not claim end-to-end encryption.

> **Important:** This is a research prototype, not a production system. See [Current Status and Limitations](#-current-status-and-limitations) below, and the full [Threat Model](docs/THREAT_MODEL.md).

### Per-share snapshots (new)

New per-share snapshot endpoints encrypt a selected snapshot with a fresh key for one doctor and apply best-effort expiry. This feature supplements the existing sharing flow. See the [scheme plan](docs/SHARE_SCHEME_PLAN.md) and [threat model](docs/THREAT_MODEL.md) for its limits.

### Private ciphertext storage

The Docker Compose deployment runs two offline Kubo nodes with no published API or gateway port. The backend and maintenance worker reach them over an internal Docker network. For configuration and the backup/restore procedure, see [IPFS backup and restore](docs/IPFS_BACKUP_RESTORE.md).

---

## 🔍 Problem Statement

Modern healthcare relies heavily on **centralized data storage**, leading to critical issues:

- 💸 **High Operational Costs:** Maintaining secure centralized servers is expensive and inefficient.  
- 🔓 **Data Breaches & Exploitation:** Sensitive health records are often misused or sold to third parties.  
- 🎯 **Targeted Manipulation:** Leaked data can be weaponized for influence or targeted advertising.  
- 🗂️ **Data Loss & Lifecycle Issues:** Physical and outdated reports are frequently lost or deleted.  
- 🧠 **Low Digital Awareness:** Patients lack control and knowledge about digital health privacy.

---

## 🌐 Scope of the System

The system explores secure and privacy-first healthcare data handling with multiple planned capabilities:

### 🩹 Health Awareness
Promotes preventive care and provides educational insights into diseases and wellness practices.

### ⏱️ Tracking & Reminders
Tracks vaccinations, appointments, and health metrics — sending automated alerts for upcoming or missed checkups.

### 🔗 Device Integration
Connects securely with fitness trackers and IoT health devices (e.g., heart rate, blood pressure, oxygen levels) for continuous monitoring.

### ☁️ Secure Backup
Planned: encrypted backups of medical records on the patient's own cloud or personal devices for long-term accessibility.

---

## 💡 Approach

A **patient-centric** data system that uses **hybrid encryption** (AES-256-GCM + RSA-4096 OAEP) for patient registration records with consent-based key sharing.

The current prototype uses a **centralized Flask + PostgreSQL backend**. A planned future design envisions data stored primarily on the patient's own device, with the server acting only as an encrypted relay.

---

## ⚙️ System Architecture

### 🧩 Components

| Layer | Technology | Description |
|-------|-------------|-------------|
| **Frontend** | HTML/CSS/JS | Patient & Doctor web interfaces |
| **Backend** | Flask (Python) | REST APIs for registration, authentication, data exchange |
| **Encryption** | AES-256-GCM, RSA-4096 OAEP | Hybrid encryption for patient registration records |
| **Storage** | PostgreSQL + private Kubo/IPFS | PostgreSQL metadata; private IPFS ciphertext for registration records and per-share snapshots |
| **Transport** | HTTPS (TLS 1.2+) | Secure communication layer |

---

## 🔐 Patient–Doctor Interaction Protocol

### 🧍 Patient Registration
- Receives a **unique patient profile code**.  
- Registration record encrypted with AES-256-GCM and stored server-side.
- RSA-4096 keypair generated for key-wrapping operations.

### 👨‍⚕️ Doctor Registration
- Admin creates doctor account with verified credentials.  
- RSA public key stored server-side for encrypted key exchange.

### 🔁 Data Sharing Workflow

1. Patient shares their profile code with the doctor.  
2. Doctor submits an access request.  
3. Patient reviews and approves → a temporary AES key wraps K_data, which is then RSA-wrapped for the doctor.  
4. Doctor unwraps the key material to access the encrypted registration record.  
5. Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.

> **Note:** Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 🧠 Privacy Design

| Feature | Description |
|----------|-------------|
| **Registration Record Encryption** | Patient registration data encrypted with AES-256-GCM. |
| **Server-Side Access Expiry** | Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked. |
| **Transport Encryption** | TLS 1.2+ with HSTS for all communication. |
| **Consent-Based Access** | Doctors can only receive key material after explicit patient approval. |

---

## 🚀 API Endpoints

### 🧍 Patient Registration

```python
POST /register_user
Content-Type: application/json

{
  "user_id": "315df6aa",
  "name": "Sanskar",
  "email": "sanskar@example.com",
  "public_key": "<patient_public_key>"
}
```

---

## ⚠️ Current Status and Limitations

This is a **research prototype**. The following honestly states what is and is not implemented:

This is a centralized Flask + PostgreSQL prototype with a private, offline Kubo/IPFS ciphertext store for encrypted registration records and per-share snapshots only. Most clinical data remains plaintext in PostgreSQL, and portal servers handle keys. No public gateway, public-network publishing, blockchain, or public IPFS network is used. The Android patient app and registry-based doctor verification are planned and not implemented. Revocation cannot un-see decrypted data.

The maintenance worker migrates legacy inline encrypted registration/share payloads in batches; until that finishes, legacy ciphertext can remain in PostgreSQL. The registration-record deletion endpoint removes the registration envelope and related share metadata/pins, but does not remove plaintext EMR data or the patient account.

### What is implemented
- Hybrid encryption (AES-256-GCM + RSA-4096 OAEP) for the **patient registration record**
- Private Kubo/IPFS storage for registration ciphertext and per-share snapshot ciphertext; PostgreSQL retains CIDs, SHA-256, sizes, wrapped keys and metadata
- Consent-based key sharing: doctors must request access, patients must approve
- Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (access_db) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.
- JWT-based authentication with refresh token rotation
- Audit logging of access events
- TLS transport encryption via Nginx
- Allergy/drug-interaction safety check for prescriptions

### What is NOT implemented (planned for future work)
- **Client-side (phone/browser) encryption**: Currently, all key generation, encryption, and decryption happen on the portal server, not on the patient's device. The portal server can read plaintext and private keys.
- **Encryption of clinical data**: Most clinical data (doctor notes, prescriptions, lab reports, vitals, conditions, encounters, EMR profiles) is stored as **plaintext** in the database. Only the initial patient registration record is encrypted.
- **Public or decentralized storage**: IPFS is a private offline ciphertext store for registration records and per-share snapshots only. It does not provide anonymity or guaranteed deletion. EMR clinical data remains in PostgreSQL.
- **Robust key recovery**: Key loss currently means partial data loss.
- **Doctor identity verification**: Doctor accounts are created manually by an admin. The `doctor_verification_status` column exists but no verification logic is implemented.
- **Encrypted backup/export**: No backup export mechanism exists.
- **Emergency access**: No emergency access mechanism exists.
- **Tamper-evident audit log**: The audit log has no integrity protection (no hash chain or signatures).
- **Argon2id for all key derivation**: An Argon2id key derivation function is implemented but not yet wired into runtime call sites; PBKDF2 is used at all KEK derivation points.

### Known security limitations
- The same password is used for login and KEK derivation; the backend receives the password at login.
- `_doctor_has_active_access` grants permanent implicit access if a doctor has ever written a prescription or lab report for the patient.
- `/approve_request` is protected by a shared API key, not patient-specific authentication.
- The API key comparison uses `!=` instead of a constant-time compare.

For a full analysis, see **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.
