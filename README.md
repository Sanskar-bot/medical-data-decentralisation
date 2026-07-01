# 🏥 Decentralized Healthcare Data Management System

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Framework-lightgrey?logo=flask)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM%20%2B%20RSA-orange)
![Status](https://img.shields.io/badge/Status-Active-blue)

Maintained as an active development project.

---

## 📘 Overview

The **Decentralized Healthcare Data Management System** is a **secure, end-to-end encrypted platform** that decentralizes medical data ownership.  
Patients **fully control** their records, and doctors can access them **only with consent** for a **limited time** — ensuring **data privacy, security, and transparency** across distributed networks.

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

The system enables secure and privacy-first healthcare data handling with multiple applications:

### 🩹 Health Awareness
Promotes preventive care and provides educational insights into diseases and wellness practices.

### ⏱️ Tracking & Reminders
Tracks vaccinations, appointments, and health metrics — sending automated alerts for upcoming or missed checkups.

### 🔗 Device Integration
Connects securely with fitness trackers and IoT health devices (e.g., heart rate, blood pressure, oxygen levels) for continuous monitoring.

### ☁️ Secure Backup
Allows encrypted backups of medical records on trusted cloud or personal devices for long-term accessibility.

---

## 💡 Proposed Solution

A **decentralized, patient-centric** data system that uses **end-to-end encryption** and **distributed storage** (like IPFS or hybrid clouds).  
Patients own their data, hospitals retain **time-limited access**, and servers only manage **encrypted metadata**.

---

## ⚙️ System Architecture

### 🧩 Components

| Layer | Technology | Description |
|-------|-------------|-------------|
| **Frontend** | HTML/CSS/JS / Kivy | Patient & Doctor interfaces |
| **Backend** | Flask (Python) | REST APIs for registration, data exchange |
| **Encryption** | AES-256-GCM, RSA/ECC | End-to-end data protection |
| **Storage** | IPFS / Hybrid Cloud | Encrypted data storage |
| **Transport** | HTTPS (TLS 1.3) | Secure communication layer |

---

## 🔐 Patient–Doctor Interaction Protocol

### 🧍 Patient Registration
- Receives a **unique patient ID** and verification card.  
- Data stored **locally and encrypted**; only metadata uploaded.  

### 👨‍⚕️ Doctor Registration
- Doctor creates an ID linked to verified credentials.  
- Public key stored server-side for encrypted interactions.

### 🔁 Data Sharing Workflow

1. Patient shares their ID or QR code with the doctor.  
2. Doctor requests **temporary (24-hour)** access.  
3. Patient grants access → AES key encrypted with doctor’s public key.  
4. Doctor decrypts data locally using their private key.  
5. Updated prescriptions are securely uploaded and auto-expire after a set duration.

---

## 🧠 Privacy-Centric Design

| Feature | Description |
|----------|-------------|
| **Time-Limited Data Retention** | Servers only hold data for a short window (e.g., 24 hours). |
| **Server-Side Log Retention** | Only minimal access logs for audits. |
| **End-to-End Encryption** | AES-GCM for confidentiality, RSA/ECC for secure sharing. |
| **Patient Ownership** | Full control and encrypted backup capabilities. |

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
