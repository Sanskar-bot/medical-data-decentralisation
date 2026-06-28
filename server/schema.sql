-- server/schema.sql
-- Run with: psql $DATABASE_URL -f server/schema.sql
-- Safe to re-run: all tables use CREATE TABLE IF NOT EXISTS.

BEGIN;

-- ── Users ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                    TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    email                 TEXT UNIQUE NOT NULL,
    username              TEXT UNIQUE NOT NULL,
    name                  TEXT NOT NULL,
    phone                 TEXT DEFAULT '',
    role                  TEXT NOT NULL DEFAULT 'patient'
                          CHECK (role IN ('patient','doctor','admin','receptionist')),
    password_hash         TEXT NOT NULL,
    public_key            TEXT DEFAULT '',
    encrypted_private_key TEXT DEFAULT '',
    profile_code          TEXT DEFAULT '',
    doctor_code           TEXT DEFAULT '',
    profile_photo_url     TEXT DEFAULT '',
    locked                BOOLEAN DEFAULT FALSE,
    failed_attempts       INTEGER DEFAULT 0,
    created_at            TIMESTAMPTZ DEFAULT now(),
    last_login            TIMESTAMPTZ
);

-- ── OTP store ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS otp_store (
    email       TEXT PRIMARY KEY,
    otp         TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    INTEGER DEFAULT 0
);

-- ── Token blocklist ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS token_blocklist (
    jti         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocklist_exp ON token_blocklist(expires_at);

-- ── Login history ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS login_history (
    id      BIGSERIAL PRIMARY KEY,
    email   TEXT NOT NULL,
    ts      TIMESTAMPTZ DEFAULT now(),
    ip      TEXT
);
CREATE INDEX IF NOT EXISTS idx_login_history_email ON login_history(email);

-- ── Patients ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS patients (
    profile_code        TEXT PRIMARY KEY,
    encrypted_record    JSONB NOT NULL,
    patient_public_pem  TEXT,
    signature           TEXT,
    uploaded_at         TIMESTAMPTZ DEFAULT now()
);

-- ── Doctors ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS doctors (
    doctor_code         TEXT PRIMARY KEY,
    doctor_id           TEXT UNIQUE NOT NULL,
    public_pem          TEXT NOT NULL,
    encrypted_profile   TEXT,
    registered_at       TIMESTAMPTZ DEFAULT now()
);

-- ── Access requests ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS access_requests (
    request_id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    profile_code                TEXT NOT NULL,
    doctor_code                 TEXT NOT NULL,
    status                      TEXT NOT NULL DEFAULT 'pending'
                                CHECK (status IN
                                ('pending','approved','denied','expired','cancelled')),
    doctor_public_pem           TEXT,
    encrypted_doctor_profile    TEXT,
    wrapped_key                 TEXT,
    encrypted_kdata             JSONB,
    temp_key_expires_at         TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ DEFAULT now(),
    approved_at                 TIMESTAMPTZ,
    denied_at                   TIMESTAMPTZ,
    cancelled_at                TIMESTAMPTZ,
    expired_at                  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_requests_profile
    ON access_requests(profile_code);
CREATE INDEX IF NOT EXISTS idx_access_requests_doctor
    ON access_requests(doctor_code);
CREATE INDEX IF NOT EXISTS idx_access_requests_status
    ON access_requests(status);

-- ── Wrapped keys ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wrapped_keys (
    id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    profile_code        TEXT NOT NULL,
    doctor_code         TEXT NOT NULL,
    wrapped_key         TEXT NOT NULL,
    encrypted_kdata     JSONB,
    temp_key_expires_at TIMESTAMPTZ,
    uploaded_at         TIMESTAMPTZ DEFAULT now(),
    UNIQUE(profile_code, doctor_code)
);
CREATE INDEX IF NOT EXISTS idx_wrapped_keys_profile
    ON wrapped_keys(profile_code);

-- ── Doctor notes ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS doctor_notes (
    note_id                 TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_code            TEXT NOT NULL,
    doctor_code             TEXT NOT NULL,
    doctor_name             TEXT DEFAULT '',
    doctor_specialization   TEXT DEFAULT '',
    doctor_hospital         TEXT DEFAULT '',
    note_type               TEXT DEFAULT 'General',
    note_text               TEXT NOT NULL,
    visit_date              DATE,
    created_at              TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notes_patient ON doctor_notes(patient_code);
CREATE INDEX IF NOT EXISTS idx_notes_doctor  ON doctor_notes(doctor_code);

-- ── Records (visit reports) ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS records (
    id                      TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id              TEXT NOT NULL,
    doctor_id               TEXT NOT NULL,
    doctor_email            TEXT DEFAULT '',
    encrypted_report_blob   JSONB,
    encrypted_aes_key       TEXT DEFAULT '',
    file_hash               TEXT DEFAULT '',
    created_at              TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_records_patient ON records(patient_id);

-- ── Images ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS images (
    id                      TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    record_id               TEXT NOT NULL,
    encrypted_image_path    TEXT NOT NULL,
    encrypted_aes_key       TEXT DEFAULT '',
    file_hash               TEXT DEFAULT '',
    server_hash             TEXT DEFAULT '',
    hash_verified           BOOLEAN,
    doctor_id               TEXT DEFAULT '',
    created_at              TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_images_record ON images(record_id);

-- ── Access DB (JWT-based access management) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS access_db (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    doctor_id       TEXT NOT NULL,
    doctor_email    TEXT DEFAULT '',
    patient_id      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','revoked','denied')),
    created_at      TIMESTAMPTZ DEFAULT now(),
    responded_at    TIMESTAMPTZ,
    UNIQUE(doctor_id, patient_id)
);

-- ── Appointments ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS appointments (
    id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id          TEXT NOT NULL,
    patient_username    TEXT DEFAULT '',
    patient_name        TEXT DEFAULT '',
    doctor_username     TEXT NOT NULL,
    date                TEXT NOT NULL,
    time                TEXT NOT NULL,
    notes               TEXT DEFAULT '',
    status              TEXT DEFAULT 'pending'
                        CHECK (status IN
                        ('pending','accepted','rejected','rescheduled','completed')),
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_appointments_patient
    ON appointments(patient_id);
CREATE INDEX IF NOT EXISTS idx_appointments_doctor
    ON appointments(doctor_username);

-- ── EMR profiles ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS emr_profiles (
    patient_id          TEXT PRIMARY KEY,
    name                TEXT DEFAULT '',
    age                 TEXT DEFAULT '',
    gender              TEXT DEFAULT '',
    blood_group         TEXT DEFAULT '',
    medical_history     JSONB DEFAULT '[]',
    allergies           JSONB DEFAULT '[]',
    emergency_contact   JSONB DEFAULT '{}',
    past_visits         JSONB DEFAULT '[]',
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);

-- ── EMR appointments ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS emr_appointments (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id  TEXT NOT NULL,
    doctor_id   TEXT NOT NULL,
    date_time   TEXT NOT NULL,
    reason      TEXT DEFAULT '',
    status      TEXT DEFAULT 'scheduled'
                CHECK (status IN
                ('scheduled','completed','cancelled','no_show')),
    notes       TEXT DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_emr_appt_patient ON emr_appointments(patient_id);
CREATE INDEX IF NOT EXISTS idx_emr_appt_doctor  ON emr_appointments(doctor_id);

-- ── Unified appointment view ────────────────────────────────────────────────
CREATE OR REPLACE VIEW appointments_unified AS
SELECT
    id::TEXT AS id,
    'request'::TEXT AS source,
    patient_id,
    patient_name,
    patient_username,
    doctor_username,
    ''::TEXT AS doctor_id,
    date,
    time,
    (date || ' ' || time)::TEXT AS date_time,
    notes AS reason,
    notes,
    status,
    created_at,
    updated_at
FROM appointments
UNION ALL
SELECT
    id::TEXT AS id,
    'emr'::TEXT AS source,
    patient_id,
    ''::TEXT AS patient_name,
    ''::TEXT AS patient_username,
    ''::TEXT AS doctor_username,
    doctor_id,
    ''::TEXT AS date,
    ''::TEXT AS time,
    date_time,
    reason,
    notes,
    status,
    created_at,
    updated_at
FROM emr_appointments;

-- ── EMR prescriptions ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS emr_prescriptions (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id      TEXT NOT NULL,
    doctor_id       TEXT NOT NULL,
    doctor_email    TEXT DEFAULT '',
    diagnosis       TEXT DEFAULT '',
    medications     JSONB NOT NULL DEFAULT '[]',
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_emr_rx_patient ON emr_prescriptions(patient_id);
CREATE INDEX IF NOT EXISTS idx_emr_rx_doctor  ON emr_prescriptions(doctor_id);

-- ── EMR lab reports ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS emr_lab_reports (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id      TEXT NOT NULL,
    doctor_id       TEXT DEFAULT '',
    doctor_email    TEXT DEFAULT '',
    report_type     TEXT NOT NULL,
    results         JSONB DEFAULT '{}',
    file_hash       TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_emr_lab_patient ON emr_lab_reports(patient_id);

-- ── Audit log ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGSERIAL PRIMARY KEY,
    ts      TIMESTAMPTZ DEFAULT now(),
    action  TEXT NOT NULL,
    actor   TEXT DEFAULT '',
    target  TEXT DEFAULT '',
    detail  TEXT DEFAULT '',
    ip      TEXT DEFAULT ''
);
-- append-only: application layer must never UPDATE or DELETE this table
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);

-- ── Rate limits ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
    id          BIGSERIAL PRIMARY KEY,
    ip          TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    hit_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_endpoint
    ON rate_limits(ip, endpoint, hit_at DESC);

-- ── Conditions (Problem List) ─────────────────────────────────────────────────
-- Tracks chronic and acute conditions for a patient.  Linked to an encounter
-- when the condition is first recorded during a visit (nullable — a condition
-- can be entered outside any single visit).
CREATE TABLE IF NOT EXISTS conditions (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id      TEXT NOT NULL,
    description     TEXT NOT NULL,       -- free-text, e.g. "Type 2 Diabetes"
    icd10_code      TEXT DEFAULT '',     -- empty until a coding step exists
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'resolved', 'inactive')),
    onset_date      DATE,
    resolved_date   DATE,
    recorded_by     TEXT NOT NULL,       -- doctor_id / doctor_code
    encounter_id    TEXT,                -- nullable FK-by-convention to encounters.id
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conditions_patient
    ON conditions(patient_id);
CREATE INDEX IF NOT EXISTS idx_conditions_status
    ON conditions(patient_id, status);

-- ── Encounters ────────────────────────────────────────────────────────────────
-- A single clinical visit.  Ties together appointment + notes + prescriptions
-- + lab orders for one encounter.  appointment_source disambiguates which of
-- the two appointment tables (legacy `appointments` or `emr_appointments`) the
-- appointment_id refers to — this project currently has two parallel systems.
CREATE TABLE IF NOT EXISTS encounters (
    id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id          TEXT NOT NULL,
    doctor_id           TEXT NOT NULL,
    appointment_id      TEXT,            -- nullable: walk-in visits have none
    appointment_source  TEXT DEFAULT ''
                        CHECK (appointment_source IN ('', 'legacy', 'emr')),
    status              TEXT NOT NULL DEFAULT 'in_progress'
                        CHECK (status IN ('in_progress', 'completed', 'cancelled')),
    reason              TEXT DEFAULT '',
    summary             TEXT DEFAULT '', -- free-text visit summary on completion
    started_at          TIMESTAMPTZ DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_encounters_patient
    ON encounters(patient_id);
CREATE INDEX IF NOT EXISTS idx_encounters_doctor
    ON encounters(doctor_id);
CREATE INDEX IF NOT EXISTS idx_encounters_appt
    ON encounters(appointment_id);

-- ── Cross-table linkage columns (idempotent ALTERs) ──────────────────────────
-- These link existing visit-artifact rows to the encounters and conditions
-- tables.  All nullable — records created outside any tracked encounter/
-- condition context must continue to work unchanged.

ALTER TABLE emr_prescriptions ADD COLUMN IF NOT EXISTS encounter_id  TEXT;
ALTER TABLE emr_prescriptions ADD COLUMN IF NOT EXISTS condition_id  TEXT;
ALTER TABLE emr_lab_reports   ADD COLUMN IF NOT EXISTS encounter_id  TEXT;
ALTER TABLE emr_lab_reports   ADD COLUMN IF NOT EXISTS condition_id  TEXT;
ALTER TABLE doctor_notes      ADD COLUMN IF NOT EXISTS encounter_id  TEXT;
ALTER TABLE emr_appointments  ADD COLUMN IF NOT EXISTS encounter_id  TEXT;
ALTER TABLE appointments      ADD COLUMN IF NOT EXISTS encounter_id  TEXT;

-- ── Bug 2: structured patient demographics ────────────────────────────────────
-- date_of_birth replaces the free-text age column as the source of truth.
-- age TEXT is kept for backward-compatibility (existing rows are unaffected).
-- Application layer always derives age from date_of_birth when present.
ALTER TABLE emr_profiles ADD COLUMN IF NOT EXISTS date_of_birth DATE;
ALTER TABLE emr_profiles ADD COLUMN IF NOT EXISTS patient_metadata JSONB DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_emr_rx_encounter
    ON emr_prescriptions(encounter_id);
CREATE INDEX IF NOT EXISTS idx_emr_lab_encounter
    ON emr_lab_reports(encounter_id);
CREATE INDEX IF NOT EXISTS idx_notes_encounter
    ON doctor_notes(encounter_id);

COMMIT;
