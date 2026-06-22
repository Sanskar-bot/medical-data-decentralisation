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

COMMIT;
