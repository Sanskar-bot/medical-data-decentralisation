-- Schema additions: conditions + encounters tables
-- Run with: psql $DATABASE_URL -f server/schema_additions.sql
-- Safe to re-run: all statements use IF NOT EXISTS / IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS conditions (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id      TEXT NOT NULL,
    description     TEXT NOT NULL,
    icd10_code      TEXT DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'resolved', 'inactive')),
    onset_date      DATE,
    resolved_date   DATE,
    recorded_by     TEXT NOT NULL,
    encounter_id    TEXT,
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conditions_patient ON conditions(patient_id);
CREATE INDEX IF NOT EXISTS idx_conditions_status  ON conditions(patient_id, status);

CREATE TABLE IF NOT EXISTS encounters (
    id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    patient_id          TEXT NOT NULL,
    doctor_id           TEXT NOT NULL,
    appointment_id      TEXT,
    appointment_source  TEXT DEFAULT ''
                        CHECK (appointment_source IN ('', 'legacy', 'emr')),
    status              TEXT NOT NULL DEFAULT 'in_progress'
                        CHECK (status IN ('in_progress', 'completed', 'cancelled')),
    reason              TEXT DEFAULT '',
    summary             TEXT DEFAULT '',
    started_at          TIMESTAMPTZ DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_encounters_patient ON encounters(patient_id);
CREATE INDEX IF NOT EXISTS idx_encounters_doctor  ON encounters(doctor_id);
CREATE INDEX IF NOT EXISTS idx_encounters_appt    ON encounters(appointment_id);

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS patient_details JSONB DEFAULT '{}'::jsonb;

-- Per-share snapshots; package payload contains encrypted snapshot data only.
CREATE TABLE IF NOT EXISTS shares (
    share_id        TEXT PRIMARY KEY,
    patient_code    TEXT NOT NULL,
    doctor_code     TEXT NOT NULL,
    label           TEXT DEFAULT '',
    ciphertext_blob JSONB,
    wrapped_key     TEXT,
    signature       TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','revoked','expired','purged')),
    fetched_at      TIMESTAMPTZ,
    purged_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_shares_doctor_status ON shares(doctor_code, status);
CREATE INDEX IF NOT EXISTS idx_shares_patient_status ON shares(patient_code, status);
CREATE INDEX IF NOT EXISTS idx_shares_expires_at ON shares(expires_at);

-- IPFS content addressing for encrypted share snapshots.
ALTER TABLE shares ADD COLUMN IF NOT EXISTS ipfs_cid TEXT;
ALTER TABLE shares ADD COLUMN IF NOT EXISTS ciphertext_sha256 TEXT;
ALTER TABLE shares ADD COLUMN IF NOT EXISTS ciphertext_size BIGINT;

-- Encrypted registration records are stored in private Kubo. Keep the old
-- column nullable for one-way migration of rows created by earlier releases.
ALTER TABLE patients ALTER COLUMN encrypted_record DROP NOT NULL;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS ipfs_cid TEXT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS ciphertext_sha256 TEXT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS ciphertext_size BIGINT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS ipfs_version INTEGER NOT NULL DEFAULT 1;

-- Pin state is tracked per CID and private target so the repair worker can
-- restore replicas without placing ciphertext in PostgreSQL.
CREATE TABLE IF NOT EXISTS ipfs_pin_status (
    cid             TEXT NOT NULL,
    target          TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pinned','pending','unpinned')),
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT DEFAULT '',
    PRIMARY KEY (cid, target)
);
CREATE INDEX IF NOT EXISTS idx_ipfs_pin_status_pending
    ON ipfs_pin_status(status, last_checked_at);

-- Orphans are delayed before cleanup to avoid racing a just-uploaded CID with
-- its metadata transaction.
CREATE TABLE IF NOT EXISTS ipfs_orphans (
    cid         TEXT NOT NULL,
    target      TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cid, target)
);

CREATE TABLE IF NOT EXISTS ipfs_gc_state (
    target       TEXT PRIMARY KEY,
    last_gc_at   TIMESTAMPTZ NOT NULL DEFAULT 'epoch'
);
