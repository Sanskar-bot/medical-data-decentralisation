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
