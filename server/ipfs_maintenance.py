"""Repair private Kubo pins, remove orphan pins, and run scheduled repo GC."""

from __future__ import annotations

import logging
import os
import base64
import json
import sys
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
load_dotenv(os.path.join(ROOT, ".env"))

from common.ipfs_utils import (  # noqa: E402
    IPFSClient, IPFSIntegrityError, IPFSStorageError,
)
from db import db_cursor, init_db  # noqa: E402

logging.basicConfig(level=os.getenv("IPFS_MAINTENANCE_LOG_LEVEL", "INFO"))
log = logging.getLogger("medvault.ipfs_maintenance")


def _payload_rows():
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT ipfs_cid AS cid, ciphertext_sha256 AS sha256
              FROM patients
             WHERE ipfs_cid IS NOT NULL AND ciphertext_sha256 IS NOT NULL
            UNION
            SELECT ipfs_cid AS cid, ciphertext_sha256 AS sha256
              FROM shares
             WHERE status = 'active' AND expires_at > now()
               AND ipfs_cid IS NOT NULL AND ciphertext_sha256 IS NOT NULL
        """)
        return [(row["cid"], row["sha256"]) for row in cur.fetchall()]


def _unpin_if_unreferenced(client, cid):
    """Avoid removing a content-addressed block still used by another row."""
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM patients WHERE ipfs_cid = %s
                UNION ALL
                SELECT 1 FROM shares WHERE ipfs_cid = %s AND status = 'active'
            ) AS referenced
        """, (cid, cid))
        if cur.fetchone()["referenced"]:
            return
    client.unpin_all(cid)


def _upload_and_verify(client, data):
    """Return a stored block only after fetching and verifying it again."""
    stored = client.store_ciphertext(data)
    try:
        fetched = client.get_verified_bytes(stored.cid, stored.sha256)
        if len(fetched) != stored.size or fetched != data:
            raise IPFSIntegrityError("Migrated ciphertext size or byte verification failed")
        return stored
    except Exception:
        try:
            _unpin_if_unreferenced(client, stored.cid)
        except Exception:
            # The normal orphan grace-period cleanup handles a pin when Postgres
            # is unavailable during rollback.
            pass
        raise


def legacy_inline_counts() -> dict[str, int]:
    """Count encrypted legacy payloads still inline in PostgreSQL."""
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT
                (SELECT count(*) FROM patients
                  WHERE encrypted_record IS NOT NULL) AS registrations,
                (SELECT count(*) FROM shares
                  WHERE ipfs_cid IS NULL
                    AND ciphertext_blob ? 'ciphertext') AS shares
        """)
        row = cur.fetchone()
        return {
            "registrations": int(row["registrations"]),
            "shares": int(row["shares"]),
        }


def migrate_legacy_ciphertext(client=None, batch_size=100) -> dict[str, int]:
    """Move pre-IPFS encrypted registration/share blobs out of PostgreSQL."""
    client = client or IPFSClient()
    migrated = {"registrations": 0, "shares": 0, "failed": 0}
    with db_cursor(commit=False) as cur:
        cur.execute("""
            SELECT profile_code, encrypted_record, patient_public_pem, signature
              FROM patients
             WHERE encrypted_record IS NOT NULL AND ipfs_cid IS NULL
             ORDER BY profile_code
             LIMIT %s
        """, (batch_size,))
        registration_rows = [dict(row) for row in cur.fetchall()]
        cur.execute("""
            SELECT share_id, ciphertext_blob FROM shares
             WHERE status = 'active' AND expires_at > now() AND ipfs_cid IS NULL
             ORDER BY share_id
             LIMIT %s
        """, (batch_size,))
        share_rows = [dict(row) for row in cur.fetchall()]

    for row in registration_rows:
        try:
            envelope = row["encrypted_record"]
            if isinstance(envelope, str):
                envelope = json.loads(envelope)
            data = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
            stored = _upload_and_verify(client, data)
            with db_cursor() as cur:
                cur.execute("""
                    UPDATE patients SET encrypted_record = NULL, ipfs_cid = %s,
                        ciphertext_sha256 = %s, ciphertext_size = %s, ipfs_version = 1,
                        uploaded_at = now()
                    WHERE profile_code = %s AND encrypted_record IS NOT NULL AND ipfs_cid IS NULL
                """, (stored.cid, stored.sha256, stored.size, row["profile_code"]))
                updated = cur.rowcount
                if updated:
                    _save_pin_status(cur, stored.cid, stored.pin_status)
            if updated:
                migrated["registrations"] += 1
            else:
                _unpin_if_unreferenced(client, stored.cid)
        except Exception as exc:
            log.warning("Legacy registration migration failed for one row: %s", exc)
            migrated["failed"] += 1

    for row in share_rows:
        try:
            blob = row["ciphertext_blob"]
            if isinstance(blob, str):
                blob = json.loads(blob)
            ciphertext = blob.get("ciphertext") if isinstance(blob, dict) else None
            if not isinstance(ciphertext, str):
                continue
            data = base64.b64decode(ciphertext, validate=True)
            stored = _upload_and_verify(client, data)
            metadata = {key: value for key, value in blob.items() if key != "ciphertext"}
            with db_cursor() as cur:
                cur.execute("""
                    UPDATE shares SET ciphertext_blob = %s, ipfs_cid = %s,
                        ciphertext_sha256 = %s, ciphertext_size = %s
                    WHERE share_id = %s AND status = 'active' AND ipfs_cid IS NULL
                """, (json.dumps(metadata), stored.cid, stored.sha256,
                      stored.size, row["share_id"]))
                updated = cur.rowcount
                if updated:
                    _save_pin_status(cur, stored.cid, stored.pin_status)
            if updated:
                migrated["shares"] += 1
            else:
                _unpin_if_unreferenced(client, stored.cid)
        except Exception as exc:
            log.warning("Legacy share migration failed for one row: %s", exc)
            migrated["failed"] += 1
    return migrated


def _save_pin_status(cur, cid, pin_status):
    for target, status in pin_status.items():
        cur.execute("""
            INSERT INTO ipfs_pin_status (cid, target, status, last_checked_at, last_error)
            VALUES (%s, %s, %s, now(), '')
            ON CONFLICT (cid, target) DO UPDATE SET
                status = EXCLUDED.status, last_checked_at = now(), last_error = ''
        """, (cid, target, status))


def repair_pins(client=None) -> dict[str, int]:
    client = client or IPFSClient()
    rows = _payload_rows()
    result = {"checked": 0, "repaired": 0, "pending": 0}
    endpoints = [("primary", client.api_url), *client.pin_targets]
    for cid, digest in rows:
        try:
            verified = client.get_verified_bytes(cid, digest)
        except IPFSStorageError as exc:
            log.warning("Could not verify CID %s for pin repair: %s", cid, exc)
            result["pending"] += len(endpoints)
            continue
        for target_name, target_url in endpoints:
            result["checked"] += 1
            target = client if target_url == client.api_url else IPFSClient(
                api_url=target_url, timeout=client.timeout, retries=client.retries,
                backoff=client.backoff, pin_targets=[],
            )
            try:
                already_pinned = cid in target.list_pins()
                if already_pinned:
                    try:
                        target.get_verified_bytes(cid, digest)
                        status, error = "pinned", ""
                    except IPFSStorageError:
                        target.unpin(cid)
                        already_pinned = False
                if not already_pinned:
                    actual = target.add_bytes(verified)
                    if actual != cid:
                        raise IPFSStorageError("pin repair CID mismatch")
                    status, error = "pinned", ""
                    result["repaired"] += 1
            except IPFSStorageError as exc:
                status, error = "pending", str(exc)[:500]
                result["pending"] += 1
            with db_cursor() as cur:
                cur.execute("""
                    INSERT INTO ipfs_pin_status (cid, target, status, last_checked_at, last_error)
                    VALUES (%s, %s, %s, now(), %s)
                    ON CONFLICT (cid, target) DO UPDATE SET
                        status = EXCLUDED.status, last_checked_at = now(),
                        last_error = EXCLUDED.last_error
                """, (cid, target_name, status, error))
    return result


def cleanup_orphans(client=None, grace_seconds=None) -> dict[str, int]:
    """Unpin CIDs with no live DB reference after a configurable grace period."""
    client = client or IPFSClient()
    grace = int(grace_seconds if grace_seconds is not None else
                os.getenv("IPFS_ORPHAN_GRACE_SECONDS", "86400"))
    known = {cid for cid, _digest in _payload_rows()}
    result = {"observed": 0, "removed": 0, "pending": 0}
    endpoints = [("primary", client.api_url), *client.pin_targets]
    for target_name, target_url in endpoints:
        target = client if target_url == client.api_url else IPFSClient(
            api_url=target_url, timeout=client.timeout, retries=client.retries,
            backoff=client.backoff, pin_targets=[],
        )
        try:
            pins = target.list_pins()
        except IPFSStorageError as exc:
            log.warning("Could not list pins on %s: %s", target_name, exc)
            result["pending"] += 1
            continue
        for cid in pins - known:
            result["observed"] += 1
            with db_cursor() as cur:
                cur.execute("""
                    INSERT INTO ipfs_orphans (cid, target)
                    VALUES (%s, %s)
                    ON CONFLICT (cid, target) DO UPDATE SET last_seen = now()
                    RETURNING EXTRACT(EPOCH FROM (now() - first_seen)) AS age
                """, (cid, target_name))
                age = float(cur.fetchone()["age"] or 0)
            if age < grace:
                continue
            try:
                target.unpin(cid)
                with db_cursor() as cur:
                    cur.execute("DELETE FROM ipfs_orphans WHERE cid = %s AND target = %s",
                                (cid, target_name))
                    cur.execute("""
                        INSERT INTO ipfs_pin_status (cid, target, status, last_checked_at, last_error)
                        VALUES (%s, %s, 'unpinned', now(), '')
                        ON CONFLICT (cid, target) DO UPDATE SET
                            status = 'unpinned', last_checked_at = now(), last_error = ''
                    """, (cid, target_name))
                result["removed"] += 1
            except IPFSStorageError as exc:
                log.warning("Could not unpin orphan %s from %s: %s", cid, target_name, exc)
                result["pending"] += 1
    return result


def run_scheduled_gc(client=None, now=None) -> int:
    """Run repository GC at most once per configured interval per target."""
    client = client or IPFSClient()
    interval = max(3600, int(os.getenv("IPFS_GC_INTERVAL_SECONDS", "86400")))
    current = now or datetime.now(timezone.utc)
    ran = 0
    for target_name, target_url in [("primary", client.api_url), *client.pin_targets]:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO ipfs_gc_state (target, last_gc_at)
                VALUES (%s, 'epoch') ON CONFLICT (target) DO NOTHING
            """, (target_name,))
            cur.execute("SELECT last_gc_at FROM ipfs_gc_state WHERE target = %s FOR UPDATE",
                        (target_name,))
            last_gc = cur.fetchone()["last_gc_at"]
            if (current - last_gc).total_seconds() < interval:
                continue
            target = client if target_url == client.api_url else IPFSClient(
                api_url=target_url, timeout=client.timeout, retries=client.retries,
                backoff=client.backoff, pin_targets=[],
            )
            try:
                target.repo_gc()
                cur.execute("UPDATE ipfs_gc_state SET last_gc_at = %s WHERE target = %s",
                            (current, target_name))
                ran += 1
            except IPFSStorageError as exc:
                log.warning("Kubo repo gc failed for %s: %s", target_name, exc)
    return ran


def run_once(client=None) -> dict[str, dict[str, int] | int]:
    init_db()
    client = client or IPFSClient()
    return {
        "legacy_migration": migrate_legacy_ciphertext(client),
        "pin_repair": repair_pins(client),
        "orphan_cleanup": cleanup_orphans(client),
        "gc_runs": run_scheduled_gc(client),
        "legacy_inline_remaining": legacy_inline_counts(),
    }


def main():
    interval = max(30, int(os.getenv("IPFS_MAINTENANCE_INTERVAL_SECONDS", "300")))
    init_db()
    client = IPFSClient()
    log.info("Private IPFS maintenance worker started; targets=%d", 1 + len(client.pin_targets))
    while True:
        try:
            log.info("Maintenance result: %s", {
                "legacy_migration": migrate_legacy_ciphertext(client),
                "pin_repair": repair_pins(client),
                "orphan_cleanup": cleanup_orphans(client),
                "gc_runs": run_scheduled_gc(client),
                "legacy_inline_remaining": legacy_inline_counts(),
            })
        except Exception:
            log.exception("IPFS maintenance cycle failed")
        time.sleep(interval)


if __name__ == "__main__":
    main()
