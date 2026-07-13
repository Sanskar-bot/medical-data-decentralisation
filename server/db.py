"""
server/db.py — PostgreSQL connection pool and helpers.

All database access goes through this module.
Never import psycopg2 directly elsewhere.
"""
import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_pool: pool.ThreadedConnectionPool = None


def _apply_schema_migrations(conn):
    """Apply the repository schema files in an idempotent way.

    Uses a Postgres advisory lock (lock id 987654321) so that only ONE gunicorn
    worker runs the migrations even when all workers boot simultaneously.
    Workers that don't win the lock skip silently — the winning worker already
    applied everything.

    Each file is applied in its own transaction so a failure in one file does
    not roll back already-applied migrations.
    """
    # Try to acquire a session-level advisory lock — non-blocking.
    # If another worker already holds it, skip and let them do the work.
    LOCK_ID = 987654321
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_ID,))
        acquired = cur.fetchone()[0]

    if not acquired:
        logger.info("[DB] Migration lock held by another worker — skipping.")
        return

    try:
        schema_path = Path(__file__).with_name("schema.sql")
        additions_path = Path(__file__).with_name("schema_additions.sql")
        for path in (schema_path, additions_path):
            if not path.exists():
                continue
            sql = path.read_text(encoding="utf-8")
            if not sql.strip():
                continue
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                conn.commit()
                logger.info(f"[DB] Applied migration: {path.name}")
            except Exception as migration_err:
                conn.rollback()
                logger.warning(
                    f"[DB] Migration {path.name} failed (may already be applied): {migration_err}"
                )
    finally:
        # Always release the advisory lock when done.
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
        conn.commit()


def init_db(database_url: str = None):
    """
    Initialize the connection pool. Call once at server startup.
    Raises RuntimeError if connection fails.
    """
    global _pool
    url = database_url or os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError(
            "DATABASE_URL not set. Add it to .env or set as environment variable."
        )
    try:
        _pool = pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            dsn=url
        )
        conn = _pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            _apply_schema_migrations(conn)
        finally:
            _pool.putconn(conn)
        logger.info("[DB] PostgreSQL connection pool initialized.")
    except Exception as e:
        raise RuntimeError(f"[DB] Failed to connect to PostgreSQL: {e}")


def get_conn():
    """Get a connection from the pool."""
    if _pool is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _pool.getconn()


def put_conn(conn):
    """Return a connection to the pool."""
    if _pool and conn:
        _pool.putconn(conn)


class db_cursor:
    """
    Context manager for database operations.

    Usage:
        with db_cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            return cur.fetchone()

    Commits on success, rolls back on exception.
    Always uses RealDictCursor so rows are dicts.
    """
    def __init__(self, commit=True):
        self.commit = commit
        self.conn = None
        self.cur = None

    def __enter__(self):
        self.conn = get_conn()
        self.cur = self.conn.cursor(cursor_factory=RealDictCursor)
        return self.cur

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.conn.rollback()
            logger.error(f"[DB] Transaction rolled back: {exc_val}")
        elif self.commit:
            self.conn.commit()
        self.cur.close()
        put_conn(self.conn)
        return False  # do not suppress exceptions
