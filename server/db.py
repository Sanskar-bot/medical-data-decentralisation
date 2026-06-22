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

logger = logging.getLogger(__name__)

_pool: pool.ThreadedConnectionPool = None


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
        # verify connection works
        conn = _pool.getconn()
        conn.cursor().execute("SELECT 1")
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
