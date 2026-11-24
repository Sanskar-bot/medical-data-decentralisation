#!/usr/bin/env python3
"""
server/create_admin.py - create the first (or another) MedVault admin account.

Admins can no longer self-register. Run this on the server host:

    python server/create_admin.py --email admin@example.org --username admin --name "Site Admin"

The password is read from the MEDVAULT_ADMIN_PASSWORD environment variable if it
is set, otherwise it is asked for interactively. It must be at least 12 characters.
"""
import argparse
import getpass
import os
import sys
import uuid

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

from werkzeug.security import generate_password_hash  # noqa: E402

MIN_PASSWORD_LENGTH = 12


def create_admin(email: str, username: str, name: str, password: str) -> str:
    """Insert an admin row and return its id. Raises ValueError on bad input."""
    from db import init_db, db_cursor
    email = (email or "").strip().lower()
    username = (username or "").strip().lower()
    name = (name or "").strip()
    if not email or "@" not in email:
        raise ValueError("a valid --email is required")
    if not username:
        raise ValueError("--username is required")
    if not name:
        raise ValueError("--name is required")
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    init_db()
    uid = str(uuid.uuid4())
    with db_cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE email = %s OR lower(username) = %s",
                    (email, username))
        if cur.fetchone():
            raise ValueError("a user with this email or username already exists")
        cur.execute(
            """INSERT INTO users (id, email, username, name, role, password_hash)
               VALUES (%s, %s, %s, %s, 'admin', %s)""",
            (uid, email, username, name,
             generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)),
        )
        cur.execute(
            "INSERT INTO audit_log (action, actor, target, detail) VALUES (%s, %s, %s, %s)",
            ("admin_created_cli", "cli", email, "created by server/create_admin.py"),
        )
    return uid


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Create a MedVault admin account.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args(argv)
    password = os.environ.get("MEDVAULT_ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
    try:
        uid = create_admin(args.email, args.username, args.name, password)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"admin created: {uid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
