#!/usr/bin/env python3
"""
auth_utils.py — Shared authentication helpers for MedVault portals.

Provides:
  - login_required(role=None)  Flask decorator  (server-side session check)
  - hash_password(pw)          werkzeug pbkdf2:sha256 hash
  - check_password(pw, stored) supports both old sha256 AND new werkzeug hashes
"""

from functools import wraps
from flask import session, redirect, url_for, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash as wz_check
import hashlib

LANDING_URL = "http://127.0.0.1:5003"


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(raw: str) -> str:
    """Return a werkzeug pbkdf2:sha256 hash of *raw*."""
    return generate_password_hash(raw, method="pbkdf2:sha256", salt_length=16)


def check_password(raw: str, stored: str) -> bool:
    """
    Verify *raw* against *stored*.

    Handles two hash formats:
      1. werkzeug  — stored starts with "pbkdf2:sha256:"
      2. legacy    — plain hex SHA-256 (64 chars)
    """
    if not raw or not stored:
        return False

    # New-style werkzeug hash
    if stored.startswith("pbkdf2:sha256:") or stored.startswith("scrypt:"):
        return wz_check(stored, raw)

    # Legacy SHA-256 hex
    return hashlib.sha256(raw.encode()).hexdigest() == stored


# ── Route protection decorator ────────────────────────────────────────────────

def login_required(role: str | None = None):
    """
    Decorator that enforces Flask-session authentication.

    Also accepts a valid ``X-API-Key`` header as proof of authentication
    (used by landing.py when proxying requests to doctor_portal.py).

    Usage::

        @app.route("/api/something")
        @login_required(role="patient")
        def something():
            ...

    If the request is a plain browser GET (not XHR), the user is redirected to
    the landing page.  JSON/XHR callers receive a 401 JSON response so the
    front-end can handle it gracefully.

    Args:
        role: If given, also verifies session["role"] matches.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # ── Allow API-key authenticated requests (from landing.py proxy) ──
            api_key = request.headers.get("X-API-Key", "")
            if api_key:
                import os
                _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                _kf = os.path.join(_ROOT, "server", "api_key.txt")
                try:
                    stored_key = open(_kf).read().strip()
                    if api_key == stored_key:
                        # Trusted internal call — skip session check
                        return f(*args, **kwargs)
                except FileNotFoundError:
                    pass

            if not session.get("logged_in"):
                if _is_json_request():
                    return jsonify({"error": "unauthenticated", "login_url": LANDING_URL}), 401
                return redirect(LANDING_URL)

            if role and session.get("role") != role:
                if _is_json_request():
                    return jsonify({"error": "forbidden", "required_role": role}), 403
                return redirect(LANDING_URL)

            return f(*args, **kwargs)
        return wrapper
    return decorator


def _is_json_request() -> bool:
    """True when the caller expects a JSON response (API / XHR call)."""
    accept = request.headers.get("Accept", "")
    content_type = request.headers.get("Content-Type", "")
    return (
        "application/json" in accept
        or "application/json" in content_type
        or request.path.startswith("/api/")
        or request.is_json
    )
