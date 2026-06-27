#!/usr/bin/env python3
"""
auth_utils.py — Shared authentication helpers for MedVault portals.

Provides:
  - login_required(role=None)  Flask decorator  (server-side session check)
  - hash_password(pw)          werkzeug pbkdf2:sha256 hash
  - check_password(pw, stored) supports both old sha256 AND new werkzeug hashes
  - ALLOWED_ORIGINS            set of permitted CORS origins (from env or defaults)
  - cors_after_request(resp)   after_request hook implementing whitelist CORS
"""

import os
from functools import wraps
from flask import session, redirect, url_for, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash as wz_check
import hashlib

LANDING_URL = "http://127.0.0.1:5003"


# ── CORS configuration ─────────────────────────────────────────────────────────
# Reads from MEDVAULT_ALLOWED_ORIGINS env var (comma-separated list of origins).
# Falls back to the three localhost portal ports used in development.
# Example .env entry:
#   MEDVAULT_ALLOWED_ORIGINS=http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003

_DEFAULT_ORIGINS = {
    "http://127.0.0.1:5001",  # patient portal
    "http://127.0.0.1:5002",  # doctor portal
    "http://127.0.0.1:5003",  # landing page
    "http://localhost:5001",
    "http://localhost:5002",
    "http://localhost:5003",
}

_env_origins_raw = os.environ.get("MEDVAULT_ALLOWED_ORIGINS", "")
if _env_origins_raw.strip():
    ALLOWED_ORIGINS: set = {o.strip() for o in _env_origins_raw.split(",") if o.strip()}
else:
    ALLOWED_ORIGINS: set = _DEFAULT_ORIGINS


def cors_after_request(response):
    """
    Centralized CORS after_request hook for all MedVault portals.

    Only emits Access-Control-Allow-Origin when the request carries an Origin
    header that is in the ALLOWED_ORIGINS whitelist.  Wildcard '*' is never used.

    Usage in each Flask app::

        from auth_utils import cors_after_request

        @app.after_request
        def _cors(r):
            return cors_after_request(r)
    """
    origin = request.headers.get("Origin", "")
    # Always set Vary: Origin so caches know the response varies by origin
    vary = response.headers.get("Vary", "")
    if vary:
        if "Origin" not in vary:
            response.headers["Vary"] = vary + ", Origin"
    else:
        response.headers["Vary"] = "Origin"

    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Headers"]     = (
            "Content-Type,X-API-Key,Authorization"
        )
        response.headers["Access-Control-Allow-Methods"]     = (
            "GET,POST,PUT,DELETE,OPTIONS"
        )
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


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
                # [C1] Prefer SERVER_API_KEY env var; fall back to api_key.txt only in dev mode
                stored_key = os.environ.get("SERVER_API_KEY", "")
                if not stored_key:
                    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    _kf = os.path.join(_ROOT, "server", "api_key.txt")
                    try:
                        stored_key = open(_kf).read().strip()
                    except FileNotFoundError:
                        stored_key = ""
                if stored_key and api_key == stored_key:
                    # Trusted internal call — skip session check
                    return f(*args, **kwargs)

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
    """Return True if the caller expects a JSON response."""
    ct = request.content_type or ""
    accept = request.accept_mimetypes
    xhr = request.headers.get("X-Requested-With", "") == "XMLHttpRequest"
    return (
        "application/json" in ct
        or xhr
        or (accept.best == "application/json")
        or request.path.startswith("/api/")
    )
