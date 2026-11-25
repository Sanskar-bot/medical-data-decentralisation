"""Shared expiry rules for doctor wrapped-key grants."""

from __future__ import annotations

import math
import os
import re
from datetime import datetime, timedelta, timezone


def active_wrapped_key_sql(alias: str | None = None) -> str:
    """SQL predicate requiring an explicit, future wrapped-key expiry."""
    if alias is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
        raise ValueError("SQL alias must be a static identifier")
    column = f"{alias}.temp_key_expires_at" if alias else "temp_key_expires_at"
    return f"{column} IS NOT NULL AND {column} > now()"


def parse_expiry(value) -> datetime | None:
    """Parse a timestamp as UTC; malformed or missing values fail closed."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def wrapped_key_expiry_is_active(value, *, now: datetime | None = None) -> bool:
    expires_at = parse_expiry(value)
    if expires_at is None:
        return False
    now = parse_expiry(now) if now is not None else datetime.now(timezone.utc)
    return bool(now and expires_at > now)


def configured_wrapped_key_expiry(value=None, *, now: datetime | None = None) -> datetime:
    """Return a valid supplied expiry or a configurable 24-hour default."""
    expires_at = parse_expiry(value)
    if expires_at is not None:
        return expires_at

    raw_ttl = os.getenv("WRAPPED_KEY_TTL_HOURS", "24")
    try:
        ttl_hours = float(raw_ttl)
    except ValueError as exc:
        raise ValueError("WRAPPED_KEY_TTL_HOURS must be a positive number") from exc
    if not math.isfinite(ttl_hours) or ttl_hours <= 0:
        raise ValueError("WRAPPED_KEY_TTL_HOURS must be a positive number")

    base = parse_expiry(now) if now is not None else datetime.now(timezone.utc)
    return base + timedelta(hours=ttl_hours)
