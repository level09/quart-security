"""Utility helpers."""

from __future__ import annotations

import datetime
import inspect
import unicodedata

from email_validator import EmailNotValidError, validate_email
from quart import url_for


def url_for_security(endpoint, **kwargs):
    """Flask-Security-compatible helper for endpoint URLs."""
    return url_for(f"security.{endpoint}", **kwargs)


async def maybe_await(value):
    """Await values when needed while supporting sync extension hooks."""
    if inspect.isawaitable(value):
        return await value
    return value


def normalize_email(value: str | None) -> str:
    """One form per mailbox: lowercased, Unicode NFC, IDNA domains decoded.

    Lowercasing first keeps it idempotent: lowering an NFC string can leave one
    that is not NFC.
    """
    value = unicodedata.normalize("NFC", (value or "").strip().lower())
    try:
        return validate_email(value, check_deliverability=False).normalized
    except EmailNotValidError:
        return value  # not an address; it can only fail to match one


def naive_utcnow() -> datetime.datetime:
    """Return a naive UTC datetime while avoiding utcnow() deprecations."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
