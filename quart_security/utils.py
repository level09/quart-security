"""Utility helpers."""

from __future__ import annotations

import datetime
import inspect

from quart import url_for


def url_for_security(endpoint, **kwargs):
    """Flask-Security-compatible helper for endpoint URLs."""
    return url_for(f"security.{endpoint}", **kwargs)


async def maybe_await(value):
    """Await values when needed while supporting sync extension hooks."""
    if inspect.isawaitable(value):
        return await value
    return value


def naive_utcnow() -> datetime.datetime:
    """Return a naive UTC datetime while avoiding utcnow() deprecations."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
