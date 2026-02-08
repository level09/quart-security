"""Utility helpers."""

from quart import url_for


def url_for_security(endpoint, **kwargs):
    """Flask-Security-compatible helper for endpoint URLs."""
    return url_for(f"security.{endpoint}", **kwargs)
