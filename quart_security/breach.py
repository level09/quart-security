"""HIBP k-anonymity breach check (NIST 800-63B-4 SHALL)."""

from __future__ import annotations

import hashlib
import logging

import httpx

logger = logging.getLogger(__name__)

_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_TIMEOUT = 3.0


async def password_is_breached(password: str, *, count_min: int = 1) -> bool | None:
    """Check whether *password* appears in the HIBP breach corpus.

    Uses the k-anonymity range API: sends only the first 5 hex chars of the
    SHA-1 digest. The full digest never leaves the process.

    Returns:
        True  - password appears >= count_min times.
        False - password not found in response.
        None  - network/HTTP error; caller should fail-open (allow the password).
    """
    sha1 = (
        hashlib.sha1(password.encode("utf-8"), usedforsecurity=False)
        .hexdigest()
        .upper()
    )
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(
                _HIBP_URL.format(prefix=prefix),
                headers={"Add-Padding": "true"},
            )
            response.raise_for_status()
    except Exception as exc:
        logger.warning(
            "HIBP breach check failed (%s: %s); failing open",
            type(exc).__name__,
            exc,
        )
        return None

    for line in response.text.splitlines():
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        candidate, raw_count = parts[0].strip(), parts[1].strip()
        if candidate == suffix:
            try:
                count = int(raw_count)
            except ValueError:
                continue
            return count >= count_min

    return False
