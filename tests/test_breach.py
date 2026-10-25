"""Tests for the HIBP k-anonymity breach check."""

import hashlib
from unittest.mock import patch

import httpx2
import pytest

from quart_security.breach import password_is_breached

_REAL_CLIENT = httpx2.AsyncClient


def _hibp(prefix, respond):
    """Serve the HIBP range for *prefix* with *respond(request)*, in process."""

    def handler(request):
        assert str(request.url) == f"https://api.pwnedpasswords.com/range/{prefix}"
        return respond(request)

    transport = httpx2.MockTransport(handler)
    return patch(
        "quart_security.breach.httpx2.AsyncClient",
        lambda **kwargs: _REAL_CLIENT(transport=transport, **kwargs),
    )


def _sha1_parts(password: str) -> tuple[str, str]:
    sha1 = (
        hashlib.sha1(password.encode("utf-8"), usedforsecurity=False)
        .hexdigest()
        .upper()
    )
    return sha1[:5], sha1[5:]


BREACHED_PW = "password123"
CLEAN_PW = "xK9!mQ2#pL5@zR7"

_PREFIX_BREACHED, _SUFFIX_BREACHED = _sha1_parts(BREACHED_PW)
_PREFIX_CLEAN, _SUFFIX_CLEAN = _sha1_parts(CLEAN_PW)


@pytest.mark.asyncio
async def test_breached_password():
    """Password present in HIBP response returns True."""
    body = f"{_SUFFIX_BREACHED}:42\nDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:1\n"
    with _hibp(_PREFIX_BREACHED, lambda request: httpx2.Response(200, text=body)):
        result = await password_is_breached(BREACHED_PW, count_min=1)
    assert result is True


@pytest.mark.asyncio
async def test_breached_password_below_count_min():
    """Password present but below threshold returns False."""
    body = f"{_SUFFIX_BREACHED}:2\n"
    with _hibp(_PREFIX_BREACHED, lambda request: httpx2.Response(200, text=body)):
        result = await password_is_breached(BREACHED_PW, count_min=5)
    assert result is False


@pytest.mark.asyncio
async def test_clean_password():
    """Password absent from HIBP response returns False."""
    body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:999\n"
    with _hibp(_PREFIX_CLEAN, lambda request: httpx2.Response(200, text=body)):
        result = await password_is_breached(CLEAN_PW)
    assert result is False


@pytest.mark.asyncio
async def test_network_error_fails_open():
    """Network error returns None (fail-open)."""

    def unreachable(request):
        raise httpx2.ConnectError("unreachable", request=request)

    with _hibp(_PREFIX_BREACHED, unreachable):
        result = await password_is_breached(BREACHED_PW)
    assert result is None


@pytest.mark.asyncio
async def test_http_error_fails_open():
    """Non-2xx HTTP response returns None (fail-open)."""
    with _hibp(
        _PREFIX_BREACHED,
        lambda request: httpx2.Response(503, text="Service Unavailable"),
    ):
        result = await password_is_breached(BREACHED_PW)
    assert result is None
