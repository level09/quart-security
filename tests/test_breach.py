"""Tests for the HIBP k-anonymity breach check."""

import hashlib

import httpx
import pytest
import respx

from quart_security.breach import password_is_breached


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
@respx.mock
async def test_breached_password():
    """Password present in HIBP response returns True."""
    body = f"{_SUFFIX_BREACHED}:42\nDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:1\n"
    respx.get(f"https://api.pwnedpasswords.com/range/{_PREFIX_BREACHED}").mock(
        return_value=httpx.Response(200, text=body)
    )
    result = await password_is_breached(BREACHED_PW, count_min=1)
    assert result is True


@pytest.mark.asyncio
@respx.mock
async def test_breached_password_below_count_min():
    """Password present but below threshold returns False."""
    body = f"{_SUFFIX_BREACHED}:2\n"
    respx.get(f"https://api.pwnedpasswords.com/range/{_PREFIX_BREACHED}").mock(
        return_value=httpx.Response(200, text=body)
    )
    result = await password_is_breached(BREACHED_PW, count_min=5)
    assert result is False


@pytest.mark.asyncio
@respx.mock
async def test_clean_password():
    """Password absent from HIBP response returns False."""
    body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:999\n"
    respx.get(f"https://api.pwnedpasswords.com/range/{_PREFIX_CLEAN}").mock(
        return_value=httpx.Response(200, text=body)
    )
    result = await password_is_breached(CLEAN_PW)
    assert result is False


@pytest.mark.asyncio
@respx.mock
async def test_network_error_fails_open():
    """Network error returns None (fail-open)."""
    respx.get(f"https://api.pwnedpasswords.com/range/{_PREFIX_BREACHED}").mock(
        side_effect=httpx.ConnectError("unreachable")
    )
    result = await password_is_breached(BREACHED_PW)
    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_http_error_fails_open():
    """Non-2xx HTTP response returns None (fail-open)."""
    respx.get(f"https://api.pwnedpasswords.com/range/{_PREFIX_BREACHED}").mock(
        return_value=httpx.Response(503, text="Service Unavailable")
    )
    result = await password_is_breached(BREACHED_PW)
    assert result is None
