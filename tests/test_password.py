import pytest

from quart_security.password import (
    hash_password,
    hash_password_async,
    validate_password,
    verify_password,
    verify_password_async,
)


def test_hash_and_verify(app):
    hashed = hash_password("abcdefgh")
    assert hashed != "abcdefgh"
    assert verify_password("abcdefgh", hashed)
    assert not verify_password("abcdefghx", hashed)


def test_validate_password_length():
    errors = validate_password("short", min_length=8)
    assert errors
    assert "at least 8" in errors[0]


@pytest.mark.asyncio
async def test_async_hash_and_verify(app):
    hashed = await hash_password_async("asyncpassword")
    assert hashed != "asyncpassword"
    assert await verify_password_async("asyncpassword", hashed)
    assert not await verify_password_async("wrong", hashed)


@pytest.mark.asyncio
async def test_async_variants_consistent_with_sync(app):
    sync_hash = hash_password("consistencytest")
    assert await verify_password_async("consistencytest", sync_hash)

    async_hash = await hash_password_async("consistencytest")
    assert verify_password("consistencytest", async_hash)
