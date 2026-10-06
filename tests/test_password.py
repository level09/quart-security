import passlib.hash as ph
import pytest

from quart_security.password import (
    hash_password,
    hash_password_async,
    password_needs_rehash,
    validate_password,
    verify_password,
    verify_password_async,
)


def test_hash_and_verify(app):
    hashed = hash_password("abcdefgh", app=app)
    assert hashed != "abcdefgh"
    assert verify_password("abcdefgh", hashed, app=app)
    assert not verify_password("abcdefghx", hashed, app=app)


def test_default_scheme_is_argon2id(app):
    hashed = hash_password("anypassword", app=app)
    assert hashed.startswith("$argon2id$")


def test_validate_password_length():
    errors = validate_password("short", min_length=8)
    assert errors
    assert "at least 8" in errors[0]


@pytest.mark.asyncio
async def test_async_hash_and_verify(app):
    hashed = await hash_password_async("asyncpassword", app=app)
    assert hashed != "asyncpassword"
    assert await verify_password_async("asyncpassword", hashed, app=app)
    assert not await verify_password_async("wrong", hashed, app=app)


@pytest.mark.asyncio
async def test_async_variants_consistent_with_sync(app):
    sync_hash = hash_password("consistencytest", app=app)
    assert await verify_password_async("consistencytest", sync_hash, app=app)

    async_hash = await hash_password_async("consistencytest", app=app)
    assert verify_password("consistencytest", async_hash, app=app)


def test_pbkdf2_hash_still_verifies(app):
    """Legacy pbkdf2_sha512 hashes must verify against the new context."""
    old_hash = ph.pbkdf2_sha512.hash("legacypassword")
    assert verify_password("legacypassword", old_hash, app=app)


def test_pbkdf2_hash_needs_rehash(app):
    """Legacy pbkdf2_sha512 hashes must be flagged for upgrade."""
    old_hash = ph.pbkdf2_sha512.hash("legacypassword")
    assert password_needs_rehash(old_hash, app=app) is True


def test_argon2_hash_does_not_need_rehash(app):
    """A freshly created argon2id hash must not trigger a rehash."""
    fresh_hash = hash_password("freshpassword", app=app)
    assert password_needs_rehash(fresh_hash, app=app) is False


def test_bcrypt_legacy_hash_verifies_and_needs_rehash(app):
    legacy = ph.bcrypt.using(rounds=4).hash("bcrypt-legacy-password")
    assert verify_password("bcrypt-legacy-password", legacy, app=app)
    assert password_needs_rehash(legacy, app=app)
