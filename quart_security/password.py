"""Password hashing and validation helpers."""

import asyncio

from passlib.context import CryptContext
from quart import current_app

# OWASP 2025 minimum argon2id parameters
_ARGON2_MEMORY_COST = 19456  # KiB
_ARGON2_TIME_COST = 2
_ARGON2_PARALLELISM = 1


def init_password_context(app):
    """Initialize passlib context from app config.

    Default scheme is argon2id (OWASP 2025). Existing pbkdf2_sha512 and bcrypt
    hashes continue to verify and are transparently rehashed on next login when
    password_needs_rehash() returns True.

    Set SECURITY_PASSWORD_HASH to override the default scheme.
    Set SECURITY_ARGON2_MEMORY_COST / _TIME_COST / _PARALLELISM to override
    argon2 parameters (useful for test environments).
    """
    scheme = app.config.get("SECURITY_PASSWORD_HASH", "argon2")

    memory_cost = app.config.get("SECURITY_ARGON2_MEMORY_COST", _ARGON2_MEMORY_COST)
    time_cost = app.config.get("SECURITY_ARGON2_TIME_COST", _ARGON2_TIME_COST)
    parallelism = app.config.get("SECURITY_ARGON2_PARALLELISM", _ARGON2_PARALLELISM)

    # Build context: argon2 with OWASP params, legacy schemes deprecated.
    # CryptContext handles per-scheme kwargs via <scheme>__<param> notation.
    context = CryptContext(
        schemes=["argon2", "pbkdf2_sha512", "bcrypt"],
        default=scheme,
        deprecated="auto",
        argon2__memory_cost=memory_cost,
        argon2__time_cost=time_cost,
        argon2__parallelism=parallelism,
        argon2__type="id",
    )
    app.extensions["quart_security_password"] = (
        context,
        app.config.get("SECURITY_PASSWORD_SALT"),
    )


def _password_config(app=None):
    return (app or current_app).extensions["quart_security_password"]


def hash_password(password: str, *, app=None) -> str:
    context, _salt = _password_config(app)
    return context.hash(password)


def verify_password(password: str, password_hash: str, *, app=None) -> bool:
    context, salt = _password_config(app)
    if context.verify(password, password_hash):
        return True
    # Optional fallback for deployments that previously mixed in app salt.
    if salt:
        return context.verify(f"{password}{salt}", password_hash)
    return False


def password_needs_rehash(password_hash: str, *, app=None) -> bool:
    """Return True if the hash was made with a deprecated/weaker scheme.

    Call this after a successful verify to decide whether to upgrade the
    stored hash transparently on login.
    """
    context, _salt = _password_config(app)
    return context.needs_update(password_hash)


async def hash_password_async(password: str, *, app=None) -> str:
    return await asyncio.to_thread(hash_password, password, app=app)


async def verify_password_async(password: str, password_hash: str, *, app=None) -> bool:
    return await asyncio.to_thread(verify_password, password, password_hash, app=app)


def validate_password(password: str, min_length: int = 12) -> list[str]:
    errors: list[str] = []
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters")
    return errors
