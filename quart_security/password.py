"""Password hashing and validation helpers."""

import asyncio

from passlib.context import CryptContext

_pwd_context: CryptContext | None = None
_password_salt: str | None = None

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
    global _pwd_context, _password_salt

    scheme = app.config.get("SECURITY_PASSWORD_HASH", "argon2")
    _password_salt = app.config.get("SECURITY_PASSWORD_SALT")

    memory_cost = app.config.get("SECURITY_ARGON2_MEMORY_COST", _ARGON2_MEMORY_COST)
    time_cost = app.config.get("SECURITY_ARGON2_TIME_COST", _ARGON2_TIME_COST)
    parallelism = app.config.get("SECURITY_ARGON2_PARALLELISM", _ARGON2_PARALLELISM)

    # Build context: argon2 with OWASP params, legacy schemes deprecated.
    # CryptContext handles per-scheme kwargs via <scheme>__<param> notation.
    _pwd_context = CryptContext(
        schemes=["argon2", "pbkdf2_sha512", "bcrypt"],
        default=scheme,
        deprecated="auto",
        argon2__memory_cost=memory_cost,
        argon2__time_cost=time_cost,
        argon2__parallelism=parallelism,
        argon2__type="id",
    )


def _ensure_context() -> CryptContext:
    if _pwd_context is None:
        raise RuntimeError("Password context is not initialized")
    return _pwd_context


def hash_password(password: str) -> str:
    return _ensure_context().hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    context = _ensure_context()
    if context.verify(password, password_hash):
        return True
    # Optional fallback for deployments that previously mixed in app salt.
    if _password_salt:
        return context.verify(f"{password}{_password_salt}", password_hash)
    return False


def password_needs_rehash(password_hash: str) -> bool:
    """Return True if the hash was made with a deprecated/weaker scheme.

    Call this after a successful verify to decide whether to upgrade the
    stored hash transparently on login.
    """
    return _ensure_context().needs_update(password_hash)


async def hash_password_async(password: str) -> str:
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, password_hash: str) -> bool:
    return await asyncio.to_thread(verify_password, password, password_hash)


def validate_password(password: str, min_length: int = 12) -> list[str]:
    errors: list[str] = []
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters")
    return errors
