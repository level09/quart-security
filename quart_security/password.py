"""Password hashing and validation helpers."""

from passlib.context import CryptContext

_pwd_context: CryptContext | None = None
_password_salt: str | None = None


def init_password_context(app):
    """Initialize passlib context from app config."""
    global _pwd_context, _password_salt

    scheme = app.config.get("SECURITY_PASSWORD_HASH", "pbkdf2_sha512")
    _password_salt = app.config.get("SECURITY_PASSWORD_SALT")
    _pwd_context = CryptContext(schemes=[scheme], deprecated="auto")


def _ensure_context() -> CryptContext:
    if _pwd_context is None:
        raise RuntimeError("Password context is not initialized")
    return _pwd_context


def hash_password(password: str) -> str:
    # Keep default behavior compatible with existing Flask-Security hashes.
    return _ensure_context().hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    context = _ensure_context()
    if context.verify(password, password_hash):
        return True
    # Optional fallback for deployments that previously mixed in app salt.
    if _password_salt:
        return context.verify(f"{password}{_password_salt}", password_hash)
    return False


def validate_password(password: str, min_length: int = 12) -> list[str]:
    errors: list[str] = []
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters")
    return errors
