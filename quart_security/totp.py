"""TOTP and recovery-code helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets


def _require_pyotp():
    try:
        import pyotp
    except ImportError as exc:
        raise RuntimeError("pyotp is required for TOTP support") from exc
    return pyotp


def generate_totp_secret() -> str:
    pyotp = _require_pyotp()
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str) -> str:
    pyotp = _require_pyotp()
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def generate_qr_code(uri: str) -> str:
    try:
        import qrcode
    except ImportError as exc:
        raise RuntimeError("qrcode is required for QR generation") from exc

    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64}"


def verify_totp(secret: str, token: str) -> bool:
    pyotp = _require_pyotp()
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(token, valid_window=1))


def generate_recovery_codes(n: int = 3) -> list[str]:
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(5)
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


_RECOVERY_HASH_PREFIX = "hmac-sha256$"


def _normalize_recovery_code(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def _recovery_digest(code: str, secret_key: bytes | str) -> str:
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    digest = hmac.new(
        secret_key, _normalize_recovery_code(code).encode(), hashlib.sha256
    ).hexdigest()
    return f"{_RECOVERY_HASH_PREFIX}{digest}"


def hash_recovery_codes(codes: list[str], secret_key: bytes | str) -> list[str]:
    return [_recovery_digest(code, secret_key) for code in codes]


def ensure_hashed_recovery_codes(
    codes: list[str], secret_key: bytes | str
) -> list[str]:
    return [
        code if is_hashed_recovery_code(code) else _recovery_digest(code, secret_key)
        for code in codes
    ]


def is_hashed_recovery_code(code: str) -> bool:
    return code.startswith(_RECOVERY_HASH_PREFIX)


def verify_recovery_code(
    code: str, stored_codes: list[str], *, secret_key: bytes | str = b""
) -> tuple[bool, list[str]]:
    normalized = code.strip().lower().replace("-", "").replace(" ", "")
    submitted_hash = _recovery_digest(code, secret_key)
    matched_index = -1
    for i, stored in enumerate(stored_codes):
        stored_normalized = _normalize_recovery_code(stored)
        # compare_digest on every entry — no early exit
        matches_plaintext = not is_hashed_recovery_code(
            stored
        ) and secrets.compare_digest(normalized, stored_normalized)
        matches_hash = is_hashed_recovery_code(stored) and secrets.compare_digest(
            submitted_hash, stored
        )
        if matches_plaintext or matches_hash:
            matched_index = i
    if matched_index >= 0:
        remaining = [item for i, item in enumerate(stored_codes) if i != matched_index]
        return True, remaining
    return False, stored_codes
