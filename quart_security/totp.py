"""TOTP and recovery-code helpers."""

from __future__ import annotations

import base64
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
    return [secrets.token_hex(4) for _ in range(n)]


def verify_recovery_code(code: str, stored_codes: list[str]) -> tuple[bool, list[str]]:
    if code in stored_codes:
        remaining = [item for item in stored_codes if item != code]
        return True, remaining
    return False, stored_codes
