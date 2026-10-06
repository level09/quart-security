import pytest
from cryptography.fernet import Fernet, InvalidToken
from quart import Quart

from quart_security.totp import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    init_totp_encryption,
)


def test_cipher_rejects_tampering_wrong_key_and_supports_rotation():
    app = Quart(__name__)
    old, new = Fernet.generate_key(), Fernet.generate_key()
    app.config["SECURITY_TOTP_ENCRYPTION_KEYS"] = [old]
    init_totp_encryption(app)
    encrypted = encrypt_totp_secret("JBSWY3DPEHPK3PXP", app=app)
    assert "JBSWY3DPEHPK3PXP" not in encrypted
    assert decrypt_totp_secret(encrypted, app=app) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(InvalidToken):
        decrypt_totp_secret(encrypted[:-8] + "AAAAAAAA", app=app)
    app.config["SECURITY_TOTP_ENCRYPTION_KEYS"] = [new, old]
    init_totp_encryption(app)
    rotated = encrypt_totp_secret(encrypted, app=app)
    app.config["SECURITY_TOTP_ENCRYPTION_KEYS"] = [new]
    init_totp_encryption(app)
    assert decrypt_totp_secret(rotated, app=app) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(InvalidToken):
        decrypt_totp_secret(encrypted, app=app)


def test_default_key_is_application_scoped_and_legacy_is_readable():
    first, second = Quart("first"), Quart("second")
    first.secret_key, second.secret_key = "first-secret", "second-secret"
    init_totp_encryption(first)
    init_totp_encryption(second)
    encrypted = encrypt_totp_secret("JBSWY3DPEHPK3PXP", app=first)
    with pytest.raises(InvalidToken):
        decrypt_totp_secret(encrypted, app=second)
    assert decrypt_totp_secret("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"


async def test_encrypted_seed_works_with_public_totp_helpers():
    import pyotp

    from quart_security.totp import get_totp_uri, verify_totp

    app = Quart("totp-helpers")
    app.secret_key = "helper-secret"
    init_totp_encryption(app)
    secret = pyotp.random_base32()
    encrypted = encrypt_totp_secret(secret, app=app)
    async with app.app_context():
        assert verify_totp(encrypted, pyotp.TOTP(secret).now())
        assert secret in get_totp_uri(encrypted, "user@example.com", "fixture")
