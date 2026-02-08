from quart_security.password import hash_password, validate_password, verify_password


def test_hash_and_verify(app):
    hashed = hash_password("abcdefgh")
    assert hashed != "abcdefgh"
    assert verify_password("abcdefgh", hashed)
    assert not verify_password("abcdefghx", hashed)


def test_validate_password_length():
    errors = validate_password("short", min_length=8)
    assert errors
    assert "at least 8" in errors[0]
