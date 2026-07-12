import pytest

from quart_security import totp
from quart_security.totp import (
    ensure_hashed_recovery_codes,
    hash_recovery_codes,
    is_hashed_recovery_code,
    verify_recovery_code,
)


@pytest.mark.asyncio
async def test_two_factor_setup_enables_totp_and_recovery_codes(
    client_two_factor, app_two_factor, monkeypatch
):
    user = app_two_factor.extensions["test_basic_user"]

    monkeypatch.setattr(totp, "generate_totp_secret", lambda: "test-secret")
    monkeypatch.setattr(
        totp,
        "get_totp_uri",
        lambda secret, email, issuer: "otpauth://totp/test",
    )
    monkeypatch.setattr(totp, "generate_qr_code", lambda uri: "qr-data")
    monkeypatch.setattr(
        totp,
        "verify_totp",
        lambda secret, token: secret == "test-secret" and token == "123456",
    )

    await client_two_factor.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    get_response = await client_two_factor.get("/tf-setup?setup=authenticator")
    assert get_response.status_code == 200

    post_response = await client_two_factor.post(
        "/tf-setup",
        form={"action": "verify", "token": "123456"},
    )

    assert post_response.status_code == 200
    assert "Recovery codes" in await post_response.get_data(as_text=True)
    assert user.tf_primary_method == "authenticator"
    assert user.tf_totp_secret == "test-secret"
    assert (
        len(user.mf_recovery_codes or [])
        == app_two_factor.config["SECURITY_MULTI_FACTOR_RECOVERY_CODES_N"]
    )


@pytest.mark.asyncio
async def test_login_requires_second_factor_then_allows_access(
    client_two_factor, app_two_factor, monkeypatch
):
    user = app_two_factor.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    user.tf_totp_secret = "existing-secret"

    monkeypatch.setattr(
        totp,
        "verify_totp",
        lambda secret, token: secret == "existing-secret" and token == "123456",
    )

    login = await client_two_factor.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert login.status_code == 302
    assert login.headers["Location"].endswith("/tf-validate")

    protected = await client_two_factor.get("/protected")
    assert protected.status_code == 302
    assert "/login" in protected.headers["Location"]

    invalid_code = await client_two_factor.post(
        "/tf-validate", form={"token": "000000"}
    )
    assert invalid_code.status_code == 200

    valid_code = await client_two_factor.post("/tf-validate", form={"token": "123456"})
    assert valid_code.status_code == 302
    assert valid_code.headers["Location"].endswith("/protected")

    protected_after = await client_two_factor.get("/protected")
    assert protected_after.status_code == 200


@pytest.mark.asyncio
async def test_two_factor_recovery_code_login_consumes_code(
    client_two_factor, app_two_factor
):
    user = app_two_factor.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    user.tf_totp_secret = None
    user.mf_recovery_codes = ["recovery-1"]

    login = await client_two_factor.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    assert login.status_code == 302
    assert login.headers["Location"].endswith("/tf-validate")

    recovery = await client_two_factor.post(
        "/tf-validate",
        form={"token": "recovery-1"},
    )
    assert recovery.status_code == 302
    assert recovery.headers["Location"].endswith("/protected")
    assert user.mf_recovery_codes == []


@pytest.mark.asyncio
async def test_invalid_second_factor_increments_account_failures(
    client_two_factor, app_two_factor
):
    user = app_two_factor.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    user.tf_totp_secret = "JBSWY3DPEHPK3PXP"

    await client_two_factor.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    await client_two_factor.post("/tf-validate", form={"token": "000000"})

    assert user.failed_login_count == 1


@pytest.mark.asyncio
async def test_expired_second_factor_state_requires_login(
    client_two_factor, app_two_factor
):
    user = app_two_factor.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    async with client_two_factor.session_transaction() as sess:
        sess["tf_user_id"] = {"user_id": user.fs_uniquifier, "issued_at": 0}

    response = await client_two_factor.get("/tf-validate")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_verify_recovery_code_constant_time_valid():
    codes = ["ab12c-de34f", "fg56h-ij78k"]
    ok, remaining = verify_recovery_code("ab12c-de34f", codes)
    assert ok is True
    assert remaining == ["fg56h-ij78k"]


def test_verify_recovery_code_constant_time_invalid():
    codes = ["ab12c-de34f", "fg56h-ij78k"]
    ok, remaining = verify_recovery_code("zzzzz-zzzzz", codes)
    assert ok is False
    assert remaining == codes


def test_verify_recovery_code_all_entries_checked():
    """Verify the last code in the list is found (ensures no early exit skips it)."""
    codes = ["ab12c-de34f", "fg56h-ij78k", "target-code1"]
    ok, remaining = verify_recovery_code("targetcode1", codes)
    assert ok is True
    assert remaining == ["ab12c-de34f", "fg56h-ij78k"]


def test_recovery_codes_are_stored_as_keyed_hashes():
    stored = hash_recovery_codes(["ab12c-de34f"], b"application-secret")
    assert stored[0] != "ab12c-de34f"
    assert is_hashed_recovery_code(stored[0])
    ok, remaining = verify_recovery_code(
        "ab12c-de34f", stored, secret_key=b"application-secret"
    )
    assert ok is True
    assert remaining == []


def test_legacy_recovery_codes_are_migrated_without_double_hashing():
    hashed = hash_recovery_codes(["ab12c-de34f"], b"application-secret")[0]
    migrated = ensure_hashed_recovery_codes(
        [hashed, "fg56h-ij78k"], b"application-secret"
    )
    assert migrated[0] == hashed
    assert is_hashed_recovery_code(migrated[1])


@pytest.mark.asyncio
async def test_recovery_regeneration_form_has_csrf_token(
    client_two_factor, app_two_factor
):
    app_two_factor.config["SECURITY_CSRF_PROTECT"] = True
    async with client_two_factor.session_transaction() as sess:
        sess["_user_id"] = "user-1"
        sess["_fresh"] = True
        sess["_auth_at"] = 9999999999

    response = await client_two_factor.get("/mf-recovery-codes")
    body = await response.get_data(as_text=True)
    assert 'name="csrf_token"' in body
    assert 'value=""' not in body
