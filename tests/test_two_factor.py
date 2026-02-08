import pytest

from quart_security import totp


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

    assert post_response.status_code == 302
    assert post_response.headers["Location"].endswith("/mf-recovery-codes")
    assert user.tf_primary_method == "authenticator"
    assert user.tf_totp_secret == "test-secret"
    assert len(user.mf_recovery_codes or []) == app_two_factor.config[
        "SECURITY_MULTI_FACTOR_RECOVERY_CODES_N"
    ]


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
