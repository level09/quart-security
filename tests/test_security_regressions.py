import json
import time

import pytest

from quart_security import hash_password, verify_password, webauthn
from quart_security.totp import generate_qr_code, hash_recovery_codes


async def login(client):
    return await client.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )


def test_real_qr_generation():
    assert generate_qr_code("otpauth://totp/test").startswith("data:image/png;base64,")


async def test_current_password_keeps_spaces(client, app):
    user = app.extensions["test_basic_user"]
    user.password = hash_password(" correct-password ", app=app)
    await client.post(
        "/login",
        form={"email": user.email, "password": " correct-password "},
    )
    response = await client.post(
        "/change",
        form={
            "password": " correct-password ",
            "new_password": "new-correct-password",
            "new_password_confirm": "new-correct-password",
        },
    )
    assert response.status_code == 302
    assert verify_password("new-correct-password", user.password, app=app)


async def test_disabled_recovery_rejects_code(client_two_factor, app_two_factor):
    user = app_two_factor.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    user.mf_recovery_codes = hash_recovery_codes(
        ["12345-67890"], app_two_factor.secret_key
    )
    await login(client_two_factor)
    app_two_factor.config["SECURITY_MULTI_FACTOR_RECOVERY_CODES"] = False
    result = await client_two_factor.post("/mf-recovery", form={"code": "12345-67890"})
    assert result.status_code == 404
    assert (await client_two_factor.get("/protected")).status_code == 302


@pytest.fixture
def verified_passkey(app_webauthn, monkeypatch):
    user = app_webauthn.extensions["test_basic_user"]
    user.fs_webauthn_user_handle = "handle"
    credential = app_webauthn.extensions["test_datastore"].create_webauthn_credential(
        user,
        credential_id=b"key",
        public_key=b"public-key",
        sign_count=0,
        name="Key",
        usage="secondary",
    )

    async def verify(*args, **kwargs):
        return 0

    monkeypatch.setattr(webauthn, "complete_authentication", verify)
    return credential


def assertion():
    return {
        "credential": json.dumps(
            {"id": webauthn.bytes_to_base64url(b"key"), "response": {}}
        )
    }


async def test_secondary_passkey_cannot_sign_in(client_webauthn, verified_passkey):
    await client_webauthn.post("/wan-signin")
    await client_webauthn.post("/wan-signin-response", form=assertion())
    assert (await client_webauthn.get("/protected")).status_code == 302


async def test_step_up_refreshes_time(client_webauthn, verified_passkey):
    await login(client_webauthn)
    async with client_webauthn.session_transaction() as state:
        state["_auth_at"] = int(time.time()) - 7200
    await client_webauthn.post("/wan-verify")
    await client_webauthn.post("/wan-verify-response", form=assertion())
    assert (await client_webauthn.get("/wan-register")).status_code == 200


async def test_password_context_is_scoped_to_app(app, app_webauthn):
    from quart_security.password import init_password_context

    app.config["SECURITY_PASSWORD_HASH"] = "pbkdf2_sha512"
    init_password_context(app)
    init_password_context(app_webauthn)
    async with app.app_context():
        assert hash_password("test-password").startswith("$pbkdf2-sha512$")
    async with app_webauthn.app_context():
        assert hash_password("test-password").startswith("$argon2id$")


async def test_session_cookie_has_safe_defaults(client):
    response = await login(client)
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


async def test_password_change_revokes_copied_session(client, app):
    await login(client)
    stolen = app.test_client()
    async with client.session_transaction() as state:
        copied = dict(state)
    async with stolen.session_transaction() as state:
        state.update(copied)
    await client.post(
        "/change",
        form={
            "password": "correct-password",
            "new_password": "new-correct-password",
            "new_password_confirm": "new-correct-password",
        },
    )
    assert (await stolen.get("/protected")).status_code == 302
    assert (await client.get("/protected")).status_code == 200


async def test_disabled_user_cannot_complete_mfa(client_two_factor, app_two_factor):
    user = app_two_factor.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    user.mf_recovery_codes = hash_recovery_codes(
        ["12345-67890"], app_two_factor.secret_key
    )
    await login(client_two_factor)
    user.active = False
    await client_two_factor.post("/mf-recovery", form={"code": "12345-67890"})
    assert user.login_count is None
    assert len(user.mf_recovery_codes) == 1


async def test_logout_revokes_copied_cookie(client, app):
    await login(client)
    stolen = app.test_client()
    async with client.session_transaction() as state:
        copied = dict(state)
    async with stolen.session_transaction() as state:
        state.update(copied)
    await client.post("/logout")
    assert (await stolen.get("/protected")).status_code == 302


async def test_setup_secret_is_server_side_and_old_cookie_cannot_disable_mfa(
    client_two_factor, app_two_factor
):
    import pyotp

    await login(client_two_factor)
    response = await client_two_factor.get("/tf-setup?setup=authenticator")
    body = await response.get_data(as_text=True)
    async with client_two_factor.session_transaction() as state:
        copied = dict(state)
    assert "tf_pending_secret" not in copied
    pending = await app_two_factor.extensions["security"].state_store.get(
        copied["tf_setup_state"]
    )
    from quart_security.totp import decrypt_totp_secret

    secret = decrypt_totp_secret(pending["secret"], app=app_two_factor)
    assert secret in body
    assert 'name="action" value="verify"' in body
    assert pending["secret"] not in str(copied)
    result = await client_two_factor.post(
        "/tf-setup",
        form={"action": "verify", "token": pyotp.TOTP(secret).now()},
    )
    assert result.status_code == 200
    stolen = app_two_factor.test_client()
    async with stolen.session_transaction() as state:
        state.update(copied)
    assert (
        await stolen.post("/tf-setup", form={"action": "disable"})
    ).status_code == 302
    assert (
        app_two_factor.extensions["test_basic_user"].tf_primary_method
        == "authenticator"
    )


async def test_real_totp_cannot_be_reused(app_two_factor):
    import pyotp

    user = app_two_factor.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    user.tf_totp_secret = pyotp.random_base32()
    token = pyotp.TOTP(user.tf_totp_secret).now()
    first, second = app_two_factor.test_client(), app_two_factor.test_client()
    await login(first)
    await login(second)
    await first.post("/tf-validate", form={"token": token})
    await second.post("/tf-validate", form={"token": token})
    assert (await first.get("/protected")).status_code == 200
    assert (await second.get("/protected")).status_code == 302


async def test_passkey_challenge_rejects_restored_cookie(
    client_webauthn, app_webauthn, verified_passkey
):
    verified_passkey.usage = "primary"
    await client_webauthn.post("/wan-signin")
    async with client_webauthn.session_transaction() as state:
        copied = dict(state)
    await client_webauthn.post("/wan-signin-response", form=assertion())
    replay = app_webauthn.test_client()
    async with replay.session_transaction() as state:
        state.update(copied)
    await replay.post("/wan-signin-response", form=assertion())
    assert (await replay.get("/protected")).status_code == 302


def test_lockout_cannot_silently_lack_atomic_datastore_hook():
    from conftest import InMemoryDatastore, MemoryStateStore
    from quart import Quart

    from quart_security import Security

    datastore = InMemoryDatastore()
    datastore.record_auth_failure = None
    app = Quart(__name__)
    app.secret_key = "test-secret"
    with pytest.raises(RuntimeError, match="record_auth_failure"):
        Security(app, datastore, state_store=MemoryStateStore())
