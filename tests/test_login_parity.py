"""Login fixes that Flask-Security-Too made and quart-security had missed."""

import datetime
import unicodedata

import bcrypt
import pytest
from conftest import WebAuthnCredential, _build_app

from quart_security import auth_required, hash_password, verify_password, webauthn
from quart_security.utils import naive_utcnow, normalize_email


async def test_auth_required_next_survives_login(app, client):
    @app.get("/deep")
    @auth_required("session")
    async def deep():
        return "deep"

    await client.get((await client.get("/deep?tab=2")).headers["Location"])
    response = await client.post(
        "/login", form={"email": "user@example.com", "password": "correct-password"}
    )
    assert response.headers["Location"] == "/deep?tab=2"


async def test_auth_required_next_keeps_encoded_characters(app, client):
    @app.get("/files/<name>")
    @auth_required("session")
    async def file(name):
        return name

    login = (await client.get("/files/report%23q1?a=b%3F")).headers["Location"]
    await client.get(login)
    response = await client.post(
        "/login", form={"email": "user@example.com", "password": "correct-password"}
    )
    assert response.headers["Location"] == "/files/report%23q1?a=b%3F"


async def test_password_that_normalizes_past_the_limit_still_verifies(app):
    password = "\ufdfa" * 228  # NFKD expands each to 18 characters
    context, _salt = app.extensions["quart_security_password"]
    assert verify_password(password, context.hash(password), app=app)


def test_normalize_email_is_idempotent():
    once = normalize_email("J\u030c@example.com")
    assert normalize_email(once) == once


async def test_password_matches_in_any_unicode_form(app, client, datastore):
    password = unicodedata.normalize("NFC", "pässwörd-long")
    datastore.create_user(
        email="u2@example.com", password=hash_password(password, app=app), active=True
    )
    response = await client.post(
        "/login",
        form={
            "email": "u2@example.com",
            "password": unicodedata.normalize("NFD", password),
        },
    )
    assert response.status_code == 302


async def test_hash_made_before_normalization_still_verifies(app, client, datastore):
    password = unicodedata.normalize("NFD", "pässwörd-long")
    context, _salt = app.extensions["quart_security_password"]
    datastore.create_user(
        email="old@example.com", password=context.hash(password), active=True
    )
    response = await client.post(
        "/login", form={"email": "old@example.com", "password": password}
    )
    assert response.status_code == 302


async def test_legacy_bcrypt_accepts_long_password(client, datastore):
    password = "x" * 80
    datastore.create_user(
        email="legacy@example.com",
        password=bcrypt.hashpw(password[:72].encode(), bcrypt.gensalt()).decode(),
        active=True,
    )
    response = await client.post(
        "/login", form={"email": "legacy@example.com", "password": password}
    )
    assert response.status_code == 302


async def test_one_account_per_mailbox(client, datastore):
    before = len(datastore.users)
    for email in [
        "josé@example.com",
        unicodedata.normalize("NFD", "josé@example.com"),
        "bob@münchen.de",
        "bob@xn--mnchen-3ya.de",
    ]:
        await client.post(
            "/register",
            form={
                "email": email,
                "password": "long-enough-pass",
                "password_confirm": "long-enough-pass",
            },
        )
    assert len(datastore.users) - before == 2


@pytest.mark.parametrize(
    "case, signed_in",
    [("verified", True), ("unverified", False), ("locked", False)],
)
async def test_passkey_sign_in_gates(datastore, monkeypatch, case, signed_in):
    app = _build_app(datastore, two_factor=True, webauthn=True)
    if case == "unverified":
        app.config["SECURITY_WAN_REQUIRE_USER_VERIFICATION"] = False
    client = app.test_client()
    user = app.extensions["test_basic_user"]
    user.tf_primary_method = "authenticator"
    user.tf_totp_secret = "JBSWY3DPEHPK3PXP"
    user.fs_webauthn_user_handle = "h1"
    if case == "locked":
        user.locked_until = naive_utcnow() + datetime.timedelta(minutes=10)
    user.webauthn.append(
        WebAuthnCredential(
            credential_id=b"cid",
            public_key=b"pk",
            sign_count=0,
            name="k",
            usage="primary",
            user_id="h1",
        )
    )

    async def assertion_ok(*args, **kwargs):
        return 1

    monkeypatch.setattr(webauthn, "complete_authentication", assertion_ok)
    await client.post("/wan-signin")
    credential = {"id": webauthn.bytes_to_base64url(b"cid"), "response": {}}
    await client.post("/wan-signin-response", json={"credential": credential})
    assert ((await client.get("/protected")).status_code == 200) is signed_in
