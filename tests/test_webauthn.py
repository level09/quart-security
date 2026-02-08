import json

import pytest

from quart_security import webauthn as wan


def _registration_options(challenge: bytes, user_id: bytes = b"user-handle"):
    return {
        "challenge": wan.bytes_to_base64url(challenge),
        "user": {"id": wan.bytes_to_base64url(user_id), "name": "user@example.com"},
        "excludeCredentials": [],
    }


def _authentication_options(challenge: bytes, credential_id: bytes):
    return {
        "challenge": wan.bytes_to_base64url(challenge),
        "allowCredentials": [{"id": wan.bytes_to_base64url(credential_id)}],
    }


@pytest.mark.asyncio
async def test_wan_register_creates_credential(client_webauthn, app_webauthn, monkeypatch):
    user = app_webauthn.extensions["test_basic_user"]

    async def fake_begin_registration(user, rp_id, rp_name, challenge, existing_credentials=None):
        return {"challenge": challenge}

    def fake_options_to_json_dict(options):
        return _registration_options(options["challenge"])

    async def fake_complete_registration(
        credential,
        challenge,
        rp_id,
        expected_origin,
        require_user_verification=True,
    ):
        return {
            "credential_id": b"cred-1",
            "public_key": b"public-key",
            "sign_count": 0,
            "backup_state": False,
            "device_type": "single_device",
        }

    monkeypatch.setattr(wan, "begin_registration", fake_begin_registration)
    monkeypatch.setattr(wan, "options_to_json_dict", fake_options_to_json_dict)
    monkeypatch.setattr(wan, "complete_registration", fake_complete_registration)

    await client_webauthn.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    register_start = await client_webauthn.post(
        "/wan-register",
        form={"name": "MacBook Passkey", "usage": "primary"},
    )
    assert register_start.status_code == 200

    credential_payload = {
        "id": wan.bytes_to_base64url(b"cred-1"),
        "rawId": wan.bytes_to_base64url(b"cred-1"),
        "type": "public-key",
        "response": {
            "clientDataJSON": "client",
            "attestationObject": "attestation",
        },
    }

    register_finish = await client_webauthn.post(
        "/wan-register-response",
        form={"credential": json.dumps(credential_payload)},
    )

    assert register_finish.status_code == 302
    assert register_finish.headers["Location"].endswith("/wan-register")
    assert len(user.webauthn) == 1
    assert user.webauthn[0].name == "MacBook Passkey"
    assert user.webauthn[0].usage == "primary"


@pytest.mark.asyncio
async def test_wan_signin_logs_in_with_passkey(client_webauthn, app_webauthn, monkeypatch):
    user = app_webauthn.extensions["test_basic_user"]
    user.fs_webauthn_user_handle = "handle-1"
    app_webauthn.extensions["test_datastore"].create_webauthn_credential(
        user,
        credential_id=b"cred-primary",
        public_key=b"public-key",
        sign_count=1,
        name="Phone",
        usage="primary",
    )

    async def fake_begin_authentication(credentials, rp_id, challenge):
        return {"challenge": challenge, "credential_id": credentials[0].credential_id}

    def fake_options_to_json_dict(options):
        return _authentication_options(options["challenge"], options["credential_id"])

    async def fake_complete_authentication(
        credential,
        challenge,
        rp_id,
        expected_origin,
        stored_credential,
        require_user_verification=True,
    ):
        return stored_credential.sign_count + 1

    monkeypatch.setattr(wan, "begin_authentication", fake_begin_authentication)
    monkeypatch.setattr(wan, "options_to_json_dict", fake_options_to_json_dict)
    monkeypatch.setattr(wan, "complete_authentication", fake_complete_authentication)

    signin_start = await client_webauthn.post(
        "/wan-signin",
        form={"identity": "user@example.com", "remember": "y"},
    )
    assert signin_start.status_code == 200

    credential_payload = {
        "id": wan.bytes_to_base64url(b"cred-primary"),
        "rawId": wan.bytes_to_base64url(b"cred-primary"),
        "type": "public-key",
        "response": {
            "clientDataJSON": "client",
            "authenticatorData": "auth-data",
            "signature": "sig",
            "userHandle": None,
        },
    }

    signin_finish = await client_webauthn.post(
        "/wan-signin-response",
        form={"credential": json.dumps(credential_payload)},
    )
    assert signin_finish.status_code == 302
    assert signin_finish.headers["Location"].endswith("/protected")

    protected = await client_webauthn.get("/protected")
    assert protected.status_code == 200
    assert user.webauthn[0].sign_count == 2


@pytest.mark.asyncio
async def test_wan_verify_updates_sign_count(client_webauthn, app_webauthn, monkeypatch):
    user = app_webauthn.extensions["test_basic_user"]
    user.fs_webauthn_user_handle = "handle-2"
    app_webauthn.extensions["test_datastore"].create_webauthn_credential(
        user,
        credential_id=b"cred-secondary",
        public_key=b"public-key",
        sign_count=10,
        name="Security Key",
        usage="secondary",
    )

    async def fake_begin_authentication(credentials, rp_id, challenge):
        return {"challenge": challenge, "credential_id": credentials[0].credential_id}

    def fake_options_to_json_dict(options):
        return _authentication_options(options["challenge"], options["credential_id"])

    async def fake_complete_authentication(
        credential,
        challenge,
        rp_id,
        expected_origin,
        stored_credential,
        require_user_verification=True,
    ):
        return stored_credential.sign_count + 5

    monkeypatch.setattr(wan, "begin_authentication", fake_begin_authentication)
    monkeypatch.setattr(wan, "options_to_json_dict", fake_options_to_json_dict)
    monkeypatch.setattr(wan, "complete_authentication", fake_complete_authentication)

    await client_webauthn.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    verify_start = await client_webauthn.post("/wan-verify")
    assert verify_start.status_code == 200

    credential_payload = {
        "id": wan.bytes_to_base64url(b"cred-secondary"),
        "rawId": wan.bytes_to_base64url(b"cred-secondary"),
        "type": "public-key",
        "response": {
            "clientDataJSON": "client",
            "authenticatorData": "auth-data",
            "signature": "sig",
            "userHandle": None,
        },
    }

    verify_finish = await client_webauthn.post(
        "/wan-verify-response",
        form={"credential": json.dumps(credential_payload)},
    )
    assert verify_finish.status_code == 302
    assert user.webauthn[0].sign_count == 15


@pytest.mark.asyncio
async def test_wan_delete_removes_credential(client_webauthn, app_webauthn):
    user = app_webauthn.extensions["test_basic_user"]
    user.fs_webauthn_user_handle = "handle-3"
    app_webauthn.extensions["test_datastore"].create_webauthn_credential(
        user,
        credential_id=b"cred-delete",
        public_key=b"public-key",
        sign_count=0,
        name="To Delete",
        usage="secondary",
    )

    await client_webauthn.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )

    response = await client_webauthn.post(
        "/wan-delete",
        form={"credential_id": wan.bytes_to_base64url(b"cred-delete")},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/wan-register")
    assert user.webauthn == []
