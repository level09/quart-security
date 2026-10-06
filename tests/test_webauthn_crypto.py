import hashlib
import json
import re

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from quart_security.webauthn import bytes_to_base64url


def options(body, operation):
    match = re.search(rf"decode{operation}Options\((\{{.*\}})\);", body)
    assert match
    return json.loads(match[1])


def client_data(kind, challenge, origin="http://localhost"):
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin}).encode()


def public_key(key):
    numbers = key.public_key().public_numbers()
    return cbor2.dumps(
        {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32), -3: numbers.y.to_bytes(32)}
    )


@pytest.mark.parametrize("origin", ["http://localhost", "https://attacker.invalid"])
@pytest.mark.parametrize("counter", [0, 1])
async def test_real_registration_and_discoverable_signin(
    client_webauthn, app_webauthn, origin, counter
):
    key = ec.generate_private_key(ec.SECP256R1())
    credential_id = b"real-credential"
    encoded_id = bytes_to_base64url(credential_id)
    await client_webauthn.post(
        "/login",
        form={"email": "user@example.com", "password": "correct-password"},
    )
    start = await client_webauthn.post(
        "/wan-register", form={"name": "Software test key", "usage": "primary"}
    )
    registration = options(await start.get_data(as_text=True), "Registration")
    auth_data = (
        hashlib.sha256(b"localhost").digest()
        + b"\x45"
        + (0).to_bytes(4)
        + bytes(16)
        + len(credential_id).to_bytes(2)
        + credential_id
        + public_key(key)
    )
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    result = await client_webauthn.post(
        "/wan-register-response",
        form={
            "credential": json.dumps(
                {
                    "id": encoded_id,
                    "rawId": encoded_id,
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": bytes_to_base64url(
                            client_data(
                                "webauthn.create", registration["challenge"], origin
                            )
                        ),
                        "attestationObject": bytes_to_base64url(attestation),
                    },
                }
            )
        },
    )
    assert result.status_code == 302
    user = app_webauthn.extensions["test_basic_user"]
    if origin != "http://localhost":
        assert user.webauthn == []
        return
    assert len(user.webauthn) == 1
    await client_webauthn.post("/logout")
    start = await client_webauthn.post("/wan-signin")
    authentication = options(await start.get_data(as_text=True), "Authentication")
    assert authentication["userVerification"] == "required"
    data = client_data("webauthn.get", authentication["challenge"])
    auth_data = hashlib.sha256(b"localhost").digest() + b"\x05" + counter.to_bytes(4)
    signature = key.sign(
        auth_data + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256())
    )
    form = {
        "credential": json.dumps(
            {
                "id": encoded_id,
                "rawId": encoded_id,
                "type": "public-key",
                "response": {
                    "clientDataJSON": bytes_to_base64url(data),
                    "authenticatorData": bytes_to_base64url(auth_data),
                    "signature": bytes_to_base64url(signature),
                    "userHandle": bytes_to_base64url(
                        user.fs_webauthn_user_handle.encode()
                    ),
                },
            }
        )
    }
    async with client_webauthn.session_transaction() as state:
        old = dict(state)
    result = await client_webauthn.post("/wan-signin-response", form=form)
    assert result.status_code == 302
    assert (await client_webauthn.get("/protected")).status_code == 200
    assert user.webauthn[0].sign_count == counter
    replay = app_webauthn.test_client()
    async with replay.session_transaction() as state:
        state.update(old)
    await replay.post("/wan-signin-response", form=form)
    assert (await replay.get("/protected")).status_code == 302
