"""Thin wrappers over the webauthn package primitives."""

from __future__ import annotations

import base64
import json


def bytes_to_base64url(value: bytes) -> str:
    """Encode bytes to unpadded base64url."""
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def base64url_to_bytes(value: str) -> bytes:
    """Decode unpadded base64url into bytes."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")


def _require_webauthn():
    try:
        from webauthn import (
            generate_authentication_options,
            generate_registration_options,
            options_to_json,
            verify_authentication_response,
            verify_registration_response,
        )
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    except ImportError as exc:
        raise RuntimeError("webauthn package is required for WebAuthn support") from exc

    return {
        "generate_authentication_options": generate_authentication_options,
        "generate_registration_options": generate_registration_options,
        "options_to_json": options_to_json,
        "verify_authentication_response": verify_authentication_response,
        "verify_registration_response": verify_registration_response,
        "PublicKeyCredentialDescriptor": PublicKeyCredentialDescriptor,
    }


def options_to_json_dict(options) -> dict:
    """Serialize WebAuthn option objects into JSON-safe dictionaries."""
    api = _require_webauthn()
    payload = api["options_to_json"](options)
    if isinstance(payload, bytes):
        return json.loads(payload.decode("utf-8"))
    if isinstance(payload, str):
        return json.loads(payload)
    if isinstance(payload, dict):
        return payload
    raise RuntimeError("Unsupported WebAuthn options payload type")


async def begin_registration(
    user,
    rp_id,
    rp_name,
    challenge: bytes,
    existing_credentials=None,
):
    api = _require_webauthn()

    user_id = getattr(user, "fs_webauthn_user_handle", "") or ""
    if isinstance(user_id, str):
        user_id = user_id.encode("utf-8")

    exclude_credentials = []
    for cred in existing_credentials or []:
        exclude_credentials.append(
            api["PublicKeyCredentialDescriptor"](id=cred.credential_id)
        )

    return api["generate_registration_options"](
        rp_id=rp_id,
        rp_name=rp_name,
        challenge=challenge,
        user_id=user_id,
        user_name=getattr(user, "email", ""),
        user_display_name=getattr(user, "name", None) or getattr(user, "email", ""),
        exclude_credentials=exclude_credentials,
    )


async def complete_registration(
    credential,
    challenge,
    rp_id,
    expected_origin,
    require_user_verification: bool = True,
):
    api = _require_webauthn()
    verification = api["verify_registration_response"](
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        require_user_verification=require_user_verification,
    )
    return {
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
        "backup_state": bool(getattr(verification, "credential_backed_up", False)),
        "device_type": getattr(verification, "credential_device_type", None),
    }


async def begin_authentication(credentials, rp_id, challenge: bytes):
    api = _require_webauthn()
    return api["generate_authentication_options"](
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=[
            api["PublicKeyCredentialDescriptor"](id=item.credential_id)
            for item in credentials
        ],
    )


async def complete_authentication(
    credential,
    challenge,
    rp_id,
    expected_origin,
    stored_credential,
    require_user_verification: bool = True,
):
    api = _require_webauthn()
    verification = api["verify_authentication_response"](
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        credential_public_key=stored_credential.public_key,
        credential_current_sign_count=stored_credential.sign_count,
        require_user_verification=require_user_verification,
    )
    return verification.new_sign_count
