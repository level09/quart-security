"""Thin wrappers over py_webauthn primitives."""

from __future__ import annotations


def _require_webauthn():
    try:
        from webauthn import (
            generate_authentication_options,
            generate_registration_options,
            verify_authentication_response,
            verify_registration_response,
        )
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    except ImportError as exc:
        raise RuntimeError("py_webauthn is required for WebAuthn support") from exc

    return {
        "generate_authentication_options": generate_authentication_options,
        "generate_registration_options": generate_registration_options,
        "verify_authentication_response": verify_authentication_response,
        "verify_registration_response": verify_registration_response,
        "PublicKeyCredentialDescriptor": PublicKeyCredentialDescriptor,
    }


async def begin_registration(user, rp_id, rp_name, existing_credentials=None):
    api = _require_webauthn()

    user_id = getattr(user, "fs_webauthn_user_handle", "") or ""
    if isinstance(user_id, str):
        user_id = user_id.encode("utf-8")

    exclude_credentials = []
    for cred in existing_credentials or []:
        exclude_credentials.append(
            api["PublicKeyCredentialDescriptor"](id=getattr(cred, "credential_id"))
        )

    return api["generate_registration_options"](
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id,
        user_name=getattr(user, "email", ""),
        user_display_name=getattr(user, "name", None) or getattr(user, "email", ""),
        exclude_credentials=exclude_credentials,
    )


async def complete_registration(credential, challenge, rp_id, expected_origin):
    api = _require_webauthn()
    verification = api["verify_registration_response"](
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
    )
    return {
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
        "transports": verification.credential_device_type,
    }


async def begin_authentication(credentials, rp_id):
    api = _require_webauthn()
    return api["generate_authentication_options"](
        rp_id=rp_id,
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
):
    api = _require_webauthn()
    verification = api["verify_authentication_response"](
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        credential_public_key=stored_credential.public_key,
        credential_current_sign_count=stored_credential.sign_count,
    )
    return verification.new_sign_count
