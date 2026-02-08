"""Auth blueprint and route handlers."""

from __future__ import annotations

import datetime
import json
import secrets
from urllib.parse import urlsplit

from quart import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
)
from werkzeug.routing import BuildError

from . import webauthn as wan
from .decorators import auth_required
from .forms import (
    QuartForm,
    RecoveryCodeForm,
    TwoFactorVerifyForm,
    WebAuthnRegisterForm,
    WebAuthnVerifyForm,
)
from .password import hash_password, validate_password, verify_password
from .proxies import _security, current_user
from .signals import password_changed, tf_profile_changed, user_registered
from .utils import url_for_security

security_bp = Blueprint("security", __name__, template_folder="templates")


def _is_post() -> bool:
    return request.method == "POST"


def _normalize_email(value: str | None) -> str:
    return (value or "").strip().lower()


def _resolve_redirect(config_key: str, fallback_endpoint: str) -> str:
    value = current_app.config.get(config_key)
    if isinstance(value, str) and value:
        if value.startswith("/"):
            return value
        try:
            return url_for_security(value)
        except BuildError:
            return value
    return url_for_security(fallback_endpoint)


async def _find_user(**kwargs):
    return await current_app.ensure_async(_security.datastore.find_user)(**kwargs)


async def _create_user(**kwargs):
    return await current_app.ensure_async(_security.datastore.create_user)(**kwargs)


async def _commit():
    await current_app.ensure_async(_security.datastore.commit)()


async def _enforce_csrf(submitted_token: str | None = None):
    if not _is_post():
        return
    if not current_app.config.get("SECURITY_CSRF_PROTECT", True):
        return

    if submitted_token is None:
        submitted_token = (await request.form).get("csrf_token")

    expected_token = session.get("_csrf_token")
    if not expected_token or not submitted_token:
        abort(400)
    if not secrets.compare_digest(str(expected_token), str(submitted_token)):
        abort(400)


def _ensure_csrf_token() -> str:
    csrf_token = session.get("_csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        session["_csrf_token"] = csrf_token
    return csrf_token


def _safe_redirect_target(candidate: str | None, fallback: str = "/") -> str:
    if not candidate:
        return fallback
    parts = urlsplit(candidate)
    if parts.scheme or parts.netloc:
        return fallback
    if not candidate.startswith("/") or candidate.startswith("//"):
        return fallback
    return candidate


def _webauthn_rp_id() -> str:
    configured = current_app.config.get("SECURITY_WAN_RP_ID")
    if configured:
        return str(configured)
    return request.host.split(":", 1)[0]


def _webauthn_expected_origin() -> str:
    configured = current_app.config.get("SECURITY_WAN_EXPECTED_ORIGIN")
    if configured:
        return str(configured)
    return f"{request.scheme}://{request.host}"


def _webauthn_rp_name() -> str:
    return str(current_app.config.get("SECURITY_WAN_RP_NAME") or current_app.name)


def _set_wan_state(key: str, **payload):
    session[key] = {
        "payload": payload,
        "issued_at": int(datetime.datetime.utcnow().timestamp()),
    }


def _pop_wan_state(key: str, max_age_seconds: int = 300) -> dict | None:
    state = session.pop(key, None)
    if not isinstance(state, dict):
        return None
    issued_at = state.get("issued_at")
    payload = state.get("payload")
    if not isinstance(issued_at, int) or not isinstance(payload, dict):
        return None
    age = int(datetime.datetime.utcnow().timestamp()) - issued_at
    if age < 0 or age > max_age_seconds:
        return None
    return payload


async def _list_webauthn_credentials(user, usage: str | None = None):
    getter = getattr(_security.datastore, "get_webauthn_credentials", None)
    if getter:
        credentials = await current_app.ensure_async(getter)(user, usage=usage)
    else:
        credentials = list(getattr(user, "webauthn", None) or [])
        if usage:
            credentials = [
                credential
                for credential in credentials
                if getattr(credential, "usage", None) == usage
            ]
    return credentials


async def _find_webauthn_credential(credential_id: bytes, user=None):
    finder = getattr(_security.datastore, "find_webauthn_credential", None)
    if finder:
        return await current_app.ensure_async(finder)(credential_id, user=user)

    candidates = list(getattr(user, "webauthn", None) or []) if user else []
    for credential in candidates:
        if getattr(credential, "credential_id", None) == credential_id:
            return credential
    return None


async def _create_webauthn_credential(user, **kwargs):
    creator = getattr(_security.datastore, "create_webauthn_credential", None)
    if creator:
        return await current_app.ensure_async(creator)(user, **kwargs)
    raise RuntimeError("Datastore does not implement create_webauthn_credential")


async def _delete_webauthn_credential(user, credential):
    deleter = getattr(_security.datastore, "delete_webauthn_credential", None)
    if deleter:
        return await current_app.ensure_async(deleter)(user, credential)

    user_credentials = getattr(user, "webauthn", None)
    if user_credentials is not None and credential in user_credentials:
        user_credentials.remove(credential)
        return True
    return False


def _extract_webauthn_credential_id(credential_payload: dict | None) -> bytes | None:
    if not isinstance(credential_payload, dict):
        return None
    raw_id = credential_payload.get("id") or credential_payload.get("rawId")
    if not isinstance(raw_id, str):
        return None
    try:
        return wan.base64url_to_bytes(raw_id)
    except Exception:
        return None


async def _extract_webauthn_credential_payload():
    payload = await request.get_json(silent=True)
    if isinstance(payload, dict):
        if isinstance(payload.get("credential"), dict):
            return payload["credential"]
        if "id" in payload and "response" in payload:
            return payload

    form_data = await request.form
    raw = form_data.get("credential")
    if not raw:
        return None
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def _format_webauthn_credential(credential) -> dict:
    raw_id = getattr(credential, "credential_id", b"")
    if isinstance(raw_id, memoryview):
        raw_id = raw_id.tobytes()
    if isinstance(raw_id, bytearray):
        raw_id = bytes(raw_id)
    if not isinstance(raw_id, bytes):
        raw_id = str(raw_id).encode("utf-8")

    last_use = getattr(credential, "lastuse_datetime", None)
    if isinstance(last_use, datetime.datetime):
        last_use = last_use.isoformat(timespec="seconds")
    elif last_use is None:
        last_use = "Never"

    return {
        "id": wan.bytes_to_base64url(raw_id),
        "name": getattr(credential, "name", "Unnamed credential"),
        "usage": getattr(credential, "usage", "secondary"),
        "device_type": getattr(credential, "device_type", "unknown"),
        "last_use": last_use,
    }


@security_bp.route("/login", methods=["GET", "POST"])
async def login():
    form = await _security.login_form_cls.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        user = await _find_user(email=_normalize_email(form.email.data))
        if (
            user
            and getattr(user, "active", True)
            and verify_password(form.password.data, user.password)
        ):
            if current_app.config.get("SECURITY_TWO_FACTOR") and getattr(
                user, "tf_primary_method", None
            ):
                session["tf_user_id"] = user.get_id()
                return redirect(url_for_security("two_factor_token_validation"))

            await _security.login_user(user)
            return redirect(_resolve_redirect("SECURITY_POST_LOGIN_VIEW", "login"))

        await flash("Invalid email or password", "error")

    return await render_template("security/login_user.html", login_user_form=form)


@security_bp.route("/register", methods=["GET", "POST"])
async def register():
    if not current_app.config.get("SECURITY_REGISTERABLE", False):
        abort(404)

    form = await _security.register_form_cls.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        email = _normalize_email(form.email.data)
        if await _find_user(email=email):
            await flash("A user with this email already exists", "error")
            return await render_template(
                "security/register_user.html", register_user_form=form
            )

        errors = validate_password(
            form.password.data,
            min_length=current_app.config.get("SECURITY_PASSWORD_LENGTH_MIN", 12),
        )
        if errors:
            for error in errors:
                await flash(error, "error")
            return await render_template(
                "security/register_user.html", register_user_form=form
            )

        user_kwargs = {
            "email": email,
            "password": hash_password(form.password.data),
            "active": True,
        }
        if hasattr(form, "name") and form.name.data:
            user_kwargs["name"] = form.name.data.strip()

        user = await _create_user(**user_kwargs)
        if hasattr(user, "confirmed_at"):
            user.confirmed_at = datetime.datetime.utcnow()

        await _commit()
        user_registered.send(current_app._get_current_object(), user=user)

        await flash("Registration successful. Please log in.", "success")
        return redirect(_resolve_redirect("SECURITY_POST_REGISTER_VIEW", "login"))

    return await render_template("security/register_user.html", register_user_form=form)


@security_bp.route("/logout", methods=["GET", "POST"])
async def logout():
    await _security.logout_user()
    await flash("You have been logged out.", "info")
    return redirect(url_for_security("login"))


@security_bp.route("/change", methods=["GET", "POST"])
@auth_required("session")
async def change_password():
    if not current_app.config.get("SECURITY_CHANGEABLE", False):
        abort(404)

    form = await _security.change_password_form_cls.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        user = current_user

        has_usable_password = getattr(user, "has_usable_password", True)
        if has_usable_password and getattr(user, "password", None):
            current_password = (form.password.data or "").strip()
            if not current_password:
                await flash("Current password is required", "error")
                return await render_template(
                    "security/change_password.html", change_password_form=form
                )
            if not verify_password(current_password, user.password):
                await flash("Invalid current password", "error")
                return await render_template(
                    "security/change_password.html", change_password_form=form
                )
            if current_password == form.new_password.data:
                await flash("New password must be different", "error")
                return await render_template(
                    "security/change_password.html", change_password_form=form
                )

        errors = validate_password(
            form.new_password.data,
            min_length=current_app.config.get("SECURITY_PASSWORD_LENGTH_MIN", 12),
        )
        if errors:
            for error in errors:
                await flash(error, "error")
            return await render_template(
                "security/change_password.html", change_password_form=form
            )

        user.password = hash_password(form.new_password.data)
        if hasattr(user, "password_set"):
            user.password_set = True

        await _commit()
        password_changed.send(current_app._get_current_object(), user=user)

        await flash("Password updated", "success")
        return redirect(url_for_security("change_password"))

    active_password = bool(getattr(current_user, "password", None)) and getattr(
        current_user, "has_usable_password", True
    )
    return await render_template(
        "security/change_password.html",
        change_password_form=form,
        active_password=active_password,
    )


@security_bp.route("/tf-setup", methods=["GET", "POST"])
@auth_required("session")
async def two_factor_setup():
    if not current_app.config.get("SECURITY_TWO_FACTOR", False):
        abort(404)

    from .totp import (
        generate_qr_code,
        generate_recovery_codes,
        generate_totp_secret,
        get_totp_uri,
        verify_totp,
    )

    primary_method = getattr(current_user, "tf_primary_method", None) or "none"

    if _is_post():
        form_data = await request.form
        await _enforce_csrf(form_data.get("csrf_token"))
        action = form_data.get("action")

        if action == "disable":
            current_user.tf_totp_secret = None
            current_user.tf_primary_method = None
            session.pop("tf_pending_secret", None)
            await _commit()
            tf_profile_changed.send(
                current_app._get_current_object(), user=current_user
            )
            await flash("Two-factor authentication disabled.", "success")
            return redirect(url_for_security("two_factor_setup"))

        if action == "verify":
            token = (form_data.get("token") or "").strip()
            pending_secret = session.get("tf_pending_secret")
            if pending_secret and token and verify_totp(pending_secret, token):
                current_user.tf_totp_secret = pending_secret
                current_user.tf_primary_method = "authenticator"
                session.pop("tf_pending_secret", None)

                if current_app.config.get(
                    "SECURITY_MULTI_FACTOR_RECOVERY_CODES", True
                ):
                    if not getattr(current_user, "mf_recovery_codes", None):
                        count = current_app.config.get(
                            "SECURITY_MULTI_FACTOR_RECOVERY_CODES_N", 3
                        )
                        current_user.mf_recovery_codes = generate_recovery_codes(
                            count
                        )

                await _commit()
                tf_profile_changed.send(
                    current_app._get_current_object(), user=current_user
                )
                await flash("Two-factor authentication enabled.", "success")
                return redirect(url_for_security("mf_recovery_codes"))

            await flash("Invalid authentication code.", "error")
            return redirect(
                url_for_security("two_factor_setup") + "?setup=authenticator"
            )

    setup_form = await QuartForm.from_formdata()
    chosen_method = None
    authr_qrcode = None
    authr_key = None

    # Only show QR when user explicitly chose to set up authenticator
    if primary_method == "none" and request.args.get("setup") == "authenticator":
        chosen_method = "authenticator"
        pending_secret = session.get("tf_pending_secret")
        if not pending_secret:
            pending_secret = generate_totp_secret()
            session["tf_pending_secret"] = pending_secret
        authr_key = pending_secret
        issuer = current_app.config.get("SECURITY_TOTP_ISSUER", "Quart")
        uri = get_totp_uri(pending_secret, current_user.email, issuer)
        authr_qrcode = generate_qr_code(uri)

    return await render_template(
        "security/two_factor_setup.html",
        two_factor_setup_form=setup_form,
        primary_method=primary_method,
        chosen_method=chosen_method,
        authr_qrcode=authr_qrcode,
        authr_key=authr_key,
    )


@security_bp.route("/tf-validate", methods=["GET", "POST"])
async def two_factor_token_validation():
    if not current_app.config.get("SECURITY_TWO_FACTOR", False):
        abort(404)

    from .totp import verify_recovery_code, verify_totp

    form = await TwoFactorVerifyForm.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))
    user_id = session.get("tf_user_id")
    if not user_id:
        return redirect(url_for_security("login"))

    user = await _find_user(fs_uniquifier=user_id)
    if user is None:
        session.pop("tf_user_id", None)
        return redirect(url_for_security("login"))

    if _is_post():
        form_data = await request.form
        token = (form_data.get("code") or form_data.get("token") or "").strip()
        valid = False

        if token and getattr(user, "tf_totp_secret", None):
            valid = verify_totp(user.tf_totp_secret, token)

        if not valid and token and current_app.config.get(
            "SECURITY_MULTI_FACTOR_RECOVERY_CODES", True
        ):
            codes = list(getattr(user, "mf_recovery_codes", None) or [])
            ok, remaining = verify_recovery_code(token, codes)
            if ok:
                user.mf_recovery_codes = remaining
                await _commit()
                valid = True

        if valid:
            session.pop("tf_user_id", None)
            await _security.login_user(user)
            return redirect(_resolve_redirect("SECURITY_POST_LOGIN_VIEW", "login"))

        await flash("Invalid code", "error")

    return await render_template(
        "security/two_factor_verify_code.html",
        two_factor_verify_code_form=form,
    )


@security_bp.route("/tf-select", methods=["GET", "POST"])
async def tf_select():
    if "tf_user_id" not in session:
        return redirect(url_for_security("login"))
    return await render_template("security/two_factor_select.html")


@security_bp.route("/mf-recovery-codes", methods=["GET", "POST"])
@auth_required("session")
async def mf_recovery_codes():
    if not current_app.config.get("SECURITY_MULTI_FACTOR_RECOVERY_CODES", True):
        abort(404)

    from .totp import generate_recovery_codes

    # A dummy form just for hidden_tag() CSRF support
    form = await QuartForm.from_formdata()
    codes = []

    if _is_post():
        await _enforce_csrf()
        count = current_app.config.get("SECURITY_MULTI_FACTOR_RECOVERY_CODES_N", 3)
        codes = generate_recovery_codes(count)
        current_user.mf_recovery_codes = codes
        await _commit()
        tf_profile_changed.send(current_app._get_current_object(), user=current_user)
        await flash("Recovery codes regenerated.", "success")
    elif request.args.get("show_codes"):
        codes = list(getattr(current_user, "mf_recovery_codes", None) or [])

    has_codes = bool(getattr(current_user, "mf_recovery_codes", None))

    return await render_template(
        "security/mf_recovery_codes.html",
        recovery_codes=codes,
        has_codes=has_codes or bool(codes),
        mf_recovery_codes_form=form,
    )


@security_bp.route("/mf-recovery", methods=["GET", "POST"])
async def mf_recovery():
    form = await RecoveryCodeForm.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        user_id = session.get("tf_user_id")
        if not user_id:
            return redirect(url_for_security("login"))

        user = await _find_user(fs_uniquifier=user_id)
        if user is None:
            return redirect(url_for_security("login"))

        from .totp import verify_recovery_code

        ok, remaining = verify_recovery_code(
            form.code.data.strip(), list(getattr(user, "mf_recovery_codes", None) or [])
        )
        if ok:
            user.mf_recovery_codes = remaining
            await _commit()
            session.pop("tf_user_id", None)
            await _security.login_user(user)
            return redirect(_resolve_redirect("SECURITY_POST_LOGIN_VIEW", "login"))

        await flash("Invalid recovery code", "error")

    return await render_template("security/mf_recovery.html", recovery_form=form)


@security_bp.route("/wan-register", methods=["GET", "POST"])
@auth_required("session")
async def wan_register():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)

    form = await WebAuthnRegisterForm.from_formdata()
    response_form = await QuartForm.from_formdata()
    delete_form = await QuartForm.from_formdata()

    registered_credentials = await _list_webauthn_credentials(current_user)
    serialized_credentials = [
        _format_webauthn_credential(credential) for credential in registered_credentials
    ]

    credential_options = None
    if _is_post():
        await _enforce_csrf(getattr(form, "_submitted_csrf", None))

        if not form.validate():
            await flash("Please provide a valid credential name.", "error")
            return await render_template(
                "security/wan_register.html",
                wan_register_form=form,
                wan_register_response_form=response_form,
                wan_delete_form=delete_form,
                credential_options=None,
                registered_credentials=serialized_credentials,
            )

        requested_usage = (form.usage.data or "secondary").strip().lower()
        if requested_usage == "primary" and not current_app.config.get(
            "SECURITY_WAN_ALLOW_AS_FIRST_FACTOR", True
        ):
            await flash(
                "Passwordless passkey sign-in is disabled for this deployment.",
                "error",
            )
            return await render_template(
                "security/wan_register.html",
                wan_register_form=form,
                wan_register_response_form=response_form,
                wan_delete_form=delete_form,
                credential_options=None,
                registered_credentials=serialized_credentials,
            )

        if not getattr(current_user, "fs_webauthn_user_handle", None):
            current_user.fs_webauthn_user_handle = secrets.token_urlsafe(32)

        challenge = secrets.token_bytes(32)
        options = await wan.begin_registration(
            current_user,
            rp_id=_webauthn_rp_id(),
            rp_name=_webauthn_rp_name(),
            challenge=challenge,
            existing_credentials=registered_credentials,
        )
        credential_options = wan.options_to_json_dict(options)

        _set_wan_state(
            "wan_register_state",
            challenge=wan.bytes_to_base64url(challenge),
            name=form.name.data.strip(),
            usage=requested_usage,
        )
        await _commit()

    return await render_template(
        "security/wan_register.html",
        wan_register_form=form,
        wan_register_response_form=response_form,
        wan_delete_form=delete_form,
        credential_options=credential_options,
        registered_credentials=serialized_credentials,
    )


@security_bp.route("/wan-register-response", methods=["POST"])
@auth_required("session")
async def wan_register_response():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)

    await _enforce_csrf()
    state = _pop_wan_state("wan_register_state")
    if not state:
        await flash("Passkey registration expired. Please try again.", "error")
        return redirect(url_for_security("wan_register"))

    credential_payload = await _extract_webauthn_credential_payload()
    if not credential_payload:
        await flash("Invalid passkey registration payload.", "error")
        return redirect(url_for_security("wan_register"))

    try:
        verification = await wan.complete_registration(
            credential_payload,
            challenge=wan.base64url_to_bytes(state["challenge"]),
            rp_id=_webauthn_rp_id(),
            expected_origin=_webauthn_expected_origin(),
            require_user_verification=current_app.config.get(
                "SECURITY_WAN_REQUIRE_USER_VERIFICATION", True
            ),
        )
    except Exception:
        await flash("Passkey registration failed.", "error")
        return redirect(url_for_security("wan_register"))

    existing = await _find_webauthn_credential(
        verification["credential_id"], user=current_user
    )
    if existing:
        await flash("This passkey is already registered.", "warning")
        return redirect(url_for_security("wan_register"))

    await _create_webauthn_credential(
        current_user,
        credential_id=verification["credential_id"],
        public_key=verification["public_key"],
        sign_count=verification["sign_count"],
        name=state.get("name", "Passkey"),
        usage=state.get("usage", "secondary"),
        backup_state=verification.get("backup_state", False),
        device_type=verification.get("device_type") or "single_device",
        lastuse_datetime=datetime.datetime.utcnow(),
    )
    await _commit()

    await flash("Passkey registered successfully.", "success")
    return redirect(url_for_security("wan_register"))


@security_bp.route("/wan-signin", methods=["GET", "POST"])
async def wan_signin():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)
    if not current_app.config.get("SECURITY_WAN_ALLOW_AS_FIRST_FACTOR", True):
        abort(404)

    form = await WebAuthnVerifyForm.from_formdata()
    response_form = await QuartForm.from_formdata()

    credential_options = None
    if _is_post():
        await _enforce_csrf(getattr(form, "_submitted_csrf", None))
        identity = _normalize_email(form.identity.data)
        if not identity:
            await flash("Email is required.", "error")
            return await render_template(
                "security/wan_signin.html",
                wan_signin_form=form,
                wan_signin_response_form=response_form,
                credential_options=None,
            )

        user = await _find_user(email=identity)
        if user is None or not getattr(user, "active", True):
            await flash("Unable to authenticate with passkey.", "error")
            return await render_template(
                "security/wan_signin.html",
                wan_signin_form=form,
                wan_signin_response_form=response_form,
                credential_options=None,
            )

        credentials = await _list_webauthn_credentials(user)
        credentials = [
            credential
            for credential in credentials
            if getattr(credential, "usage", "secondary") in {"primary", "first"}
        ]
        if not credentials:
            await flash("No passkey is configured for passwordless sign-in.", "error")
            return await render_template(
                "security/wan_signin.html",
                wan_signin_form=form,
                wan_signin_response_form=response_form,
                credential_options=None,
            )

        challenge = secrets.token_bytes(32)
        options = await wan.begin_authentication(
            credentials,
            rp_id=_webauthn_rp_id(),
            challenge=challenge,
        )
        credential_options = wan.options_to_json_dict(options)
        _set_wan_state(
            "wan_signin_state",
            challenge=wan.bytes_to_base64url(challenge),
            user_id=user.get_id(),
            remember=bool(form.remember.data),
        )

    return await render_template(
        "security/wan_signin.html",
        wan_signin_form=form,
        wan_signin_response_form=response_form,
        credential_options=credential_options,
    )


@security_bp.route("/wan-signin-response", methods=["POST"])
async def wan_signin_response():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)
    if not current_app.config.get("SECURITY_WAN_ALLOW_AS_FIRST_FACTOR", True):
        abort(404)

    await _enforce_csrf()
    state = _pop_wan_state("wan_signin_state")
    if not state:
        await flash("Passkey sign-in expired. Please try again.", "error")
        return redirect(url_for_security("wan_signin"))

    user = await _find_user(fs_uniquifier=state.get("user_id"))
    if user is None:
        await flash("Unable to find user for passkey sign-in.", "error")
        return redirect(url_for_security("wan_signin"))

    credential_payload = await _extract_webauthn_credential_payload()
    credential_id = _extract_webauthn_credential_id(credential_payload)
    if not credential_payload or credential_id is None:
        await flash("Invalid passkey response payload.", "error")
        return redirect(url_for_security("wan_signin"))

    stored_credential = await _find_webauthn_credential(credential_id, user=user)
    if stored_credential is None:
        await flash("Passkey not recognized.", "error")
        return redirect(url_for_security("wan_signin"))

    try:
        new_sign_count = await wan.complete_authentication(
            credential_payload,
            challenge=wan.base64url_to_bytes(state["challenge"]),
            rp_id=_webauthn_rp_id(),
            expected_origin=_webauthn_expected_origin(),
            stored_credential=stored_credential,
            require_user_verification=current_app.config.get(
                "SECURITY_WAN_REQUIRE_USER_VERIFICATION", True
            ),
        )
    except Exception:
        await flash("Passkey verification failed.", "error")
        return redirect(url_for_security("wan_signin"))

    stored_credential.sign_count = int(new_sign_count)
    if hasattr(stored_credential, "lastuse_datetime"):
        stored_credential.lastuse_datetime = datetime.datetime.utcnow()

    session.permanent = bool(state.get("remember"))
    await _security.login_user(user)
    return redirect(_resolve_redirect("SECURITY_POST_LOGIN_VIEW", "login"))


@security_bp.route("/wan-verify", methods=["GET", "POST"])
@auth_required("session")
async def wan_verify():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)
    if not current_app.config.get("SECURITY_WAN_ALLOW_AS_MULTI_FACTOR", True):
        abort(404)

    form = await WebAuthnVerifyForm.from_formdata()
    response_form = await QuartForm.from_formdata()
    credential_options = None

    if _is_post():
        await _enforce_csrf(getattr(form, "_submitted_csrf", None))
        credentials = await _list_webauthn_credentials(current_user)
        credentials = [
            credential
            for credential in credentials
            if getattr(credential, "usage", "secondary") in {"secondary", "primary"}
        ]
        if not credentials:
            await flash("No passkey is configured for this account.", "error")
            return await render_template(
                "security/wan_verify.html",
                wan_verify_form=form,
                wan_verify_response_form=response_form,
                credential_options=None,
            )

        challenge = secrets.token_bytes(32)
        options = await wan.begin_authentication(
            credentials,
            rp_id=_webauthn_rp_id(),
            challenge=challenge,
        )
        credential_options = wan.options_to_json_dict(options)
        _set_wan_state(
            "wan_verify_state",
            challenge=wan.bytes_to_base64url(challenge),
            user_id=current_user.get_id(),
            next=_safe_redirect_target(request.args.get("next"), fallback="/"),
        )

    return await render_template(
        "security/wan_verify.html",
        wan_verify_form=form,
        wan_verify_response_form=response_form,
        credential_options=credential_options,
    )


@security_bp.route("/wan-verify-response", methods=["POST"])
@auth_required("session")
async def wan_verify_response():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)
    if not current_app.config.get("SECURITY_WAN_ALLOW_AS_MULTI_FACTOR", True):
        abort(404)

    await _enforce_csrf()
    state = _pop_wan_state("wan_verify_state")
    if not state:
        await flash("Passkey verification expired. Please try again.", "error")
        return redirect(url_for_security("wan_verify"))

    if state.get("user_id") != current_user.get_id():
        await flash("Passkey verification context mismatch.", "error")
        return redirect(url_for_security("wan_verify"))

    credential_payload = await _extract_webauthn_credential_payload()
    credential_id = _extract_webauthn_credential_id(credential_payload)
    if not credential_payload or credential_id is None:
        await flash("Invalid passkey response payload.", "error")
        return redirect(url_for_security("wan_verify"))

    stored_credential = await _find_webauthn_credential(credential_id, user=current_user)
    if stored_credential is None:
        await flash("Passkey not recognized.", "error")
        return redirect(url_for_security("wan_verify"))

    try:
        new_sign_count = await wan.complete_authentication(
            credential_payload,
            challenge=wan.base64url_to_bytes(state["challenge"]),
            rp_id=_webauthn_rp_id(),
            expected_origin=_webauthn_expected_origin(),
            stored_credential=stored_credential,
            require_user_verification=current_app.config.get(
                "SECURITY_WAN_REQUIRE_USER_VERIFICATION", True
            ),
        )
    except Exception:
        await flash("Passkey verification failed.", "error")
        return redirect(url_for_security("wan_verify"))

    stored_credential.sign_count = int(new_sign_count)
    if hasattr(stored_credential, "lastuse_datetime"):
        stored_credential.lastuse_datetime = datetime.datetime.utcnow()

    session["_fresh"] = True
    await _commit()

    await flash("Passkey verification successful.", "success")
    return redirect(_safe_redirect_target(state.get("next"), fallback="/"))


@security_bp.route("/wan-delete", methods=["POST"])
@auth_required("session")
async def wan_delete():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)

    payload = await request.get_json(silent=True)
    csrf_token = None
    credential_name = None
    credential_id = None

    if isinstance(payload, dict):
        csrf_token = payload.get("csrf_token")
        credential_name = payload.get("name")
        credential_id = payload.get("credential_id")
    else:
        form_data = await request.form
        csrf_token = form_data.get("csrf_token")
        credential_name = form_data.get("name")
        credential_id = form_data.get("credential_id")

    await _enforce_csrf(csrf_token)

    credentials = await _list_webauthn_credentials(current_user)
    target = None

    if credential_id:
        try:
            decoded = wan.base64url_to_bytes(str(credential_id))
        except Exception:
            decoded = None
        if decoded is not None:
            target = await _find_webauthn_credential(decoded, user=current_user)

    if target is None and credential_name:
        for credential in credentials:
            if getattr(credential, "name", None) == credential_name:
                target = credential
                break

    if target is None:
        await flash("Passkey not found.", "error")
        if isinstance(payload, dict):
            return {"error": "Passkey not found"}, 404
        return redirect(url_for_security("wan_register"))

    await _delete_webauthn_credential(current_user, target)
    await _commit()
    await flash("Passkey removed.", "success")
    if isinstance(payload, dict):
        return {"status": "ok"}
    return redirect(url_for_security("wan_register"))
