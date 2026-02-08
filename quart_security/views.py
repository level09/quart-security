"""Auth blueprint and route handlers."""

from __future__ import annotations

import datetime
import secrets

from quart import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)
from werkzeug.routing import BuildError

from .decorators import auth_required
from .forms import (
    QuartForm,
    RecoveryCodeForm,
    TwoFactorSetupForm,
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

    if _is_post() and form.validate():
        token = form.token.data.strip()
        valid = False

        if getattr(user, "tf_totp_secret", None):
            valid = verify_totp(user.tf_totp_secret, token)

        if not valid and current_app.config.get(
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
    return await render_template(
        "security/wan_register.html",
        wan_register_form=form,
        credential_options=None,
        registered_credentials=[],
    )


@security_bp.route("/wan-register-response", methods=["POST"])
async def wan_register_response():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)
    return jsonify({"error": "WebAuthn registration response not implemented"}), 501


@security_bp.route("/wan-signin", methods=["GET", "POST"])
async def wan_signin():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)

    form = await WebAuthnVerifyForm.from_formdata()
    return await render_template("security/wan_signin.html", wan_signin_form=form)


@security_bp.route("/wan-signin-response", methods=["POST"])
async def wan_signin_response():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)
    return jsonify({"error": "WebAuthn signin response not implemented"}), 501


@security_bp.route("/wan-verify", methods=["GET", "POST"])
@auth_required("session")
async def wan_verify():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)

    form = await WebAuthnVerifyForm.from_formdata()
    return await render_template("security/wan_verify.html", wan_verify_form=form)


@security_bp.route("/wan-verify-response", methods=["POST"])
async def wan_verify_response():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)
    return jsonify({"error": "WebAuthn verify response not implemented"}), 501
