"""Auth blueprint and route handlers."""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import hmac
import json
import secrets
import time
import uuid
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
from sqlalchemy.exc import IntegrityError
from werkzeug.routing import BuildError

from . import webauthn as wan
from .breach import password_is_breached
from .decorators import auth_required
from .forms import (
    QuartForm,
    RecoveryCodeForm,
    TwoFactorSetupForm,
    TwoFactorVerifyForm,
    WebAuthnRegisterForm,
    WebAuthnVerifyForm,
)
from .password import (
    hash_password_async,
    password_needs_rehash,
    unknown_user_hash_async,
    validate_password,
    verify_password_async,
)
from .proxies import _security, current_user
from .signals import (
    password_changed,
    tf_profile_changed,
    user_register_conflict,
    user_registered,
)
from .utils import maybe_await, naive_utcnow, url_for_security

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
    return await maybe_await(_security.datastore.find_user(**kwargs))


async def _create_user(**kwargs):
    return await maybe_await(_security.datastore.create_user(**kwargs))


async def _commit():
    await maybe_await(_security.datastore.commit())


def _account_is_locked(user) -> bool:
    locked_until = getattr(user, "locked_until", None)
    return bool(locked_until and naive_utcnow() < locked_until)


async def _record_auth_failure(user):
    max_attempts = current_app.config["SECURITY_LOGIN_MAX_ATTEMPTS"]
    if not max_attempts:
        return
    await maybe_await(
        _security.datastore.record_auth_failure(
            user,
            max_attempts=max_attempts,
            lockout_minutes=current_app.config["SECURITY_LOCKOUT_MINUTES"],
        )
    )


async def _record_failure_job(user_id):
    user = await _find_user(fs_uniquifier=user_id)
    if user is not None:
        await _record_auth_failure(user)


async def _reset_auth_failures(user):
    if hasattr(user, "failed_login_count"):
        user.failed_login_count = 0
        user.locked_until = None
        await _commit()


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
    # Reject control characters (ASCII 0-31)
    if any(ord(c) < 32 for c in candidate):
        return fallback
    # Reject backslash variants before any query string
    path_part = candidate.split("?", 1)[0]
    if "\\" in path_part:
        return fallback
    parts = urlsplit(candidate)
    if parts.scheme or parts.netloc:
        return fallback
    if not candidate.startswith("/") or candidate.startswith("//"):
        return fallback
    return candidate


# A login that finishes later than this after the form was shown ignores its
# `next`, so an abandoned target cannot redirect an unrelated later sign-in.
NEXT_TTL_SECONDS = 600


async def _complete_login(user):
    """Log the user in and send them where `/login?next=` asked, if it was safe."""
    # login_user clears the session, so read the target first.
    target, stored_at = session.pop("security_next", None) or (None, 0)
    if time.time() - stored_at > NEXT_TTL_SECONDS:
        target = None
    await _security.login_user(user)
    fallback = _resolve_redirect("SECURITY_POST_LOGIN_VIEW", "login")
    return redirect(_safe_redirect_target(target, fallback=fallback))


RESET_SUBJECT = "Reset your password"
RESET_NOTICE_SUBJECT = "Your password was reset"
CONFIRM_SUBJECT = "Confirm your email address"
REGISTER_CONFLICT_SUBJECT = "Sign-up attempt with your email"


def _public_url(endpoint: str, **values) -> str:
    """An absolute link for email, from SECURITY_PUBLIC_URL and never the Host
    header, which whoever triggers the mail controls."""
    base = current_app.config.get("SECURITY_PUBLIC_URL")
    if not base:
        raise RuntimeError("SECURITY_PUBLIC_URL is required to build email links")
    return base.rstrip("/") + url_for_security(endpoint, **values)


def _token_key(raw: str) -> str:
    # Only the hash is stored, so a copy of the state table cannot replay links.
    return hashlib.sha256(raw.encode()).hexdigest()


def _password_fingerprint(user) -> str:
    # Ties a reset link to the password it replaces: any change voids the link.
    return hashlib.sha256((user.password or "").encode()).hexdigest()


def _new_link(endpoint: str) -> tuple[str, str]:
    """A fresh single-use token and the emailed link that carries it. Built in
    the request, where url_for works; stored later, only if an account needs it,
    so making one costs the same whether or not the email has an account."""
    raw = secrets.token_urlsafe(32)
    return raw, _public_url(endpoint, token=raw)


async def _store_link(raw: str, payload: dict, within: str):
    ttl = int(current_app.config[within].total_seconds())
    await _security.state_store.put(payload, ttl=ttl, token=_token_key(raw))


def _defer(job, *args):
    """Run `job(*args)` after the response, on its own datastore session. Work
    that depends on whether an email has an account (lookups, token writes,
    mail) happens here, so the response takes the same time either way."""
    datastore = _security.datastore

    async def run():
        # The task inherits the request's context; give it its own session.
        begin = getattr(datastore, "begin_request", None)
        if begin:
            begin()
        try:
            await job(*args)
        finally:
            close = getattr(datastore, "close", None)
            if close:
                await maybe_await(close())

    current_app.add_background_task(run)


async def _mail(template: str, subject: str, user, **context):
    """Render security/email/<template>.txt and send it. Runs in a deferred job,
    outside any request, so links arrive already built in `context`."""
    found = current_app.jinja_env.get_template(f"security/email/{template}.txt")
    body = await found.render_async(user=user, **context)
    await _security.send_mail(subject, user.email, body)


async def _send_confirmation_job(email: str, raw: str, link: str):
    user = await _find_user(email=email)
    if user is None or not getattr(user, "active", True):
        return
    if not _awaiting_confirmation(user):
        return
    await _store_confirmation(user, raw)
    await _mail(
        "confirmation_instructions", CONFIRM_SUBJECT, user, confirmation_link=link
    )


async def _store_confirmation(user, raw: str):
    await _store_link(
        raw,
        {"confirm_user_id": user.get_id(), "email": user.email},
        "SECURITY_CONFIRM_EMAIL_WITHIN",
    )


async def _password_errors(password: str) -> list[str]:
    errors = validate_password(
        password,
        min_length=current_app.config.get("SECURITY_PASSWORD_LENGTH_MIN", 12),
    )
    if not errors and current_app.config.get("SECURITY_PASSWORD_BREACH_CHECK", True):
        count_min = current_app.config.get("SECURITY_PASSWORD_BREACH_COUNT_MIN", 1)
        if await password_is_breached(password, count_min=count_min):
            errors = ["This password has appeared in a data breach. Choose another."]
    return errors


def _awaiting_confirmation(user) -> bool:
    return bool(
        current_app.config.get("SECURITY_CONFIRMABLE")
        and getattr(user, "confirmed_at", None) is None
    )


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


async def _set_wan_state(key: str, **payload):
    await _pop_wan_state(key)
    if key == "tf_setup_state":
        from .totp import encrypt_totp_secret

        payload["secret"] = encrypt_totp_secret(payload["secret"])
    session[key] = await _security.state_store.put(payload, ttl=300)


async def _pop_wan_state(key: str) -> dict | None:
    token = session.pop(key, None)
    return await _security.state_store.pop(token) if isinstance(token, str) else None


async def _verify_totp_once(secret, token):
    from .totp import decrypt_totp_secret, matching_totp_step

    if not secret or not token:
        return False
    secret = decrypt_totp_secret(secret)
    step = matching_totp_step(secret, token)
    if step is None:
        return False
    key = current_app.secret_key
    if isinstance(key, str):
        key = key.encode()
    digest = hmac.new(key, secret.encode(), hashlib.sha256).hexdigest()
    return await _security.state_store.claim(f"totp:{digest}:{step}", ttl=120)


async def _consume_recovery_code(user, token):
    from .totp import ensure_hashed_recovery_codes, verify_recovery_code

    codes = list(user.mf_recovery_codes or [])
    ok, remaining = verify_recovery_code(
        token, codes, secret_key=current_app.secret_key
    )
    return bool(
        ok
        and await maybe_await(
            _security.datastore.replace_recovery_codes(
                user,
                codes,
                ensure_hashed_recovery_codes(remaining, current_app.secret_key),
            )
        )
    )


async def _list_webauthn_credentials(user, usage: str | None = None):
    getter = getattr(_security.datastore, "get_webauthn_credentials", None)
    if getter:
        return await maybe_await(getter(user, usage=usage))
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
        return await maybe_await(finder(credential_id, user=user))

    candidates = list(getattr(user, "webauthn", None) or []) if user else []
    for credential in candidates:
        if getattr(credential, "credential_id", None) == credential_id:
            return credential
    return None


async def _find_webauthn_credential_owner(credential):
    finder = getattr(_security.datastore, "find_user_for_webauthn_credential", None)
    if finder:
        return await maybe_await(finder(credential))
    related_user = getattr(credential, "user", None)
    if related_user is not None:
        return related_user
    owner_id = getattr(credential, "user_id", None)
    if owner_id is None:
        return None
    return await _find_user(fs_webauthn_user_handle=owner_id)


async def _create_webauthn_credential(user, **kwargs):
    creator = getattr(_security.datastore, "create_webauthn_credential", None)
    if creator:
        return await maybe_await(creator(user, **kwargs))
    raise RuntimeError("Datastore does not implement create_webauthn_credential")


async def _delete_webauthn_credential(user, credential):
    deleter = getattr(_security.datastore, "delete_webauthn_credential", None)
    if deleter:
        return await maybe_await(deleter(user, credential))

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


def _extract_webauthn_user_handle(credential_payload: dict | None) -> str | None:
    if not isinstance(credential_payload, dict):
        return None
    response = credential_payload.get("response")
    if not isinstance(response, dict):
        return None
    user_handle = response.get("userHandle")
    if not isinstance(user_handle, str) or not user_handle:
        return None
    try:
        return wan.base64url_to_bytes(user_handle).decode("utf-8")
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
    if not _is_post():
        # Every visit to the form replaces the target, so an abandoned one never
        # redirects a later login. The passkey and 2FA paths finish with it too.
        next_url = _safe_redirect_target(request.args.get("next"), fallback="")
        if next_url:
            session["security_next"] = [next_url, int(time.time())]
        else:
            session.pop("security_next", None)

    if _is_post() and form.validate():
        user = await _find_user(email=_normalize_email(form.email.data))

        # A locked account fails like a wrong password, after the same work: a
        # distinct "locked" answer would only ever appear for real accounts.
        locked = user is not None and _account_is_locked(user)
        if user and not locked and getattr(user, "locked_until", None):
            # Lock expired, reset
            user.failed_login_count = 0
            user.locked_until = None
            await _commit()

        # Always run one verify, so response time does not reveal which emails
        # have an active account. An unconfirmed account fails like an unknown
        # one: otherwise registering an email and trying its password would
        # tell whether the email already had an account.
        known = (
            user is not None
            and getattr(user, "active", True)
            and not _awaiting_confirmation(user)
            and not locked
        )
        password_ok = await verify_password_async(
            form.password.data,
            user.password if known else await unknown_user_hash_async(),
        )
        if known and password_ok:
            # Transparent rehash: upgrade weak/legacy hash on successful login
            if password_needs_rehash(user.password):
                user.password = await hash_password_async(form.password.data)
                await _commit()

            if current_app.config.get("SECURITY_TWO_FACTOR") and getattr(
                user, "tf_primary_method", None
            ):
                session["tf_user_id"] = await _security.state_store.put(
                    {"user_id": user.get_id()}, ttl=300
                )
                return redirect(url_for_security("two_factor_token_validation"))

            await _reset_auth_failures(user)
            return await _complete_login(user)

        # Track failed login after the response: the write happens only for real
        # accounts, and its time must not tell them apart.
        if user and not locked:
            _defer(_record_failure_job, user.get_id())

        if current_app.config.get("SECURITY_CONFIRMABLE"):
            # One message for every failure, so it never says which case applied.
            await flash(
                "Invalid email or password, or the email is not confirmed yet",
                "error",
            )
        else:
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
        # Password checks come first and an existing email gets the same answer as
        # a new one, after the same hashing work, so the form never reveals which
        # emails have an account.
        errors = await _password_errors(form.password.data)
        if errors:
            for error in errors:
                await flash(error, "error")
            return await render_template(
                "security/register_user.html", register_user_form=form
            )

        password = await hash_password_async(form.password.data)
        name = (form.name.data or "").strip() if hasattr(form, "name") else ""
        app = current_app._get_current_object()
        confirmable = current_app.config.get("SECURITY_CONFIRMABLE")
        if confirmable:
            raw, confirm_link = _new_link("confirm_email")
            recoverable = current_app.config.get("SECURITY_RECOVERABLE")
            links = {
                "confirm": confirm_link,
                "login": _public_url("login"),
                "reset": _public_url("forgot_password") if recoverable else None,
            }
            _defer(_register_job, app, email, password, name, raw, links)
        else:
            # Without confirmation the new account signs in at once, which
            # reveals it anyway; create it before answering.
            await _register_job(app, email, password, name, None, {})

        if confirmable:
            await flash("Check your email to confirm your account.", "success")
        else:
            await flash("Registration successful. Please log in.", "success")
        return redirect(_resolve_redirect("SECURITY_POST_REGISTER_VIEW", "login"))

    return await render_template("security/register_user.html", register_user_form=form)


async def _register_job(app, email, password, name, confirm_raw, links):
    """Create the account, or tell the owner of the existing one. With
    confirmation on this runs after the response, so neither case is slower."""
    confirmable = confirm_raw is not None
    existing = await _find_user(email=email)
    if existing is None:
        user_kwargs = {"email": email, "password": password, "active": True}
        if name:
            user_kwargs["name"] = name
        user = await _create_user(**user_kwargs)
        if hasattr(user, "confirmed_at"):
            # Set either way: a model default must not confirm a sign-up.
            user.confirmed_at = None if confirmable else naive_utcnow()
        try:
            await _commit()
        except IntegrityError:
            # Another request registered this email after the lookup above.
            await maybe_await(_security.datastore.rollback())
            existing = await _find_user(email=email)
            if existing is None:
                raise
        else:
            # Receivers run before the mail, so a mail failure cannot skip them;
            # the owner can ask for a new link at /confirm.
            await user_registered.send_async(app, user=user)
            if confirmable:
                await _store_confirmation(user, confirm_raw)
                await _mail(
                    "confirmation_instructions",
                    CONFIRM_SUBJECT,
                    user,
                    confirmation_link=links["confirm"],
                )
    if existing is not None:
        await user_register_conflict.send_async(app, user=existing)
        if confirmable:
            await _mail(
                "register_conflict",
                REGISTER_CONFLICT_SUBJECT,
                existing,
                login_link=links["login"],
                reset_link=links["reset"],
            )


@security_bp.route("/reset", methods=["GET", "POST"])
async def forgot_password():
    if not current_app.config.get("SECURITY_RECOVERABLE"):
        abort(404)
    form = await _security.forgot_password_form_cls.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        raw, link = _new_link("reset_password")
        _defer(_reset_job, _normalize_email(form.email.data), raw, link)
        await flash(
            "If an account uses that email, a link to reset its password is on"
            " its way.",
            "info",
        )
        return redirect(url_for_security("login"))

    return await render_template(
        "security/forgot_password.html", forgot_password_form=form
    )


async def _reset_job(email: str, raw: str, link: str):
    user = await _find_user(email=email)
    if user is None or not getattr(user, "active", True):
        return
    await _store_link(
        raw,
        {
            "reset_user_id": user.get_id(),
            "email": user.email,
            "password": _password_fingerprint(user),
        },
        "SECURITY_RESET_PASSWORD_WITHIN",
    )
    # To the stored address, never the one typed into the form.
    await _mail("reset_instructions", RESET_SUBJECT, user, reset_link=link)


async def _reset_link_user(state):
    if not state or "reset_user_id" not in state:
        return None
    user = await _find_user(fs_uniquifier=state["reset_user_id"])
    if user is None:
        return None
    # The identity map may hold the copy loaded earlier in this request; read
    # the row again so an email or password changed meanwhile is seen.
    refresh = getattr(_security.datastore, "refresh", None)
    if refresh:
        await maybe_await(refresh(user))
    if not getattr(user, "active", True):
        return None
    # A changed email or password voids the link: it was sent to the old inbox.
    if user.email != state["email"]:
        return None
    if not hmac.compare_digest(state["password"], _password_fingerprint(user)):
        return None
    return user


@security_bp.route("/reset/<token>", methods=["GET", "POST"])
async def reset_password(token):
    if not current_app.config.get("SECURITY_RECOVERABLE"):
        abort(404)
    key = _token_key(token)
    # A GET only looks: mail scanners open links, and must not spend the token.
    user = await _reset_link_user(await _security.state_store.get(key))
    if user is None:
        await flash("This reset link is invalid or has expired.", "error")
        return redirect(url_for_security("forgot_password"))

    form = await _security.reset_password_form_cls.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))
    if _is_post() and form.validate():
        errors = await _password_errors(form.password.data)
        for error in errors:
            await flash(error, "error")
        if not errors:
            # Hash first: the slow step must not sit between the final check of
            # the account and the update that rotates it.
            password = await hash_password_async(form.password.data)
            if await _reset_link_user(await _security.state_store.pop(key)) is None:
                await flash("This reset link is invalid or has expired.", "error")
                return redirect(url_for_security("forgot_password"))
            user.password = password
            # The link reached the inbox, which is what confirmation proves.
            if hasattr(user, "confirmed_at") and user.confirmed_at is None:
                user.confirmed_at = naive_utcnow()
            if hasattr(user, "failed_login_count"):
                user.failed_login_count = 0
                user.locked_until = None
            # Signs out every session, including whoever knew the old password.
            rotated = await maybe_await(
                _security.datastore.rotate_uniquifier(
                    user, user.get_id(), uuid.uuid4().hex
                )
            )
            if not rotated:
                abort(409)
            app = current_app._get_current_object()
            await password_changed.send_async(app, user=user)
            _defer(_mail, "reset_notice", RESET_NOTICE_SUBJECT, user)
            await flash("Your password was reset. Sign in with the new one.", "success")
            return redirect(url_for_security("login"))

    return await render_template(
        "security/reset_password.html",
        reset_password_form=form,
        reset_password_token=token,
    )


def _confirmation_routes_enabled() -> bool:
    # Only sign-ups wait for confirmation, so the routes exist only with sign-up.
    config = current_app.config
    return bool(
        config.get("SECURITY_CONFIRMABLE") and config.get("SECURITY_REGISTERABLE")
    )


@security_bp.route("/confirm", methods=["GET", "POST"])
async def send_confirmation():
    if not _confirmation_routes_enabled():
        abort(404)
    form = await _security.send_confirmation_form_cls.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        raw, link = _new_link("confirm_email")
        _defer(_send_confirmation_job, _normalize_email(form.email.data), raw, link)
        await flash(
            "If that email is waiting to be confirmed, a new link is on its way.",
            "info",
        )
        return redirect(url_for_security("login"))

    return await render_template(
        "security/send_confirmation.html", send_confirmation_form=form
    )


@security_bp.route("/confirm/<token>", methods=["GET", "POST"])
async def confirm_email(token):
    if not _confirmation_routes_enabled():
        abort(404)
    form = await QuartForm.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))
    # A GET only shows a button. Mail scanners open every link, and confirming
    # on GET would let one confirm an account someone else registered with this
    # address, keeping that person's password.
    key = _token_key(token)
    store = _security.state_store
    state = await (store.pop(key) if _is_post() else store.get(key))
    user = None
    if state and "confirm_user_id" in state:
        user = await _find_user(fs_uniquifier=state["confirm_user_id"])
    # A link sent before an email change does not confirm the new address.
    if user is None or user.email != state.get("email"):
        await flash("This confirmation link is invalid or has expired.", "error")
        return redirect(url_for_security("send_confirmation"))
    if not _is_post():
        return await render_template(
            "security/confirm_email.html",
            confirm_email_form=form,
            confirm_email_token=token,
        )
    if user.confirmed_at is None:
        user.confirmed_at = naive_utcnow()
        await _commit()
    await flash("Your email is confirmed. You can sign in now.", "success")
    return redirect(url_for_security("login"))


@security_bp.route("/logout", methods=["POST"])
async def logout():
    await _enforce_csrf()
    await _security.logout_user()
    await flash("You have been logged out.", "info")
    return redirect(url_for_security("login"))


@security_bp.route("/change", methods=["GET", "POST"])
@auth_required("session", fresh=True)
async def change_password():
    if not current_app.config.get("SECURITY_CHANGEABLE", False):
        abort(404)

    form = await _security.change_password_form_cls.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        user = current_user

        has_usable_password = getattr(user, "has_usable_password", True)
        if has_usable_password and getattr(user, "password", None):
            current_password = form.password.data or ""
            if not current_password:
                await flash("Current password is required", "error")
                return await render_template(
                    "security/change_password.html", change_password_form=form
                )
            if not await verify_password_async(current_password, user.password):
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

        if current_app.config.get("SECURITY_PASSWORD_BREACH_CHECK", True):
            count_min = current_app.config.get("SECURITY_PASSWORD_BREACH_COUNT_MIN", 1)
            breached = await password_is_breached(
                form.new_password.data, count_min=count_min
            )
            if breached:
                await flash(
                    "This password has appeared in a data breach."
                    " Choose a different one.",
                    "error",
                )
                return await render_template(
                    "security/change_password.html", change_password_form=form
                )

        user.password = await hash_password_async(form.new_password.data)
        if hasattr(user, "password_set"):
            user.password_set = True

        await _security.revoke_user_sessions(user)
        await password_changed.send_async(current_app._get_current_object(), user=user)

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
@auth_required("session", fresh=True)
async def two_factor_setup():
    if not current_app.config.get("SECURITY_TWO_FACTOR", False):
        abort(404)

    from .totp import (
        generate_qr_code,
        generate_recovery_codes,
        generate_totp_secret,
        get_totp_uri,
        hash_recovery_codes,
    )

    primary_method = getattr(current_user, "tf_primary_method", None) or "none"

    if _is_post():
        form_data = await request.form
        await _enforce_csrf(form_data.get("csrf_token"))
        action = form_data.get("action")

        if action == "disable":
            token = (form_data.get("token") or "").strip()
            valid = await _verify_totp_once(current_user.tf_totp_secret, token)
            if (
                not valid
                and token
                and current_app.config["SECURITY_MULTI_FACTOR_RECOVERY_CODES"]
            ):
                valid = await _consume_recovery_code(current_user, token)
            if current_user.tf_primary_method and not valid:
                await flash("Current authentication code is required.", "error")
                return redirect(url_for_security("two_factor_setup"))
            current_user.tf_totp_secret = None
            current_user.tf_primary_method = None
            current_user.mf_recovery_codes = []
            await _pop_wan_state("tf_setup_state")
            await _security.revoke_user_sessions(current_user)
            await tf_profile_changed.send_async(
                current_app._get_current_object(), user=current_user
            )
            await flash("Two-factor authentication disabled.", "success")
            return redirect(url_for_security("two_factor_setup"))

        if action == "verify":
            token = (form_data.get("token") or "").strip()
            pending = await _pop_wan_state("tf_setup_state")
            pending_secret = pending.get("secret") if pending else None
            if (
                pending_secret
                and pending["user_id"] == current_user.get_id()
                and not current_user.tf_primary_method
                and token
                and await _verify_totp_once(pending_secret, token)
            ):
                from .totp import encrypt_totp_secret

                current_user.tf_totp_secret = encrypt_totp_secret(pending_secret)
                current_user.tf_primary_method = "authenticator"

                raw_codes = []
                if current_app.config.get("SECURITY_MULTI_FACTOR_RECOVERY_CODES", True):
                    if not getattr(current_user, "mf_recovery_codes", None):
                        count = current_app.config.get(
                            "SECURITY_MULTI_FACTOR_RECOVERY_CODES_N", 3
                        )
                        raw_codes = generate_recovery_codes(count)
                        current_user.mf_recovery_codes = hash_recovery_codes(
                            raw_codes, current_app.secret_key
                        )

                await _security.revoke_user_sessions(current_user)
                await tf_profile_changed.send_async(
                    current_app._get_current_object(), user=current_user
                )
                await flash("Two-factor authentication enabled.", "success")
                recovery_form = await QuartForm.from_formdata()
                return await render_template(
                    "security/mf_recovery_codes.html",
                    recovery_codes=raw_codes,
                    has_codes=True,
                    mf_recovery_codes_form=recovery_form,
                )

            await flash("Invalid authentication code.", "error")
            return redirect(
                url_for_security("two_factor_setup") + "?setup=authenticator"
            )

    setup_form = await TwoFactorSetupForm.from_formdata()
    chosen_method = None
    authr_qrcode = None
    authr_key = None

    # Only show QR when user explicitly chose to set up authenticator
    if primary_method == "none" and request.args.get("setup") == "authenticator":
        chosen_method = "authenticator"
        token = session.get("tf_setup_state")
        pending = (
            await _security.state_store.get(token) if isinstance(token, str) else None
        )
        if not pending or pending["user_id"] != current_user.get_id():
            pending_secret = generate_totp_secret()
            await _set_wan_state(
                "tf_setup_state", secret=pending_secret, user_id=current_user.get_id()
            )
        else:
            from .totp import decrypt_totp_secret

            pending_secret = decrypt_totp_secret(pending["secret"])
        authr_key = pending_secret
        issuer = current_app.config.get("SECURITY_TOTP_ISSUER", "Quart")
        uri = get_totp_uri(pending_secret, current_user.email, issuer)
        authr_qrcode = await asyncio.to_thread(generate_qr_code, uri)

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

    form = await TwoFactorVerifyForm.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))
    state_token = session.get("tf_user_id")
    tf_state = (
        await _security.state_store.get(state_token)
        if isinstance(state_token, str)
        else None
    )
    if not tf_state:
        session.pop("tf_user_id", None)
        return redirect(url_for_security("login"))
    user_id = tf_state.get("user_id")
    if not user_id:
        return redirect(url_for_security("login"))

    user = await _find_user(fs_uniquifier=user_id)
    if user is None or not getattr(user, "active", True):
        session.pop("tf_user_id", None)
        return redirect(url_for_security("login"))
    if _account_is_locked(user):
        await flash("Account temporarily locked. Try again later.", "error")
        return redirect(url_for_security("login"))

    if _is_post():
        form_data = await request.form
        token = (form_data.get("code") or form_data.get("token") or "").strip()
        valid = False

        if token and getattr(user, "tf_totp_secret", None):
            valid = await _verify_totp_once(user.tf_totp_secret, token)

        if (
            not valid
            and token
            and current_app.config.get("SECURITY_MULTI_FACTOR_RECOVERY_CODES", True)
        ):
            valid = await _consume_recovery_code(user, token)

        if valid:
            if await _pop_wan_state("tf_user_id") is None:
                return redirect(url_for_security("login"))
            session.pop("tf_user_id", None)
            await _reset_auth_failures(user)
            return await _complete_login(user)

        await _record_auth_failure(user)
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
@auth_required("session", fresh=True)
async def mf_recovery_codes():
    if not current_app.config.get("SECURITY_MULTI_FACTOR_RECOVERY_CODES", True):
        abort(404)

    from .totp import generate_recovery_codes, hash_recovery_codes

    # A dummy form just for hidden_tag() CSRF support
    form = await QuartForm.from_formdata()
    codes = []

    if _is_post():
        await _enforce_csrf()
        count = current_app.config.get("SECURITY_MULTI_FACTOR_RECOVERY_CODES_N", 3)
        codes = generate_recovery_codes(count)
        current_user.mf_recovery_codes = hash_recovery_codes(
            codes, current_app.secret_key
        )
        await _security.revoke_user_sessions(current_user)
        await tf_profile_changed.send_async(
            current_app._get_current_object(), user=current_user
        )
        await flash("Recovery codes regenerated.", "success")

    has_codes = bool(getattr(current_user, "mf_recovery_codes", None))

    return await render_template(
        "security/mf_recovery_codes.html",
        recovery_codes=codes,
        has_codes=has_codes or bool(codes),
        mf_recovery_codes_form=form,
    )


@security_bp.route("/mf-recovery", methods=["GET", "POST"])
async def mf_recovery():
    if not current_app.config.get(
        "SECURITY_TWO_FACTOR", False
    ) or not current_app.config.get("SECURITY_MULTI_FACTOR_RECOVERY_CODES", True):
        abort(404)
    form = await RecoveryCodeForm.from_formdata()
    await _enforce_csrf(getattr(form, "_submitted_csrf", None))

    if _is_post() and form.validate():
        state_token = session.get("tf_user_id")
        tf_state = (
            await _security.state_store.get(state_token)
            if isinstance(state_token, str)
            else None
        )
        if not tf_state:
            session.pop("tf_user_id", None)
            return redirect(url_for_security("login"))
        user_id = tf_state.get("user_id")
        if not user_id:
            return redirect(url_for_security("login"))

        user = await _find_user(fs_uniquifier=user_id)
        if user is None or not getattr(user, "active", True):
            return redirect(url_for_security("login"))
        if _account_is_locked(user):
            return redirect(url_for_security("login"))

        if await _consume_recovery_code(user, form.code.data.strip()):
            if await _pop_wan_state("tf_user_id") is None:
                return redirect(url_for_security("login"))
            session.pop("tf_user_id", None)
            await _reset_auth_failures(user)
            return await _complete_login(user)

        await _record_auth_failure(user)
        await flash("Invalid recovery code", "error")

    return await render_template("security/mf_recovery.html", recovery_form=form)


@security_bp.route("/wan-register", methods=["GET", "POST"])
@auth_required("session", fresh=True)
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
            discoverable=(requested_usage == "primary"),
        )
        credential_options = wan.options_to_json_dict(options)

        await _set_wan_state(
            "wan_register_state",
            challenge=wan.bytes_to_base64url(challenge),
            name=form.name.data.strip(),
            usage=requested_usage,
            user_id=current_user.get_id(),
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
@auth_required("session", fresh=True)
async def wan_register_response():
    if not current_app.config.get("SECURITY_WEBAUTHN", False):
        abort(404)

    await _enforce_csrf()
    state = await _pop_wan_state("wan_register_state")
    if not state:
        await flash("Passkey registration expired. Please try again.", "error")
        return redirect(url_for_security("wan_register"))
    if state.get("user_id") != current_user.get_id():
        abort(400)

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
    except Exception as exc:
        current_app.logger.warning(
            "WebAuthn registration failed: %s: %s", type(exc).__name__, exc
        )
        await flash("Passkey registration failed.", "error")
        return redirect(url_for_security("wan_register"))

    # Look across all users too: a software authenticator can pick any credential
    # ID, and sign-in resolves the owner by ID alone.
    existing = await _find_webauthn_credential(
        verification["credential_id"], user=None
    ) or await _find_webauthn_credential(
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
        lastuse_datetime=naive_utcnow(),
    )
    await _security.revoke_user_sessions(current_user)

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

        challenge = secrets.token_bytes(32)
        options = await wan.begin_authentication(
            [],
            rp_id=_webauthn_rp_id(),
            challenge=challenge,
            require_user_verification=current_app.config[
                "SECURITY_WAN_REQUIRE_USER_VERIFICATION"
            ],
        )
        credential_options = wan.options_to_json_dict(options)
        await _set_wan_state(
            "wan_signin_state",
            challenge=wan.bytes_to_base64url(challenge),
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
    state = await _pop_wan_state("wan_signin_state")
    if not state:
        await flash("Passkey sign-in expired. Please try again.", "error")
        return redirect(url_for_security("wan_signin"))

    credential_payload = await _extract_webauthn_credential_payload()
    credential_id = _extract_webauthn_credential_id(credential_payload)
    if not credential_payload or credential_id is None:
        await flash("Invalid passkey response payload.", "error")
        return redirect(url_for_security("wan_signin"))

    stored_credential = await _find_webauthn_credential(credential_id, user=None)
    if stored_credential is None or stored_credential.usage != "primary":
        await flash("Passkey not recognized.", "error")
        return redirect(url_for_security("wan_signin"))

    user_handle = _extract_webauthn_user_handle(credential_payload)
    user = await _find_webauthn_credential_owner(stored_credential)
    if user is None:
        await flash("Unable to identify user from passkey.", "error")
        return redirect(url_for_security("wan_signin"))

    if not getattr(user, "active", True):
        await flash("Unable to find user for passkey sign-in.", "error")
        return redirect(url_for_security("wan_signin"))
    if user_handle and user_handle != user.fs_webauthn_user_handle:
        await flash("Passkey user handle mismatch.", "error")
        return redirect(url_for_security("wan_signin"))

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
    except Exception as exc:
        current_app.logger.warning(
            "WebAuthn sign-in failed: %s: %s", type(exc).__name__, exc
        )
        await flash("Passkey verification failed.", "error")
        return redirect(url_for_security("wan_signin"))

    stored_credential.sign_count = int(new_sign_count)
    if hasattr(stored_credential, "lastuse_datetime"):
        stored_credential.lastuse_datetime = naive_utcnow()

    return await _complete_login(user)


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
            require_user_verification=current_app.config[
                "SECURITY_WAN_REQUIRE_USER_VERIFICATION"
            ],
        )
        credential_options = wan.options_to_json_dict(options)
        await _set_wan_state(
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
    state = await _pop_wan_state("wan_verify_state")
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

    stored_credential = await _find_webauthn_credential(
        credential_id, user=current_user
    )
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
    except Exception as exc:
        current_app.logger.warning(
            "WebAuthn verification failed: %s: %s", type(exc).__name__, exc
        )
        await flash("Passkey verification failed.", "error")
        return redirect(url_for_security("wan_verify"))

    stored_credential.sign_count = int(new_sign_count)
    if hasattr(stored_credential, "lastuse_datetime"):
        stored_credential.lastuse_datetime = naive_utcnow()

    session["_fresh"] = True
    session["_auth_at"] = int(time.time())
    await _commit()

    await flash("Passkey verification successful.", "success")
    return redirect(_safe_redirect_target(state.get("next"), fallback="/"))


@security_bp.route("/wan-delete", methods=["POST"])
@auth_required("session", fresh=True)
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
    await _security.revoke_user_sessions(current_user)
    await flash("Passkey removed.", "success")
    if isinstance(payload, dict):
        return {"status": "ok"}
    return redirect(url_for_security("wan_register"))
