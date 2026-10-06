"""Core extension initialization and session auth lifecycle."""

from __future__ import annotations

import time
from datetime import timedelta
from uuid import uuid4

from quart import abort, current_app, g, request, session

from .datastore import SQLAlchemyUserDatastore
from .forms import ChangePasswordForm, LoginForm, RegisterForm
from .password import init_password_context
from .proxies import AnonymousUser, current_user
from .signals import user_authenticated, user_logged_out
from .state import SQLAlchemyStateStore
from .utils import maybe_await, naive_utcnow, url_for_security


class _SecurityConfig:
    """Exposes SECURITY_* config flags as template-friendly attributes."""

    _MAP = {
        "registerable": "SECURITY_REGISTERABLE",
        "recoverable": "SECURITY_RECOVERABLE",
        "confirmable": "SECURITY_CONFIRMABLE",
        "changeable": "SECURITY_CHANGEABLE",
        "trackable": "SECURITY_TRACKABLE",
        "two_factor": "SECURITY_TWO_FACTOR",
        "webauthn": "SECURITY_WEBAUTHN",
        "wan_allow_as_first_factor": "SECURITY_WAN_ALLOW_AS_FIRST_FACTOR",
        "wan_allow_as_multi_factor": "SECURITY_WAN_ALLOW_AS_MULTI_FACTOR",
        "support_mfa": "SECURITY_TWO_FACTOR",
        "multi_factor_recovery_codes": "SECURITY_MULTI_FACTOR_RECOVERY_CODES",
    }

    def __init__(self, config):
        self._config = config

    def __getattr__(self, name):
        key = self._MAP.get(name)
        if key:
            return self._config.get(key, False)
        raise AttributeError(f"'security' has no attribute '{name}'")


class Security:
    """Quart extension implementing session-based authentication."""

    def __init__(self, app=None, datastore=None, **kwargs):
        self.app = None
        self.datastore = datastore
        self.login_form_cls = kwargs.get("login_form", LoginForm)
        self.register_form_cls = kwargs.get("register_form", RegisterForm)
        self.change_password_form_cls = kwargs.get(
            "change_password_form", ChangePasswordForm
        )
        self.mail_util_cls = kwargs.get("mail_util_cls")
        self.state_store = kwargs.get("state_store")

        if app is not None:
            self.init_app(app, datastore=datastore, **kwargs)

    def init_app(self, app, datastore=None, **kwargs):
        self.app = app
        if datastore is not None:
            self.datastore = datastore
        if self.datastore is None:
            raise RuntimeError("Security requires a datastore")

        self.login_form_cls = kwargs.get("login_form", self.login_form_cls)
        self.register_form_cls = kwargs.get("register_form", self.register_form_cls)
        self.change_password_form_cls = kwargs.get(
            "change_password_form", self.change_password_form_cls
        )
        self.mail_util_cls = kwargs.get("mail_util_cls", self.mail_util_cls)
        self.state_store = kwargs.get("state_store", self.state_store)
        if self.state_store is None:
            if not isinstance(self.datastore, SQLAlchemyUserDatastore):
                raise RuntimeError("Custom datastores require a shared state_store")
            self.state_store = SQLAlchemyStateStore(self.datastore)

        self._load_defaults(app)
        for name in ("put", "get", "pop", "claim"):
            if not callable(getattr(self.state_store, name, None)):
                raise RuntimeError(f"Security state_store requires {name}")
        required_hooks = ["rotate_uniquifier"]
        if app.config["SECURITY_LOGIN_MAX_ATTEMPTS"] > 0:
            required_hooks.append("record_auth_failure")
        if app.config["SECURITY_MULTI_FACTOR_RECOVERY_CODES"]:
            required_hooks.append("replace_recovery_codes")
        for name in required_hooks:
            if not callable(getattr(self.datastore, name, None)):
                raise RuntimeError(f"Security requires atomic datastore hook: {name}")
        if isinstance(self.datastore, SQLAlchemyUserDatastore):
            required_fields = ["fs_uniquifier", "email", "password", "active"]
            if app.config["SECURITY_LOGIN_MAX_ATTEMPTS"] > 0:
                required_fields += ["failed_login_count", "locked_until"]
            if app.config["SECURITY_TWO_FACTOR"]:
                required_fields += ["tf_primary_method", "tf_totp_secret"]
            if app.config["SECURITY_MULTI_FACTOR_RECOVERY_CODES"]:
                required_fields.append("mf_recovery_codes")
            if app.config["SECURITY_WEBAUTHN"]:
                required_fields.append("fs_webauthn_user_handle")
            missing = [
                name
                for name in required_fields
                if not hasattr(self.datastore.user_model, name)
            ]
            if missing:
                raise RuntimeError(
                    f"Security user model lacks fields: {', '.join(missing)}"
                )
        if not app.secret_key:
            raise RuntimeError("Security requires SECRET_KEY")
        app.config["SESSION_COOKIE_SECURE"] = app.config["SECURITY_COOKIE_SECURE"]
        app.config["SESSION_COOKIE_HTTPONLY"] = True
        app.config["SESSION_COOKIE_SAMESITE"] = (
            app.config.get("SESSION_COOKIE_SAMESITE") or "Lax"
        )
        init_password_context(app)

        from .views import security_bp

        if "security" not in app.blueprints:
            app.register_blueprint(security_bp)

        app.extensions["security"] = self

        if not app.extensions.get("quart_security_load_user_registered", False):

            @app.before_request
            async def _security_load_user():
                begin = getattr(self.datastore, "begin_request", None)
                if begin:
                    begin()
                await self.load_user()

            @app.before_websocket
            async def _security_load_user_ws():
                begin = getattr(self.datastore, "begin_request", None)
                if begin:
                    begin()
                await self.load_user()

            @app.teardown_request
            @app.teardown_websocket
            async def _security_close_session(_exception):
                close = getattr(self.datastore, "close", None)
                if close:
                    await maybe_await(close())

            app.extensions["quart_security_load_user_registered"] = True

            if isinstance(self.state_store, SQLAlchemyStateStore):

                @app.before_serving
                async def _security_validate_state():
                    try:
                        await self.state_store.validate()
                    finally:
                        await self.datastore.close()

        app.jinja_env.globals.setdefault("url_for_security", url_for_security)

        if not app.extensions.get("quart_security_context_registered", False):

            @app.context_processor
            async def _security_context():
                return {
                    "current_user": current_user,
                    "security": _SecurityConfig(current_app.config),
                }

            app.extensions["quart_security_context_registered"] = True

        return self

    @staticmethod
    def _load_defaults(app):
        defaults = {
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_BREACH_CHECK": True,
            "SECURITY_PASSWORD_BREACH_COUNT_MIN": 1,
            "SECURITY_PASSWORD_LENGTH_MIN": 12,
            "SECURITY_REGISTERABLE": True,
            "SECURITY_CHANGEABLE": True,
            "SECURITY_TRACKABLE": True,
            "SECURITY_TWO_FACTOR": True,
            "SECURITY_WEBAUTHN": True,
            "SECURITY_TOTP_ISSUER": "Quart",
            "SECURITY_MULTI_FACTOR_RECOVERY_CODES": True,
            "SECURITY_MULTI_FACTOR_RECOVERY_CODES_N": 3,
            "SECURITY_WAN_ALLOW_AS_FIRST_FACTOR": True,
            "SECURITY_WAN_ALLOW_AS_MULTI_FACTOR": True,
            "SECURITY_WAN_RP_ID": None,
            "SECURITY_WAN_RP_NAME": None,
            "SECURITY_WAN_EXPECTED_ORIGIN": None,
            "SECURITY_WAN_REQUIRE_USER_VERIFICATION": True,
            "SECURITY_FRESHNESS": timedelta(minutes=60),
            "SECURITY_FRESHNESS_GRACE_PERIOD": timedelta(minutes=60),
            "SECURITY_LOGIN_MAX_ATTEMPTS": 5,
            "SECURITY_LOCKOUT_MINUTES": 15,
            "SECURITY_POST_LOGIN_VIEW": "/",
            "SECURITY_POST_REGISTER_VIEW": "/login",
            "SECURITY_EMAIL_SENDER": "noreply@example.com",
            "SECURITY_CSRF_PROTECT": True,
            "SECURITY_COOKIE_SECURE": True,
        }

        for key, value in defaults.items():
            app.config.setdefault(key, value)

    async def load_user(self):
        user_id = session.get("_user_id")
        if not user_id:
            g._current_user = AnonymousUser()
            return

        state = await self.state_store.get(session.get("_id"))
        if not state or state.get("user_id") != user_id:
            session.clear()
            g._current_user = AnonymousUser()
            return

        user = await maybe_await(self.datastore.find_user(fs_uniquifier=user_id))
        if user is None or not getattr(user, "active", True):
            session.clear()
            g._current_user = AnonymousUser()
            return
        g._current_user = user

    async def login_user(self, user, fresh=True):
        app = current_app._get_current_object()
        if not user.is_active:
            raise ValueError("Cannot authenticate an inactive user")

        user_id = user.get_id() if hasattr(user, "get_id") else None
        if not user_id:
            user_id = getattr(user, "fs_uniquifier", None)
        if not user_id:
            raise RuntimeError("User must have fs_uniquifier/get_id for session login")

        if app.config.get("SECURITY_TRACKABLE", True):
            user.last_login_at = getattr(user, "current_login_at", None)
            user.last_login_ip = getattr(user, "current_login_ip", None)
            user.current_login_at = naive_utcnow()
            user.current_login_ip = request.remote_addr
            user.login_count = (getattr(user, "login_count", None) or 0) + 1

        await maybe_await(self.datastore.commit())
        token = await self.state_store.put(
            {"user_id": user_id},
            ttl=int(app.permanent_session_lifetime.total_seconds()),
        )
        # Discard pre-login state only after authentication writes succeed.
        session.clear()
        session["_user_id"] = user_id
        session["_fresh"] = bool(fresh)
        session["_auth_at"] = int(time.time())
        session["_id"] = token
        g._current_user = user
        await user_authenticated.send_async(app, user=user, authn_via="session")

    async def revoke_user_sessions(self, user):
        changed = await maybe_await(
            self.datastore.rotate_uniquifier(user, user.get_id(), uuid4().hex)
        )
        if not changed:
            session.clear()
            g._current_user = AnonymousUser()
            abort(409)
        await self.state_store.pop(session.get("_id"))
        session["_user_id"] = user.get_id()
        session["_id"] = await self.state_store.put(
            {"user_id": user.get_id()},
            ttl=int(current_app.permanent_session_lifetime.total_seconds()),
        )

    async def logout_user(self, user=None):
        app = current_app._get_current_object()
        target_user = user or getattr(g, "_current_user", AnonymousUser())

        if getattr(target_user, "is_authenticated", False):
            await self.state_store.pop(session.get("_id"))
            await user_logged_out.send_async(app, user=target_user)

        session.clear()
        g._current_user = AnonymousUser()
