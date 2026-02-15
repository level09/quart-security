"""Core extension initialization and session auth lifecycle."""

from __future__ import annotations

import datetime
import secrets
from datetime import timedelta

from quart import current_app, g, request, session

from .forms import ChangePasswordForm, LoginForm, RegisterForm
from .password import init_password_context
from .proxies import AnonymousUser, current_user
from .signals import user_authenticated, user_logged_out
from .utils import url_for_security


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

        self._load_defaults(app)
        init_password_context(app)

        from .views import security_bp

        if "security" not in app.blueprints:
            app.register_blueprint(security_bp)

        app.extensions["security"] = self

        if not app.extensions.get("quart_security_load_user_registered", False):

            @app.before_request
            async def _security_load_user():
                await self.load_user()

            @app.before_websocket
            async def _security_load_user_ws():
                await self.load_user()

            app.extensions["quart_security_load_user_registered"] = True

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
            "SECURITY_PASSWORD_HASH": "pbkdf2_sha512",
            "SECURITY_PASSWORD_LENGTH_MIN": 12,
            "SECURITY_REGISTERABLE": True,
            "SECURITY_CHANGEABLE": True,
            "SECURITY_TRACKABLE": True,
            "SECURITY_TWO_FACTOR": True,
            "SECURITY_WEBAUTHN": True,
            "SECURITY_TWO_FACTOR_ENABLED_METHODS": ["authenticator"],
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
            "SECURITY_POST_LOGIN_VIEW": "/",
            "SECURITY_POST_REGISTER_VIEW": "/login",
            "SECURITY_EMAIL_SENDER": "noreply@example.com",
            "SECURITY_SEND_PASSWORD_CHANGE_EMAIL": False,
            "SECURITY_CSRF_PROTECT": True,
            "SECURITY_API_ENABLED_METHODS": ["session"],
        }

        for key, value in defaults.items():
            app.config.setdefault(key, value)

    async def load_user(self):
        user_id = session.get("_user_id")
        if not user_id:
            g._current_user = AnonymousUser()
            return

        user = await self.datastore.find_user(fs_uniquifier=user_id)
        g._current_user = user or AnonymousUser()

    async def login_user(self, user, fresh=True):
        app = current_app._get_current_object()

        user_id = user.get_id() if hasattr(user, "get_id") else None
        if not user_id:
            user_id = getattr(user, "fs_uniquifier", None)
        if not user_id:
            raise RuntimeError("User must have fs_uniquifier/get_id for session login")

        session["_user_id"] = user_id
        session["_fresh"] = bool(fresh)
        session["_id"] = secrets.token_hex(16)
        g._current_user = user

        if app.config.get("SECURITY_TRACKABLE", True):
            user.last_login_at = getattr(user, "current_login_at", None)
            user.last_login_ip = getattr(user, "current_login_ip", None)
            user.current_login_at = datetime.datetime.utcnow()
            user.current_login_ip = request.remote_addr
            user.login_count = (getattr(user, "login_count", None) or 0) + 1

        await self.datastore.commit()
        await user_authenticated.send_async(app, user=user, authn_via="session")

    async def logout_user(self, user=None):
        app = current_app._get_current_object()
        target_user = user or getattr(g, "_current_user", AnonymousUser())

        if getattr(target_user, "is_authenticated", False):
            await user_logged_out.send_async(app, user=target_user)

        session.clear()
        g._current_user = AnonymousUser()
