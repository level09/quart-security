"""WTForms used by quart-security views."""

import secrets

from markupsafe import Markup, escape
from quart import request
from wtforms import BooleanField, PasswordField, RadioField, StringField
from wtforms.form import Form
from wtforms.validators import DataRequired, Email, EqualTo, Optional


class QuartForm(Form):
    """Small helper to create WTForms from Quart request form data."""

    class Meta:
        csrf = False

    _submitted_csrf: str | None = None
    form_errors: list = []

    class _DummyField:
        errors = []
        id = "csrf_token"

    csrf_token = _DummyField()

    @classmethod
    async def from_formdata(cls):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            form_data = await request.form
            form = cls(formdata=form_data)
            form._submitted_csrf = form_data.get("csrf_token")
            return form
        return cls()

    def hidden_tag(self, *_fields):
        # Compatibility helper for templates expecting FlaskForm APIs.
        from quart import current_app, session

        if not current_app.config.get("SECURITY_CSRF_PROTECT", True):
            return Markup("")

        csrf_token = session.get("_csrf_token")
        if not csrf_token:
            csrf_token = secrets.token_urlsafe(32)
            session["_csrf_token"] = csrf_token

        escaped = escape(csrf_token)
        return Markup(
            f'<input id="csrf_token" name="csrf_token" type="hidden" value="{escaped}">'
        )


class LoginForm(QuartForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")


class RegisterForm(QuartForm):
    name = StringField("Full Name", validators=[Optional()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    password_confirm = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match")],
    )


class ChangePasswordForm(QuartForm):
    password = PasswordField("Current Password", validators=[Optional()])
    new_password = PasswordField("New Password", validators=[DataRequired()])
    new_password_confirm = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match"),
        ],
    )


class TwoFactorSetupForm(QuartForm):
    token = StringField("Code", validators=[DataRequired()])


class TwoFactorVerifyForm(QuartForm):
    token = StringField("Code", validators=[DataRequired()])


class RecoveryCodeForm(QuartForm):
    code = StringField("Recovery Code", validators=[DataRequired()])


class WebAuthnRegisterForm(QuartForm):
    name = StringField("Credential Name", validators=[DataRequired()])
    usage = RadioField(
        "Usage",
        choices=[("secondary", "Multi-factor only"), ("primary", "Passwordless sign-in")],
        default="secondary",
        validators=[DataRequired()],
    )


class WebAuthnVerifyForm(QuartForm):
    identity = StringField("Email", validators=[Optional()])
    remember = BooleanField("Remember me")
    credential = StringField("Credential", validators=[Optional()])
