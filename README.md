# quart-security

`quart-security` is a native async authentication extension for Quart.

It is designed as a practical replacement path for Flask-Security style session auth in Quart applications, without Flask shims and without Flask-Login.

## What You Get

### Core auth
- Session-based login and logout
- Email/password registration
- Password change flow (including OAuth-style users that don’t know an initial random password)
- `current_user` proxy
- `@auth_required("session")` and `@roles_required(...)`

### MFA
- TOTP setup and verification
- Recovery code generation and one-time consumption

### WebAuthn (passkeys / security keys)
- Credential registration
- Passwordless sign-in (first factor)
- Authenticated verification flow (step-up / second factor)
- Credential deletion

### Extension and compatibility surface
- Quart extension pattern (`Security(app, datastore)`)
- Flask-Security-style endpoint naming through `url_for_security()`
- Signals for auth lifecycle events
- Overridable templates under `templates/security/`

## Non-Goals (Current Scope)

This project intentionally focuses on session auth and MFA currently in active use:
- No token-based API auth
- No SMS/email OTP
- No account locking workflow
- No remember-me token system

## Installation

### Install from repository

```bash
uv add git+https://github.com/level09/quart-security.git
```

### Local development

```bash
uv sync --group dev
uv run pytest -q
```

Package build backend: `flit`.

## Quick Integration

```python
from quart import Quart
from quart_security import Security, SQLAlchemyUserDatastore

# your models should include fields used by auth, roles, and MFA/WebAuthn
from myapp.models import db, User, Role, WebAuthnCredential


def create_app():
    app = Quart(__name__)

    app.config.update(
        SECRET_KEY="change-me",
        SECURITY_PASSWORD_SALT="change-me-too",
        SECURITY_POST_LOGIN_VIEW="/dashboard",
        SECURITY_POST_REGISTER_VIEW="/login",
    )

    db.init_app(app)
    datastore = SQLAlchemyUserDatastore(
        db,
        User,
        Role,
        webauthn_model=WebAuthnCredential,
    )

    Security(app, datastore)
    return app
```

## Required Model Surface

Your user/role models are expected to provide the fields used by active features.

Minimum practical user fields:
- `fs_uniquifier`
- `email`
- `password`
- `active`
- `roles`

For tracking / MFA / WebAuthn features:
- `last_login_at`, `current_login_at`, `last_login_ip`, `current_login_ip`, `login_count`
- `tf_primary_method`, `tf_totp_secret`, `mf_recovery_codes`
- `fs_webauthn_user_handle`
- relationship/association for stored WebAuthn credentials

## Key Configuration

The extension uses `SECURITY_*` keys for migration-friendly configuration.

Core:
- `SECURITY_PASSWORD_HASH` (default: `pbkdf2_sha512`)
- `SECURITY_PASSWORD_SALT` (recommended)
- `SECURITY_PASSWORD_LENGTH_MIN` (default: `12`)
- `SECURITY_REGISTERABLE`
- `SECURITY_CHANGEABLE`
- `SECURITY_TRACKABLE`
- `SECURITY_CSRF_PROTECT` (default: `True`)

2FA:
- `SECURITY_TWO_FACTOR`
- `SECURITY_TOTP_ISSUER`
- `SECURITY_MULTI_FACTOR_RECOVERY_CODES`
- `SECURITY_MULTI_FACTOR_RECOVERY_CODES_N`

WebAuthn:
- `SECURITY_WEBAUTHN`
- `SECURITY_WAN_ALLOW_AS_FIRST_FACTOR`
- `SECURITY_WAN_ALLOW_AS_MULTI_FACTOR`
- `SECURITY_WAN_RP_ID` (optional override)
- `SECURITY_WAN_RP_NAME` (optional override)
- `SECURITY_WAN_EXPECTED_ORIGIN` (optional override)
- `SECURITY_WAN_REQUIRE_USER_VERIFICATION` (default: `True`)

Routing:
- `SECURITY_POST_LOGIN_VIEW`
- `SECURITY_POST_REGISTER_VIEW`

## Route Map

Core:
- `/login`
- `/register`
- `/logout`
- `/change`

2FA:
- `/tf-setup`
- `/tf-validate`
- `/tf-select`
- `/mf-recovery-codes`
- `/mf-recovery`

WebAuthn:
- `/wan-register`
- `/wan-register-response`
- `/wan-signin`
- `/wan-signin-response`
- `/wan-verify`
- `/wan-verify-response`
- `/wan-delete`

## Template Overrides

Default templates are intentionally simple and framework-neutral.

Override by placing templates with the same names under your app’s
`templates/security/` directory.

## Public API

```python
from quart_security import (
    Security,
    SQLAlchemyUserDatastore,
    current_user,
    auth_required,
    roles_required,
    UserMixin,
    RoleMixin,
    hash_password,
    verify_password,
    user_authenticated,
    user_logged_out,
    password_changed,
    tf_profile_changed,
    user_registered,
    url_for_security,
)
```

## Testing

Project tests cover:
- password hashing/validation
- auth and role decorators
- register/login/logout/change-password
- TOTP and recovery code flows
- WebAuthn register/sign-in/verify/delete route behavior

Run:

```bash
uv run pytest -q
```

## Notes for Production

- Run behind HTTPS for WebAuthn in non-local environments.
- Set explicit WebAuthn RP values (`SECURITY_WAN_RP_ID`, `SECURITY_WAN_EXPECTED_ORIGIN`) when behind proxies or multiple domains.
- Keep CSRF protection enabled unless you have a deliberate replacement.
