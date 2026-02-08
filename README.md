# quart-security

Native async authentication for Quart.

This package provides:

- session-based login/logout
- registration and password change
- `current_user`, `auth_required`, `roles_required`
- TOTP and recovery-code helpers
- WebAuthn register/sign-in/verify flows (passkeys/security keys)
- Flask-Security-compatible endpoint naming via `url_for_security()`

## Tooling

- Build backend: `flit`
- Environment and task runner: `uv`

## Quickstart

```bash
uv sync --group dev
uv run pytest -q
```

## Status

Core auth + TOTP + WebAuthn flows implemented with Quart-native async handlers.
