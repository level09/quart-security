# quart-security

Native async authentication for Quart.

This package provides:

- session-based login/logout
- registration and password change
- `current_user`, `auth_required`, `roles_required`
- TOTP and recovery-code helpers
- WebAuthn helper wrappers
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

Initial implementation focused on core auth and migration compatibility.
