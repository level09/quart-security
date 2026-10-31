# CLAUDE.md

## What is quart-security

Native async auth extension for Quart. Session auth, 2FA/TOTP, WebAuthn (discoverable passkeys), recovery codes, rate limiting. SQLAlchemy async models. WTForms integration.

## Commands

```bash
uv sync                           # Install dependencies
uv run pytest                     # Run tests
uv run ruff check --fix . && uv run ruff format .  # Lint + format
```

## Publishing

Trusted Publisher is configured on PyPI. Do NOT use `flit publish` or API tokens.

Bumping `version` in `pyproject.toml` is the release. Commit the bump with a `## [<version>]` CHANGELOG entry and push to main. `.github/workflows/publish.yml` then runs CI and stk's checks against the commit, publishes, and creates the tag and GitHub release from that entry. Never tag or create releases by hand; batch fixes on main and bump only when ready.

## Architecture

- Build backend: flit
- Forms: `quart_security/forms.py` (QuartForm base with CSRF)
- Views: `quart_security/views.py` (all auth endpoints)
- WebAuthn: `quart_security/webauthn.py` (registration + authentication helpers)
- Templates: `quart_security/templates/security/` (bare HTML defaults, meant to be overridden)
- Config: `quart_security/core.py` (SECURITY_* config flags)

## Key Design Decisions

- Passkey signin is discoverable-only (no email-first flow). Single "Sign in with Passkey" button, browser picks the credential.
- Registration with usage="primary" sets ResidentKeyRequirement.REQUIRED for discoverable credentials.
- find_webauthn_credential(credential_id, user=None) supports global lookup for discoverable flow.
