# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.0.6] - 2026-10-31

### Security

- Registration no longer reveals which emails have an account. An existing
  email gets the same redirect and message as a new one, after the same
  password checks and hashing, and nothing is created. The new
  `user_register_conflict` signal fires with the existing user so the app can
  tell the owner out of band.

### Fixed

- `/login?next=/path` returns the user to `/path` after password, 2FA,
  recovery code or passkey sign-in. Before, `auth_required` sent `next` but
  login always went to `SECURITY_POST_LOGIN_VIEW`. Only same-site paths are
  honored, each visit to the login form replaces the target, and a target
  older than 10 minutes is ignored.

## [2.0.5] - 2026-10-31

### Security

- Login verifies a password hash even when the email has no account or the
  account is inactive, so response time no longer reveals which emails are
  registered. A locked account still says it is locked.
- Passkey registration refuses a credential ID that another user already
  holds. Sign-in finds a credential's owner by its ID alone, and a software
  authenticator can choose any ID; before, only the registering user's own
  credentials were checked, leaving the database constraint as the only guard.

## [2.0.4] - 2026-10-31

### Fixed

- Login and registration trim spaces around the email, and
  `SQLAlchemyUserDatastore.find_user(email=...)` matches case-insensitively.
  A user stored as `Admin@Example.com` by host code (an admin page, a CLI) can
  sign in again; registration already stored emails lowercased. When two
  stored emails differ only by case, `find_user` raises `ValueError` rather
  than pick one: give the email column a unique constraint on its lowercased
  value.

### Removed

- The `remember` field on `LoginForm`, which nothing read. A custom login
  template that renders `form.remember` must drop it.
- The unused `SECURITY_FRESHNESS_GRACE_PERIOD` default.

## [2.0.3] - 2026-10-25

### Fixed

- Declare the passkey usage choices with `SelectChoice`, as WTForms 3.3
  expects. The `wtforms` floor is now 3.3.

## [2.0.2] - 2026-10-25

### Changed

- The breach check uses `httpx2` instead of `httpx`.

## [2.0.1] - 2026-10-06

### Security

- Encrypt stored TOTP secrets at rest with Fernet. Keys derive from
  `SECRET_KEY` via HMAC, or come from `SECURITY_TOTP_ENCRYPTION_KEYS` (a
  `MultiFernet` key list) to support rotation. Legacy plaintext seeds stay
  readable and are re-encrypted on load and on login. Pending setup secrets in
  the state store are encrypted as well.

### Fixed

- Generate authenticator QR codes off the event loop.

## [2.0.0] - 2026-10-06

### Security

- Server-side state store (`quart_security_state` table) backs sessions and
  one-time verification state. Cookies carry opaque tokens only; every
  authenticated request validates its token server-side. **Migration
  required**; existing login cookies are invalidated. See README.
- Revoke sessions on password change, MFA profile change, passkey
  registration/deletion, and recovery-code regeneration via atomic
  `fs_uniquifier` rotation. Conflict aborts with 409.
- Accepted TOTP time steps cannot be reused (atomic consumed-step store, per
  PyOTP guidance). WebAuthn challenges and recovery codes are consumed
  atomically.
- Pending TOTP setup secrets are stored server-side with a five-minute expiry
  instead of in the session cookie.
- First-factor passkey sign-in rejects credentials registered with
  `usage="secondary"`.
- `/mf-recovery` enforces `SECURITY_MULTI_FACTOR_RECOVERY_CODES` (404 when
  disabled).
- Passkey step-up refreshes the authentication timestamp, so fresh-required
  endpoints accept the session afterwards.
- Password change verifies the exact submitted current password.
- Force `SESSION_COOKIE_HTTPONLY=True` and `SameSite=Lax`;
  `SECURITY_COOKIE_SECURE` (default `True`) controls `SESSION_COOKIE_SECURE`.
- Fail fast at startup on missing `SECRET_KEY`, missing atomic datastore
  hooks, missing required user-model fields, or a missing state table.
- Inactive users are rejected at MFA completion, not only on the next request.

### Fixed

- Datastore keeps one session per request across commits and closes
  factory-owned sessions at request teardown. `expire_on_commit=False` is
  required and enforced.
- Real QR generation works in a clean install via the declared `qrcode[pil]`.

### Changed

- Custom datastores must provide a shared `state_store` and the atomic hooks
  `rotate_uniquifier`, `record_auth_failure` (lockout), and
  `replace_recovery_codes` (recovery codes) when those features are enabled.

## [1.4.1] - 2026-07-12

### Security

- Revoke authenticated sessions when an account is deactivated.
- Bind discoverable WebAuthn signin to the credential owner stored by the
  server instead of allowing the assertion user handle to select an account.
- Apply account lockout counters and a five-minute expiry to pending MFA
  verification.
- Store new recovery codes as keyed hashes and migrate remaining legacy
  plaintext codes after successful use.
- Require fresh authentication for MFA and passkey management.
- Require POST and CSRF validation for logout.

### Fixed

- Reuse factory-created SQLAlchemy sessions through commit so writes and their
  transactions use the same session.
- Render a valid CSRF token in the default recovery-code form.
- Display raw recovery codes only in the response that generates them.
- Remove the unsupported WebAuthn remember-me field.

## [1.4.0] - 2026-06-12

### Added

- **argon2id default password hash** (OWASP 2025 guidance): `CryptContext` now
  defaults to argon2id with minimum parameters (m=19456 KiB, t=2, p=1).
  `argon2-cffi>=23.1` added as a runtime dependency.
- **Transparent rehash on login**: after a successful password verify, if
  `password_needs_rehash()` returns True, the hash is upgraded in-place and
  committed before completing login. Old pbkdf2_sha512 and bcrypt hashes
  continue to verify and are silently upgraded on next login.
- **HIBP breach check** (NIST 800-63B-4 SHALL): new `quart_security/breach.py`
  with `password_is_breached()` using the k-anonymity range API. Wired into
  register and change-password flows. Fails open on network error.
  `httpx>=0.27` added as a runtime dependency. Config:
  `SECURITY_PASSWORD_BREACH_CHECK` (default `True`),
  `SECURITY_PASSWORD_BREACH_COUNT_MIN` (default `1`).
- **`py.typed` marker** added; package is now PEP 561 compliant.
- `SECURITY_ARGON2_MEMORY_COST` / `_TIME_COST` / `_PARALLELISM` config knobs
  to override argon2 params (e.g. low values for test environments).

### Changed

- `SECURITY_PASSWORD_HASH` default changed from `pbkdf2_sha512` to `argon2`.
  Set `SECURITY_PASSWORD_HASH=pbkdf2_sha512` to preserve old behavior.
- `webauthn` dependency floor bumped to `>=2.7`.
- `respx` added as a dev dependency for HTTP mock testing.

## [1.3.0] - 2024

### Added

- Discoverable passkey-first login (`/wan-signin`): browser picks the
  credential with no email-first step.
- `find_webauthn_credential(credential_id, user=None)` supports global lookup
  for the discoverable flow.
- Registration with `usage="primary"` sets `ResidentKeyRequirement.REQUIRED`.

### Removed

- Email-first passkey flow removed; signin is now discoverable-only.

### Fixed

- Off-loop password hashing via `asyncio.to_thread` (was blocking event loop).
- Session regeneration on login to prevent session fixation.
- Constant-time recovery code verification.
- Redirect and lockout hardening.
