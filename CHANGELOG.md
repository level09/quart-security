# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased] - 1.4.0

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
