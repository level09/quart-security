# Authentication Hardening Design

## Scope

Prepare quart-security 1.4.1 as a backward-compatible security patch for the
issues identified in the July 2026 production-readiness review.

## Datastore session ownership

`SQLAlchemyUserDatastore` will resolve one existing session interface rather
than calling a factory for every operation. It will support an explicit
`AsyncSession`, an object exposing `session`, and a scoped callable that returns
the same request-local session. Tests will use a real async SQLAlchemy session
and prove that create, mutate, delete, and commit share a transaction.

## Session authentication

Loading a session for a missing or inactive user will clear authentication state
and return an anonymous user. Logout will be POST-only. Persistent login remains
unsupported, so misleading remember fields and behavior will be removed.

Freshness will be represented by an authentication timestamp in the session.
Sensitive account-management routes will require recent authentication according
to `SECURITY_FRESHNESS` and redirect through an existing verification path when
stale.

## Password and MFA attempt control

Password, TOTP, and recovery-code failures will use the account's existing
`failed_login_count` and `locked_until` fields. A successful password check will
not reset counters until the complete MFA flow succeeds. Pending MFA state will
carry a short expiry and an attempt ceiling. Deployments enabling these controls
must provide the documented model fields.

## Recovery codes

New recovery codes will be shown once and stored as keyed hashes derived from the
application secret. Existing plaintext codes will remain usable once for a
backward-compatible migration. Any successful legacy use will rewrite remaining
codes in hashed form. Stored codes will never be displayed again.

## WebAuthn

Discoverable signin will resolve the account only from the stored credential's
server-side owner. The response `userHandle` may confirm that binding but may not
select another account. Credential deletion and MFA registration changes will
require fresh authentication.

## CSRF

The default recovery-code template will use the form's CSRF helper. Integration
tests will run with CSRF enabled for login, MFA, recovery, and WebAuthn mutation
paths.

## Lockout limitations

The built-in account counters provide a safe baseline but cannot provide a
distributed IP limiter. Documentation will recommend an application or edge
rate limiter for source-based abuse protection. The extension will avoid
claiming otherwise.

## Verification and release

Each defect will receive a regression test that fails before its implementation.
The final gate is the complete pytest suite, Ruff, and package build. Version
1.4.1 will be committed, pushed to `main` only after explicit branch
confirmation, and released through GitHub so Trusted Publishing performs the
PyPI upload.
