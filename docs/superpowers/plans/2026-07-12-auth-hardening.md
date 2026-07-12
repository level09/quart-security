# Authentication Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release quart-security 1.4.1 with the reviewed authentication defects fixed and covered by regression tests.

**Architecture:** Keep the public extension API stable while tightening state transitions in the existing core, views, datastore, and TOTP modules. Use the existing user lockout fields, server-bound WebAuthn ownership, and keyed recovery-code hashes without adding a database migration.

**Tech Stack:** Python 3.11, Quart, SQLAlchemy async, WTForms, PyOTP, WebAuthn, pytest, Ruff, Flit

---

### Task 1: Datastore session ownership

**Files:**
- Modify: `quart_security/datastore.py`
- Test: `tests/test_datastore.py`

- [ ] Write a real async SQLAlchemy test that creates a user through `SQLAlchemyUserDatastore`, commits, and reads it from the same database.
- [ ] Run `uv run pytest tests/test_datastore.py -q` and confirm the user is missing with the current per-access factory behavior.
- [ ] Resolve `db.session`, an explicit session, or a scoped callable once per operation context and use that resolved session for add, query, delete, and commit.
- [ ] Run `uv run pytest tests/test_datastore.py -q` and confirm it passes.

### Task 2: Session lifecycle and sensitive-route freshness

**Files:**
- Modify: `quart_security/core.py`
- Modify: `quart_security/decorators.py`
- Modify: `quart_security/views.py`
- Test: `tests/test_core_flows.py`

- [ ] Add tests proving inactive users become anonymous, logout rejects GET, authentication records time, and stale sessions cannot mutate MFA or WebAuthn credentials.
- [ ] Run those tests and confirm each fails for the reviewed behavior.
- [ ] Clear authentication for inactive users, make logout POST-only, record `_auth_at`, and add a freshness decorator using `SECURITY_FRESHNESS`.
- [ ] Apply freshness to MFA setup, recovery-code management, passkey registration, verification, and deletion.
- [ ] Run the focused tests and confirm they pass.

### Task 3: MFA attempt lifecycle

**Files:**
- Modify: `quart_security/views.py`
- Test: `tests/test_auth_flow.py`
- Test: `tests/test_two_factor.py`

- [ ] Add tests proving password success does not clear counters before MFA, pending MFA expires, invalid codes increment the counter, lockout blocks MFA, and full success resets counters.
- [ ] Run the focused tests and confirm the missing controls fail.
- [ ] Store an issued timestamp with pending MFA state and use the existing failed count and lockout timestamp for every authentication factor.
- [ ] Reset counters only after complete login.
- [ ] Run the focused tests and confirm they pass.

### Task 4: Recovery-code hashing and CSRF

**Files:**
- Modify: `quart_security/totp.py`
- Modify: `quart_security/views.py`
- Modify: `quart_security/templates/security/mf_recovery_codes.html`
- Test: `tests/test_two_factor.py`

- [ ] Add tests proving stored generated codes are hashed, raw codes work once, legacy plaintext remains compatible, stored codes are not redisplayed, and regeneration succeeds with CSRF enabled.
- [ ] Run the tests and confirm the current plaintext storage and empty template token fail.
- [ ] Add versioned HMAC-SHA256 recovery hashes based on `SECRET_KEY`, constant-time verification, legacy recognition, and one-time display.
- [ ] Render the form CSRF helper in the default template.
- [ ] Run the focused tests and confirm they pass.

### Task 5: WebAuthn ownership and remember cleanup

**Files:**
- Modify: `quart_security/datastore.py`
- Modify: `quart_security/forms.py`
- Modify: `quart_security/views.py`
- Test: `tests/test_webauthn.py`

- [ ] Add tests proving an assertion handle cannot select a user different from the stored credential owner and signin does not advertise ineffective persistence.
- [ ] Run the tests and confirm the ownership fallback fails.
- [ ] Resolve the user through the stored credential relationship or stored owner key only, reject assertion mismatches, and remove remember state.
- [ ] Run the focused tests and confirm they pass.

### Task 6: Documentation and release

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `pyproject.toml`

- [ ] Document required lockout fields, edge or application source throttling, recovery-code one-time display, fresh-session behavior, and POST logout.
- [ ] Add 1.4.1 release notes and bump the package version.
- [ ] Run `uv run pytest -q`, `uv run ruff check .`, `uv run ruff format --check .`, and `uv build`.
- [ ] Review `git diff --check` and the complete diff, then commit only changed project files with `fix: harden authentication flows`.
- [ ] Confirm `main` as the push target, push, and create GitHub release `v1.4.1` so Trusted Publishing publishes to PyPI.
