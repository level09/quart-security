# Security review: quart-security 1.4.1

Date: 2026-10-06. Commit: `1a88f95a180fb717d0491414c4aee3d5cdb48a6e`.

## Fix status

All nine numbered findings below are addressed in the working tree. The original
findings and verdict are retained as a record of the reviewed base commit.
Additional checks found and fixed concurrent MFA enrollment overwrites, broken
default setup form fields, missing SQLAlchemy asyncio and bcrypt backends,
inactive-user MFA completion, and shared password configuration between apps.

Verification: 80 tests pass locally and against the installed wheel on Python
3.11, 3.12, 3.13, and 3.14. Ruff and whitespace checks pass. The source distribution
and wheel build, and clean wheel installs resolve working current dependencies.
Real SQL tests use separate AsyncSessions, SQLite, CSRF-protected requests, and
independent database reads. WebAuthn tests use real software-generated EC
assertions, reject a wrong registration origin, and reject replay with both zero
and incrementing authenticator counters. The regression command below now runs
the repaired behavior tests rather than asserting that defects still exist.

The public OSV scan found affected aiosmtplib, cryptography, and cbor2 versions;
the dependency minimums and resolved versions were updated. A second scan of 43
public runtime dependencies in the clean Python 3.12 wheel environment reports no
known advisories. Exact versions and results are in
`security-review/dependency-audit.json`. This is an advisory snapshot, not a
guarantee that the dependencies have no defects.

Deployment requires the new shared `quart_security_state` table and the migration
contract in README.md. Existing cookies are invalidated. Custom datastores need
atomic security hooks and a shared state backend. Publishing this library does
not migrate host databases or deploy host applications. Physical browser and
hardware authenticator validation and PostgreSQL/MySQL runtime tests remain host
release checks. Account lockout still requires source-IP/global rate limits at
the application or edge.

## Original review

## Verdict

Do not approve this version for production use as it is. The core controls have a
useful base, but MFA policy, session revocation, one-time verification, and the
factory datastore have defects. Passing the current tests does not cover these
failure paths.

This was a local source and behavior review, not a penetration test or a security
certification. No application code was changed. The review adds this report and
`security-review/reproduce.py`.

## Evidence and scope

Reviewed all package modules, default templates, tests, configuration, declared
dependencies, and CI/publish workflows. Existing tests: 50 passed. Ruff passed.
Nine local reproductions confirmed the behaviors below. Run them with:

```sh
UV_CACHE_DIR=/tmp/quart-review-uv uv run --no-sync python security-review/reproduce.py
```

The reproductions use the existing in-memory application fixture. They use real
TOTP verification. Passkey tests replace only cryptographic verification with a
successful result to test the policy applied after verification; they do not
prove a forged assertion is accepted. The datastore reproduction uses real
SQLAlchemy mapped objects and SQLite through a small async method adapter.

Most existing flow tests turn off CSRF and breach checks. All existing WebAuthn
route tests mock the verification helpers. The single datastore test uses a fake
session and checks only creation followed by one commit. Those tests do not prove
real browser compatibility, real async ORM lifecycle safety, or concurrent
one-time consumption.

## Findings

### 1. P1: Factory datastore loses writes after a commit and leaks sessions

`quart_security/datastore.py:23-31,192-197`; affected callers include
`quart_security/views.py:93-98,340-341` and `quart_security/core.py:178-186`.

`commit()` clears the ContextVar even though existing objects remain attached to
the old session. The next commit uses a new session. For example, password login
resets auth failures with one commit, then changes login tracking on the same
user object and commits another session. Rehash and expired-lockout paths can
also leave later updates on the wrong session.

```python
active = self.session
try:
    await active.commit()
finally:
    self._active_session.set(None)
```

The local reproduction creates a user, commits, changes its email, and commits
again. A separate database query still returns the original email. This affects
the callable factory path; a host-managed `db.session` has different ownership.

No code closes or rolls back factory-created sessions, including read-only and
failure requests. Default async expiration and lazy relationships add a separate
integration risk that the current test suite does not exercise.

Fix: keep one session for the request, with explicit rollback and close at request
end. Do not discard it at each commit. Define ownership for supplied sessions.
Test the full auth flows using a real AsyncSession, eager relationships, both
success and error paths, and independent database reads.

### 2. P1: Password change does not revoke existing sessions

`quart_security/views.py:493-498`; `quart_security/core.py:146-157,188-196`.

Changing a password does not rotate `fs_uniquifier` or advance a server-side
session version. An attacker with a copied authenticated cookie retains access
after the owner changes the password. Logout clears only the current browser's
cookie; it does not invalidate that copied cookie. `_id` is generated but never
checked against server state.

The reproduction copies an authenticated session, changes the password, logs the
owner out, and gets HTTP 200 from `/protected` using the copy. A session issued
before MFA enrollment also stays fresh and can POST `action=disable` after MFA
has been enabled. That second case is reproduced too.

Fix: revoke old sessions on password changes and security profile changes using
the existing uniquifier or a session version. Reissue the owner's session only
after the required proof of identity. Require current MFA proof for disabling or
replacing MFA. State the logout revocation contract explicitly.

### 3. P1: TOTP setup secret is stored in a readable and replayable cookie

`quart_security/views.py:548-552,591-594`.

With Quart's default session backend, `tf_pending_secret` goes into a signed
cookie. Signing prevents edits; it does not encrypt the value. The reproduction
serializes and reads the pending secret using the actual session serializer.
The installed Quart source explicitly describes this storage as plain text.

After enrollment the new cookie omits the secret, but a saved older cookie still
contains the permanent enrolled secret. Within the session freshness window,
the old pending state can also be restored: setup verification has no server-side
consumed marker, expiry, or check that the account still needs enrollment.

```python
session["tf_pending_secret"] = pending_secret
```

Fix: store pending enrollment on the server, bound to the user, with an expiry and
atomic consumption. Do not place long-term authenticator secrets in session
cookies. Recheck enrollment state before writing the secret.

### 4. P1: Verification state is not reliably one-time

`quart_security/totp.py:43-46`; `quart_security/views.py:161-179,649,656-664,750-759`.

The same real TOTP authenticates two separate password login sessions in the
reproduction. `verify_totp()` uses a time window but does not persist a consumed
time step. [PyOTP's security guidance](https://github.com/pyauth/pyotp) requires
the application to reject reuse of accepted OTPs.

WebAuthn challenge consumption is also only a `session.pop()`. With default
signed cookies, restoring an older cookie restores that challenge during its
five-minute lifetime. Signature counter checks may reject replay for a counting
authenticator, but cannot be the one-time-state control for authenticators that
report zero. This WebAuthn replay risk was found by source inspection; it was not
tested with a real signed assertion.

Recovery code removal is a read/check/write of the user's list. Two concurrent
transactions can both read and accept the same code. Auth failure increments
have the same non-atomic read/write pattern. Those concurrency risks were found
by source inspection, not reproduced against an async database.

Fix: persist accepted TOTP steps and challenge state; consume them atomically.
Consume recovery codes with a conditional database update or locked transaction.
Use atomic failure counters. Test simultaneous requests, not just serial calls.

### 5. P1: Secondary credentials can perform first-factor sign-in

`quart_security/views.py:956-1008`; policy labels in `quart_security/forms.py:107-111`.

Sign-in looks up any credential globally and never checks `usage`. Thus a
discoverable credential stored as `secondary` can authenticate without a password,
despite the form's "Multi-factor only" label. Secondary registration does not
forbid a resident credential, so this is an enforceable server policy gap, not a
guarantee supplied by the browser.

The reproduction supplies a secondary credential and a successful verification
result, then gets access to `/protected`. It tests policy, not a cryptographic
bypass. First-factor passkey login also intentionally bypasses the TOTP login
branch; document that authentication policy separately.

Fix: reject credentials whose usage is not `primary` in first-factor sign-in.
Test this check after real verification and before login.

### 6. P2: Disabled recovery-code authentication still works

`quart_security/views.py:725-765`.

`/mf-recovery` does not check `SECURITY_MULTI_FACTOR_RECOVERY_CODES`. The inline
recovery path in `/tf-validate` does check it. With valid pending password state
and an existing recovery code, the reproduction logs in through `/mf-recovery`
after setting the flag to False.

Fix: enforce the feature policy at the recovery endpoint before processing a
code, and test both recovery paths with the feature disabled.

### 7. P2: Real TOTP setup fails without an undeclared dependency

`quart_security/totp.py:36`; `pyproject.toml:20`.

`qrcode.make()` selects the Pillow image backend. The package declares `qrcode`
but does not request its `pil` extra or declare Pillow. In the current installed
environment `/tf-setup?setup=authenticator` raises
`ModuleNotFoundError: No module named 'PIL'`. The reproduction confirms this,
then substitutes QR rendering so the remaining checks can run.

Fix: declare `qrcode[pil]` if PNG output is required. Add a real QR generation
smoke test in a clean install.

### 8. P2: Successful passkey step-up does not refresh authentication time

`quart_security/views.py:1114-1115`; `quart_security/decorators.py:27-35`.

Verification sets `_fresh=True`, but leaves `_auth_at` unchanged. A user whose
login is older than `SECURITY_FRESHNESS` completes passkey verification and still
gets HTTP 401 at `/wan-register`. The reproduction confirms this with a
successful verification result.

```python
session["_fresh"] = True
await _commit()
```

Fix: update the authentication timestamp after successful step-up and test the
next protected operation with an expired original timestamp.

### 9. P2: Password changes alter the submitted current password

`quart_security/views.py:450`.

Registration and login hash/verify the exact password. Password change calls
`.strip()` on the current password before verifying it. A valid password that
starts or ends with spaces can log in but cannot pass the password-change check.
This is confirmed by source comparison, not a separate reproduction.

Fix: verify the exact submitted value. Check absence separately and add one
round-trip case with leading and trailing spaces.

## Deployment requirements and remaining gaps

The lockout fields are optional and missing fields silently disable lockout.
There is no source-IP or global rate limiter. The README already assigns those
controls to the host application. This package is therefore not independently
safe against automated abuse with every supported model. Fail at startup when
an enabled security control lacks its required fields.

The extension leaves Quart's cookie defaults in place, including
`SESSION_COOKIE_SECURE=False` and `SESSION_COOKIE_SAMESITE=None` in this runtime.
A production host must use HTTPS, secure cookies, an appropriate SameSite
setting, a strong secret key, and explicit WebAuthn RP/origin configuration.
The library does not check that deployment contract. Database constraints must
make normalized emails, credential IDs, and user handles unique. Enrollment
secrets need storage protection appropriate to the host's threat model.

Password configuration is process-global in `quart_security/password.py:7-8,26-28`.
Initializing a second app overwrites the first app's hashing settings and legacy
salt. This is a multi-app isolation concern and needs an app-context test before
claiming support for multiple differently configured apps in one process.

MFA completion loads the user but does not check `active` again. The next request
revokes an inactive user's session, but login signals and tracking can still run
for a disabled user. Recheck account eligibility before final login.

The publish workflow builds without running tests or lint. Trusted Publisher
avoids a long-lived PyPI token, but release safety still depends on the tagged
commit passing CI. An offline build was attempted but could not resolve
`flit-core` from the local cache. Package build and clean wheel installation
remain unverified; this is an environment limit, not a confirmed build defect.

Live dependency advisory checks remain incomplete. Automatic approval review
rejected sending the installed package inventory to OSV because it could include
private package metadata. No inventory was sent. Network restrictions also
blocked raw downloads of dependency documentation. Public documentation search
was used only to locate the PyOTP and SQLAlchemy guidance. No claim of zero
dependency vulnerabilities is made.

Real browser/hardware passkey testing, real async database integration,
concurrent request testing, and supported Python version coverage remain open.
An application review is also needed for its proxy trust, session backend,
database model constraints, and rate limits.

## Smallest release gate

Fix findings 1 through 8 before approving a production release. Fix the password
round-trip defect in the same security maintenance pass. Add regression tests
that prove the controls work through normal requests with CSRF enabled and
independent database reads. Then run real WebAuthn registration, sign-in, step-up,
and deletion in an HTTPS test environment with at least two authenticator types.
Complete a dependency advisory scan after approval for the exact public package
names and versions sent to the advisory service. Re-review the resulting patch.
