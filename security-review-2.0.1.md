# Security scan: quart-security 2.0.1

Date: 2026-10-25. Commit: `a27a5bc` (working tree clean except untracked `AGENTS.md`).
Scope: all 16 package modules (2,726 LOC), 13 default templates, tests, config,
dependency floors, publish workflow. Follow-up to the v1.4.1 review in
`security-review.md`.

## Verdict

**Approved for production** under the documented host obligations (HTTPS, secure
cookies, unique DB constraints, `quart_security_state` migration, edge rate
limiting). All nine findings from the v1.4.1 review are confirmed fixed in
source and by behavior tests. On the controls both libraries implement, this
package is at parity with or stronger than Flask-Security defaults.

This is a source/behavior review and dependency advisory scan, not a penetration
test or certification.

## Scan evidence

| Check | Result |
|---|---|
| `uv run pytest` | 83 passed (incl. 15 security regression tests) |
| `security-review/reproduce.py` | 29 passed (asserts repaired behavior, real TOTP, real SQLAlchemy/SQLite) |
| `pip-audit --path .venv` | No known vulnerabilities (all runtime deps incl. cryptography 50.0.2, cbor2 6.1.5, aiosmtplib 5.1.3, webauthn 2.7.1) |
| `bandit -r quart_security` | 0 high; 1 medium + 4 low, all false positives (config-dict keys flagged as "hardcoded passwords"; the one `Markup()` wraps an `escape()`d CSRF token) |
| Template XSS review | Clean: Jinja autoescape throughout, no `\|safe`, JS uses `\|tojson` and `textContent` (no `innerHTML`) |

## v1.4.1 findings — confirmed fixed

1. **Datastore session lifecycle** — one ContextVar session per request, kept
   through commits, closed at teardown; `expire_on_commit=False` enforced at
   runtime. Atomic hooks (`rotate_uniquifier`, `record_auth_failure`,
   `replace_recovery_codes`) are startup-required.
2. **Session revocation on password change** — atomic uniquifier CAS
   (`UPDATE ... WHERE fs_uniquifier = expected`), server-side state token
   reissued, copied cookies die. Conflict → 409 + session clear.
3. **TOTP pending secret** — now server-side in `quart_security_state`
   (300 s TTL, Fernet-encrypted payload, single-use pop, bound to user_id).
   Cookies carry only opaque tokens.
4. **One-time verification** — TOTP steps consumed via atomic `claim()` insert
   keyed by `HMAC(secret_key, seed):step` (120 s TTL covers the ±1 window);
   WebAuthn challenges consumed by atomic delete with rowcount check; recovery
   codes consumed by compare-and-swap on the column.
5. **Secondary passkeys rejected as first factor** — `usage != "primary"` →
   reject at `/wan-signin-response`.
6. **Recovery endpoint policy** — `/mf-recovery` 404s when the feature flag is
   off.
7. **`qrcode[pil]` declared**; QR generation runs off the event loop.
8. **Step-up refreshes `_auth_at`** alongside `_fresh`.
9. **Password change verifies the exact submitted value** (no `.strip()`).

## Hardening beyond the original findings

- TOTP secrets encrypted at rest (Fernet, `MultiFernet` rotation, key derived
  from SECRET_KEY via HMAC); legacy plaintext migrated transparently on load.
- Recovery codes stored as keyed HMAC-SHA256 hashes; constant-time compare with
  no early exit; plaintext legacy codes migrated on use.
- **Server-side session validation on every request** (state token in cookie →
  DB lookup). Strictly stronger than Flask-Security's cookie-only model.
- Startup fail-fast: SECRET_KEY required, required model fields, atomic
  datastore hooks, state-table presence checked `before_serving`.
- Cookie flags forced: `Secure` (default on), `HttpOnly`, `SameSite=Lax`.
- Session regeneration on login; inactive users rejected at login, MFA
  completion, and per-request load.
- Atomic lockout counter (`coalesce(count,0)+1` in one UPDATE), lockout window
  also enforced at the TOTP/recovery stage.
- Open-redirect guard on `next` (rejects scheme/netloc, `//`, backslashes,
  control chars). Redirect-after-login uses config/endpoints, never user input.
- HIBP k-anonymity breach check on register/change (5-char prefix, padded
  responses, 3 s timeout, fail-open with warning log).
- Argon2id default at OWASP 2025 params (m=19 MiB, t=2, p=1), hashing off the
  event loop, transparent rehash of pbkdf2/bcrypt on login.
- WebAuthn: user verification required by default, discoverable-only sign-in,
  user-handle binding, sign-count tracked and persisted, registration requires
  fresh auth.

## Flask-Security comparison

| Control | quart-security 2.0.1 | Flask-Security (too, 5.x) |
|---|---|---|
| Password hash default | argon2id, OWASP 2025 params | bcrypt |
| Session revocation | uniquifier rotation + server-side state store | uniquifier in signed cookie |
| TOTP replay prevention | Enforced (consumed-step store, per PyOTP guidance) | Time-window verify |
| Recovery codes at rest | Keyed HMAC hashes | Plaintext list |
| Account lockout | Built-in (atomic, configurable) | Not built-in |
| Breached-password check | HIBP k-anonymity, on by default | Not built-in |
| CSRF | Session-token, all POSTs incl. JSON path, POST-only logout | Flask-WTF |
| Cookie hardening | Forced Secure/HttpOnly/Lax | Framework defaults |
| WebAuthn | Discoverable-only, UV required, usage policy enforced | Broader flows (email-first) |
| Email confirm / password reset | **Absent** | Present |
| Remember-me cookie | **Absent** (form field exists but is unused) | Present |
| Source-IP rate limiting | Delegated to host/edge (documented) | Delegated to host/edge |

Verdict on parity: on every control both libraries implement, quart-security
meets or exceeds Flask-Security defaults. The parity gaps are *feature* gaps
(confirm, recover, remember-me), not weaknesses in existing controls — absent
reset tokens also means no reset-token attack surface.

## Remaining notes (informational, none blocking)

1. **Feature gaps vs Flask-Security**: no `SECURITY_CONFIRMABLE` email
   confirmation or `SECURITY_RECOVERABLE` reset flow (flags exist in the
   template config map only). Hosts needing them must build their own.
2. ~~Dead surface~~ **Fixed 2026-10-25**: removed the unread `remember`
   LoginForm field and the unused `SECURITY_FRESHNESS_GRACE_PERIOD` default.
3. **Timing oracle**: unknown emails skip argon2 verification on login
   (measurable response-time difference; Flask-Security behaves the same).
   The lockout message also reveals existence of *locked* accounts.
4. **Registration enumeration**: "email already exists" message — same
   tradeoff as Flask-Security's default.
5. **WebAuthn credential-ID collision**: duplicate check at registration is
   scoped to the current user; global uniqueness relies on the DB unique
   constraint the README mandates. Consider a global `find_webauthn_credential`
   check for defense in depth (exploitable only with a software authenticator
   choosing arbitrary IDs).
6. **Write-on-read**: `load_user` commits when migrating legacy plaintext TOTP
   secrets — transient migration behavior on GET requests.
7. **State-row linger**: server-side session entries live for
   `permanent_session_lifetime` (31 d default) while cookies are
   browser-session; expired rows are purged on writes and via
   `purge_expired()`.
8. **Key rotation contract**: TOTP/recovery-code secrets are keyed from
   SECRET_KEY. Rotating SECRET_KEY without setting
   `SECURITY_TOTP_ENCRYPTION_KEYS` makes stored TOTP secrets unreadable —
   document alongside the 2.0 migration notes.
9. ~~Docs~~ **Fixed 2026-10-25**: CHANGELOG now documents 2.0.0 and 2.0.1.

## Host deployment gate (unchanged from README)

HTTPS; strong SECRET_KEY; explicit `SECURITY_WAN_RP_ID` /
`SECURITY_WAN_EXPECTED_ORIGIN`; unique constraints on normalized email,
`fs_uniquifier`, WebAuthn user handle and credential ID; `quart_security_state`
migration before rollout; edge/app rate limiter for distributed abuse;
`async_sessionmaker(..., expire_on_commit=False)`.
