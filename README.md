# wisedu_cas

A Python client library for Wisedu (金智教育) AuthServer CAS unified authentication.
Handles login form parsing, AES password encryption, TOTP 2FA, session management,
and automatic login protection (rate limiting, exponential backoff with jitter,
circuit breaker, single-flight lock).

Designed for programmatic access to services behind Wisedu CAS — proxies, bots,
automation scripts, and any headless integration that needs authenticated sessions.

中文文档见 [README.zh-CN.md](README.zh-CN.md).

---

## Table of Contents

- [Features](#features)
- [Non-Goals](#non-goals)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [TOTP / 2FA](#totp--2fa)
- [FIDO2 / Passkey](#fido2--passkey)
- [Exception Model](#exception-model)
- [Session Lifecycle](#session-lifecycle)
- [Retry, Backoff, and Circuit Breaker](#retry-backoff-and-circuit-breaker)
- [Concurrency and Thread Safety](#concurrency-and-thread-safety)
- [Logging and Observability](#logging-and-observability)
- [Security Considerations](#security-considerations)
- [CAS Compatibility](#cas-compatibility)
- [Testing](#testing)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License and Disclaimer](#license-and-disclaimer)

---

## Features

- **Full CAS login flow** — fetch login page, AES-encrypt password, submit form,
  follow redirect chain, complete TOTP 2FA, validate session.
- **TGC reuse** — detects an existing valid TGC cookie and skips form submission.
- **TOTP 2FA** — auto-generate codes from a Base32 secret, or inject a custom
  provider callable. Includes TOTP window alignment and one automatic retry on
  code rejection.
- **Session management** — `cookies_dict()`, `cookie_header()`, `auth_headers()`,
  and optional file-based persistence (save/load).
- **Protection layers** (innermost to outermost):
  1. Failure classification — distinguishes account locked, captcha, wrong password, maintenance.
  2. Circuit breaker — opens after N consecutive failures, blocks login for a configurable duration.
  3. Exponential backoff — `base * multiplier^n` with jitter.
  4. Rate limiter — rolling-window limit on login attempts per hour.
  5. Login cooldown — minimum interval between successive login attempts.
  6. Single-flight lock — one real login across concurrent callers.
- **State machine** — `OK → SUSPECT → EXPIRED → LOGIN_BACKOFF → CIRCUIT_OPEN`.
  Only definitive CAS login redirects (matching the `auth_server` host) trigger
  re-login. Network errors and upstream issues transition to `SUSPECT` without
  triggering login storms.
- **Generic** — no hardcoded school domain. `auth_server` and `target_service`
  are constructor parameters.
- **FIDO2 / Passkey** — passwordless login using a pre-extracted ECDSA P-256
  credential. Selectable via ``auth_method`` with ``"auto"`` fallback mode.
- **Type-safe** — complete type annotations. Public API fully documented with docstrings.
- **Log sanitisation** — passwords, tokens, and full cookie values are never
  logged in plain text.

### Non-Goals

- FIDO2 credential creation / WebAuthn registration on-device.
- FIDO2 credentials from OS keychain or hardware security keys
  (requires pre-extracted credential file from a browser passkey export).
- OAuth / OIDC flows.
- HTTP reverse proxy or request forwarding.
- Web UI for TOTP entry (the library raises `TotpRequiredError` for manual mode;
  the caller provides the UI).

---

## Architecture

```
                    ┌──────────────────────────────┐
                    │         AuthClient            │
                    │  (orchestration, state        │
                    │   machine, protection layers) │
                    └──────────┬───────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
   │  transport  │    │    parser    │    │    retry     │
   │  (httpx +   │    │  (CAS HTML   │    │  (backoff,   │
   │   retry)    │    │   parsing)   │    │   circuit,   │
   └─────────────┘    └──────────────┘    │   rate-limit) │
                                          └──────────────┘
          │                                        │
          ▼                                        ▼
   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
   │   crypto    │    │   session    │    │    state     │
   │  (AES-CBC)  │    │ (cookie jar, │    │  (AuthState  │
   │             │    │  validation) │    │   enum)       │
   └─────────────┘    └──────────────┘    └──────────────┘
```

### Login Sequence

```
AuthClient.login()
  │
  ├─ 1. GET {auth_server}/authserver/login?service={target}/.auth/login/cas/callback
  │     ├─ 302 → TGC exists, follow redirect chain → validate → return session
  │     └─ 200 → parse execution + pwdEncryptSalt from HTML
  │
  ├─ 2. AES-CBC encrypt password with salt
  │
  ├─ 3. POST login form (username, encrypted_password, execution, rememberMe)
  │     ├─ 302 → follow redirect chain
  │     │       ├─ /reAuthLoginView.do → complete 2FA with TOTP
  │     │       └─ → callback URL → session established
  │     └─ 200 → classify failure → raise appropriate exception
  │
  └─ 4. HEAD-probe target service → confirm session is usable
```

---

## Installation

### From PyPI (recommended)

```bash
pip install wisedu_cas
```

### From source

```bash
git clone https://github.com/majianyu2007/wisedu_cas.git
cd wisedu_cas
pip install -e .
```

### Development install

```bash
pip install -e ".[dev]"
```

---

## Quick Start

```python
import asyncio
from wisedu_cas import AuthClient

async def main():
    client = AuthClient(
        auth_server="https://authserver.example.edu.cn",
        target_service="https://target.example.edu.cn",
        username="your_username",
        password="your_password",
    )
    session = await client.login()
    print(session.cookies_dict())
    await client.close()

asyncio.run(main())
```

With TOTP:

```python
client = AuthClient(
    auth_server="https://authserver.example.edu.cn",
    target_service="https://target.example.edu.cn",
    username="your_username",
    password="your_password",
    totp_secret="JBSWY3DPEHPK3PXP",  # Base32 secret from authenticator app
)
session = await client.login()
```

With FIDO2 passkey:

```python
from wisedu_cas import AuthClient, Fido2Credential

cred = Fido2Credential(
    credential_id="a99118bb-...",
    key_value="MIH...",
    rp_id="authserver.example.edu.cn",
    device_binding_id="...",
)
client = AuthClient(
    auth_server="https://authserver.example.edu.cn",
    target_service="https://target.example.edu.cn",
    username="your_username",
    password="your_password",
    auth_method="fido2",
    fido2_credential=cred,
)
session = await client.login()
```

For routine use, prefer `ensure_logged_in()` which reuses an existing valid session:

```python
session = await client.ensure_logged_in()
```

---

## Configuration Reference

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `auth_server` | `str` | Base URL of the Wisedu AuthServer, e.g. `https://authserver.example.edu.cn`. |
| `target_service` | `str` | Base URL of the CAS-protected target service, e.g. `https://target.example.edu.cn`. |
| `username` | `str` | CAS login username. |
| `password` | `str` | CAS login password (plain text). |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `totp_secret` | `str` | `""` | Base32 TOTP secret for 2FA. If empty and 2FA is required, `TotpRequiredError` is raised. |
| `totp_provider` | `Callable[[], str]` | `None` | Custom TOTP code provider (synchronous). Takes precedence over `totp_secret`. |
| `auth_method` | `Literal["password","fido2","auto"]` | `"password"` | Authentication method. See [FIDO2 / Passkey](#fido2--passkey). |
| `fido2_credential` | `Fido2Credential \| None` | `None` | Credential for FIDO2 login. Required when ``auth_method`` is ``"fido2"``. |
| `retry_config` | `RetryConfig` | `RetryConfig()` | Custom protection-layer parameters (see below). |
| `storage_path` | `str \| None` | `None` | Directory for persisting rate-limit state and cookies. In-memory only when `None`. |
| `http_timeout` | `float` | `60.0` | Total HTTP request timeout (seconds). |
| `http_connect_timeout` | `float` | `15.0` | HTTP connection timeout (seconds). |
| `login_min_interval` | `float` | `60` | Minimum seconds between two login attempts (anti-storm). |
| `cookie_ttl_seconds` | `float` | `7200` | Local TTL for a session before it is considered stale for `is_session_valid()`. |

### RetryConfig Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_logins_per_hour` | `6` | Maximum login attempts in a rolling window. |
| `login_window_seconds` | `3600` | Length of the rate-limit window (seconds). |
| `max_consecutive_failures` | `3` | Consecutive failures before circuit breaker opens. |
| `backoff_base` | `5` | Base seconds for backoff: `base * multiplier^n`. |
| `backoff_multiplier` | `4` | Multiplier: 5 → 20 → 80 → 320 → 900 (capped). |
| `backoff_max_normal` | `900` | Maximum normal backoff (15 min). |
| `backoff_max_critical` | `14400` | Maximum critical backoff (4 hours). |
| `circuit_normal_duration` | `900` | Circuit duration for normal failures (15 min). |
| `circuit_critical_duration` | `21600` | Circuit duration for critical failures e.g. account locked (6 hours). |
| `circuit_captcha_duration` | `7200` | Circuit duration for captcha-detected failures (2 hours). |
| `circuit_password_error_duration` | `3600` | Circuit duration for password errors (1 hour). |

---

## TOTP / 2FA

Since approximately May 2026, Wisedu AuthServer deployments may require TOTP-based
second-factor authentication.

### Auto Mode (default)

Provide `totp_secret` (the Base32 key from your authenticator app). The library
generates codes automatically with TOTP window alignment (±3s into the window)
and retries once with the next window's code on rejection.

The secret may be provided in any of these formats:

- Raw Base32: `JBSWY3DPEHPK3PXP`
- `otpauth://` URI: `otpauth://totp/...?secret=JBSWY3DPEHPK3PXP&...`

### Custom Provider

```python
def my_totp_provider() -> str:
    return external_token_source.get_code()

client = AuthClient(..., totp_provider=my_totp_provider)
```

### Manual Mode

When neither `totp_secret` nor `totp_provider` is configured, and the CAS server
requires 2FA, `login()` raises `TotpRequiredError`. The caller should prompt the
user for a code, call `client.submit_totp(code)`, then retry `login()`.

---

## FIDO2 / Passkey

FIDO2/WebAuthn passkey login is available as an alternative to password
authentication. It requires a **pre-extracted credential** containing an
ECDSA P-256 private key, typically exported from a browser passkey store
(e.g. Bitwarden).

### Prerequisites

1. A FIDO2 credential exported as JSON, containing at minimum:
   - `credentialId` — the hex credential ID.
   - `keyValue` — the Base64-encoded DER private key (ECDSA P-256).
   - `rpId` — the Relying Party ID (AuthServer hostname).
   - `deviceBindingId` — the device-binding UUID for the Wisedu AuthServer
     (obtained from the browser's FIDO2 registration flow).

2. `cryptography>=42.0.0` (included in the library's optional `[dev]` extras
   or can be installed separately).

### Usage

```python
from wisedu_cas import AuthClient, Fido2Credential

cred = Fido2Credential.from_dict(json.load(open("credential.json")))
client = AuthClient(
    auth_server="https://authserver.example.edu.cn",
    target_service="https://target.example.edu.cn",
    username="your_username",
    password="your_password",  # fallback in "auto" mode
    auth_method="fido2",
    fido2_credential=cred,
)
session = await client.login()
```

### Auto Mode

When ``auth_method="auto"``, the library tries FIDO2 first. If it fails for
any reason (missing credential, server rejection, network error), it falls
back transparently to password + AES + optional TOTP.

| Scenario | FIDO2 Result | Behaviour |
|----------|-------------|-----------|
| FIDO2 succeeds | TGC obtained | Returns session; no password needed. |
| No credential configured | `None` | Falls back to password. |
| startAssertion rejected | `Fido2AssertionError` | Falls back to password. |
| Assertion rejected by server | non-302 response | Falls back to password. |
| Network error | `NetworkError` | Propagated as-is (with backoff/circuit). |

All protection layers (rate limiting, backoff, circuit breaker, single-flight)
apply identically to both FIDO2 and password paths. Consecutive FIDO2 failures
increment the same failure counter and can open the circuit breaker.

### Security Notes

- The private key is loaded into memory during authentication only. It is
  never logged, persisted, or transmitted outside the assertion signature.
- Credential files should be stored with restricted permissions
  (``chmod 600``).
- The library signs assertions locally; the private key never leaves the
  process.

---

## Exception Model

All library exceptions inherit from `AuthError`. Callers may catch `AuthError`
for a broad handler or specific subclasses for fine-grained control.

| Exception | Meaning | Typical Response |
|-----------|---------|-----------------|
| `AuthError` | Base class for all errors. | Log and retry. |
| `NetworkError` | Connection refused, DNS failure, read timeout. | Retry with backoff. |
| `InvalidCredentialsError` | Wrong username/password or account not found. | Check config; do not retry. |
| `CaptchaRequiredError` | CAS demands a CAPTCHA. | Wait (account temporarily restricted). |
| `TotpRequiredError` | 2FA required but not configured. | Provide `totp_secret` or prompt user. |
| `AccountLockedError` | Account locked by CAS. | Manual unlock required; do not retry. |
| `LoginBackoffError` | Login blocked by rate limit or backoff. | Wait and retry later. |
| `CircuitOpenError` | Circuit breaker open — login disabled. | Wait for circuit to expire. |
| `SessionExpiredError` | Session no longer valid. | Re-login via `ensure_logged_in()`. |
| `ParseError` | CAS page HTML structure changed. | Update parser or report issue. |
| `Fido2NotConfiguredError` | FIDO2 requested but no credential configured. | Provide a valid credential or switch to password. |
| `Fido2AssertionError` | Building or submitting the assertion failed. | Check credential validity; retry with backoff. |

---

## Session Lifecycle

### Obtaining a Session

- `login()` — always executes a fresh login. Use for initial authentication.
- `ensure_logged_in()` — returns an existing valid session if available; otherwise
  logs in through all protection layers. Use for routine access.

### Session Validity

- `is_session_valid()` — local heuristic (state is `OK` and cookie TTL not exceeded).
  No network request.
- `session.validate()` — sends a `HEAD` request to the target service and checks for
  a CAS redirect. Network errors are treated as "valid" (transient failure, not expiry).

### Cookie Persistence

```python
# Save
session.save("./.cas/cookies.json")

# Restore
restored = await AuthSession.load(
    "./.cas/cookies.json",
    target_service="https://target.example.edu.cn",
    auth_server="https://authserver.example.edu.cn",
)
```

The `load()` method accepts both the library's own JSON format and browser-exported
cookie arrays (compatible with common browser extension exports).

---

## Retry, Backoff, and Circuit Breaker

### Exponential Backoff

Sequence (with `base=5, multiplier=4`): **5s → 20s → 80s → 320s → 900s (capped)**.
Each value is jittered to ±25% to avoid thundering-herd effects.

Two caps exist: `backoff_max_normal` (900s) for generic failures, and
`backoff_max_critical` (14400s) for critical failures (account locked, captcha).

### Circuit Breaker

Opens after `max_consecutive_failures` (default 3) consecutive failures.
While open, all login attempts raise `CircuitOpenError`. Different failure types
use different circuit durations:

| Failure Type | Circuit Duration (default) |
|---|---|
| Normal / Unknown | 15 minutes |
| Password Error | 1 hour |
| Captcha Required | 2 hours |
| Account Locked | 6 hours |

### Rate Limiter

Rolling-window rate limiter: at most `max_logins_per_hour` (default 6) login
attempts per `login_window_seconds` (default 3600). State is optionally persisted
to `{storage_path}/login_state.json` for survival across process restarts.

---

## Concurrency and Thread Safety

`AuthClient` uses `asyncio.Lock` for its single-flight mechanism and is designed
for **async** usage. It is **not** thread-safe for synchronous `threading` use.

- Multiple `asyncio.Task`s calling `ensure_logged_in()` concurrently will be
  serialised: only one real login executes; others receive the result.
- If you need thread-safe access, wrap calls in `asyncio.run()` or manage
  synchronisation externally.

---

## Logging and Observability

The library logs to the `wisedu_cas` logger hierarchy:

- `wisedu_cas.client` — state transitions, login attempts, results.
- `wisedu_cas.transport` — network retries.
- `wisedu_cas.retry` — circuit breaker events.
- `wisedu_cas.session` — cookie save/load events.

### Sanitisation

The following are **never** logged in plain text:

- The `password` parameter
- Full cookie values (only cookie names and counts are logged)
- Full TOTP codes (only the first 2 characters are logged, suffixed with `****`)

### Integration

```python
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("wisedu_cas").setLevel(logging.DEBUG)
```

---

## Security Considerations

1. **Credential storage** — pass `password` and `totp_secret` via environment
   variables or a secrets manager. Never hardcode them in source files.
2. **Cookie files** — `save()` writes cookies in plain JSON. Restrict file
   permissions (`chmod 600`) if storing on disk.
3. **Log output** — the library sanitises passwords and tokens, but calling code
   should avoid logging raw `session.cookies_dict()` output.
4. **Transport** — always use `https://` for `auth_server` and `target_service`
   in production.
5. **Minimum privilege** — if the target service supports scoped API keys or
   tokens, prefer those over full session cookies where possible.

---

## CAS Compatibility

This library targets **Wisedu (金智教育) AuthServer** deployments. It has been
tested against the NWAFU (西北农林科技大学) AuthServer as of May 2026.

### Known Compatibility Factors

| Aspect | Behaviour | Notes |
|--------|-----------|-------|
| Login page path | `/authserver/login` | Standard Wisedu path. |
| Form fields | `username`, `password`, `execution`, `pwdEncryptSalt`, `rememberMe` | Standard. |
| AES encryption | AES-128-CBC, 64-char random prefix + 16-char IV | Matches `encrypt.js`. |
| TOTP 2FA | `reAuthCheck/reAuthLoginView.do` → `changeReAuthType.do` → `reAuthSubmit.do` | May differ across Wisedu versions. |
| Error responses | JSON `resultCode` or HTML `<div id="formErrorTip">` | Both formats handled. |
| Service URL pattern | `{target}/.auth/login/cas/callback?return_to={target}/` | Standard for Open WebUI. |

### Extensibility

If a different Wisedu deployment uses alternative form field IDs, error patterns,
or 2FA endpoints, the `parser.py` module (regex-based) and `_complete_2fa()` in
`client.py` serve as the extension points. Contributions for additional variants
are welcome.

---

## Testing

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full suite
pytest

# With coverage
pytest --cov=wisedu_cas --cov-report=term-missing
```

### What Is Covered

| Test Module | Scope |
|-------------|-------|
| `test_parser.py` | CAS HTML parsing — execution/salt extraction, error text, body CAS field detection. |
| `test_state_machine.py` | `AuthState` enum — values, equality, string representation. |
| `test_retry_and_circuit.py` | Rate limiter, backoff calculator, circuit breaker — open/close/expire. |
| `test_session_validation.py` | `AuthSession` — cookies_dict, cookie_header, auth_headers, save/load, CAS URL detection, validation probe. |
| `test_client.py` | `AuthClient` — full login flow, TGC reuse, error classification (JSON and HTML), fast path, circuit breaker integration, rate limiting, single-flight concurrency. |

All tests use `pytest-httpx` to mock HTTP responses. No real campus network is required.

---

## FAQ

**Q: Does this library work with non-Wisedu CAS servers?**

No. This library targets the Wisedu (金智教育) AuthServer specifically. Generic
CAS (Jasig/Apereo) servers use different form fields, no AES encryption, and
different 2FA flows.

**Q: What happens if the CAS server is down?**

`login()` raises `NetworkError`. The state machine transitions to `SUSPECT`.
No login retry storm occurs — only definitive CAS login redirects trigger re-login.

**Q: Can I use this synchronously?**

`AuthClient` is async-only. Wrap calls with `asyncio.run()` if needed.

**Q: How do I persist cookies across process restarts?**

Set `storage_path` in the constructor. On login success, cookies are saved
automatically. On next construction, state (rate limits, circuit) is restored,
and callers can use `AuthSession.load()` to restore cookies before attempting
`ensure_logged_in()`.

**Q: What if my school uses a different 2FA method?**

The current implementation supports TOTP only. Other methods (SMS, email, FIDO2)
are not yet supported. The `_complete_2fa()` method in `client.py` can be
overridden via subclassing or monkey-patching for custom flows.

**Q: Is it safe to hardcode my password?**

No. Always load credentials from environment variables, a `.env` file (via
`python-dotenv`), or a secrets manager.

---

## Contributing

Contributions are welcome. Please:

1. Open an issue to discuss the change before implementing.
2. Add tests for new functionality.
3. Ensure `pytest` passes.
4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Submit a pull request against the `main` branch.

### Development Environment

```bash
git clone https://github.com/majianyu2007/wisedu_cas.git
cd wisedu_cas
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## License and Disclaimer

MIT License. See [LICENSE](LICENSE) for full text.

**Disclaimer:** This project is not affiliated with, endorsed by, or connected to
Wisedu (金智教育) or any specific university. It is an independent open-source
library developed for educational and engineering purposes. Users are responsible
for complying with their institution's acceptable-use policies when automating
authentication.
