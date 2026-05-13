# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-05-13

### Added
- FIDO2/WebAuthn passkey authentication (`wisedu_cas/fido2.py`).
- `auth_method` parameter on `AuthClient`: `"password"`, `"fido2"`, `"auto"`.
- `Fido2Credential` data model for pre-extracted ECDSA P-256 credentials.
- `Fido2Authenticator` orchestrator: startAssertion, assertion building, submission.
- `Fido2AssertionError` and `Fido2NotConfiguredError` exceptions.
- `auto` auth mode: try FIDO2 first, transparent fallback to password+TOTP.
- All protection layers (rate limit, backoff, circuit breaker, single-flight)
  apply to FIDO2 and auto paths identically.
- `examples/with_fido2.py` and `examples/auto_auth_method.py`.
- 16 new pytest tests covering FIDO2 credential model, assertion building,
  startAssertion, full authenticator flow, AuthClient FIDO2 integration,
  auto fallback, and circuit breaker interaction.

### Not yet supported
- FIDO2 credentials from OS keychain or hardware security keys (requires
  pre-extracted credential file from browser passkey export).
- FIDO2 + TOTP combined flows (if 2FA is required after passkey login).
- WebAuthn registration / credential creation on-device.

## [0.1.0] — 2026-05-13

### Added
- Initial pre-release.

- `AuthClient` — primary entry point for Wisedu CAS authentication.
- `AuthSession` — session representation with `cookies_dict()`, `cookie_header()`, `auth_headers()`, `validate()`, `save()`, `load()`.
- `AuthState` — state machine: `OK`, `SUSPECT`, `EXPIRED`, `LOGIN_BACKOFF`, `CIRCUIT_OPEN`.
- Complete exception hierarchy: `AuthError`, `NetworkError`, `InvalidCredentialsError`, `CaptchaRequiredError`, `TotpRequiredError`, `AccountLockedError`, `LoginBackoffError`, `CircuitOpenError`, `SessionExpiredError`, `ParseError`.
- AES-CBC password encryption matching Wisedu frontend `encrypt.js`.
- CAS login form HTML parsing (execution, salt, error text extraction).
- Login protection layers: rate limiter, exponential backoff with jitter, circuit breaker, single-flight lock.
- TOTP 2FA auto-generation via `pyotp` with window alignment and retry-on-rejection.
- Pluggable TOTP provider (`totp_provider` callable).
- Optional file-based state persistence (rate limit, circuit breaker) and cookie persistence.
- Full type hints and public API docstrings.
- `examples/` directory with basic_login, with_totp, and custom_retry_policy scripts.
- `tests/` directory with pytest suite covering parser, state machine, retry/circuit, session validation, client flows.
- Bilingual (ZH/EN) README with comprehensive documentation.
