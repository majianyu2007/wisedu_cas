# wisedu_cas

**English** | [中文](#中文)

A Python client library for Wisedu (金智教育) AuthServer CAS unified authentication.
Handles login form parsing, AES password encryption, TOTP 2FA, session management,
and automatic login protection (rate limiting, exponential backoff with jitter,
circuit breaker, single-flight lock).

Designed for programmatic access to services behind Wisedu CAS — proxies, bots,
automation scripts, and any headless integration that needs authenticated sessions.

---

## Table of Contents

- [Features](#features)
- [Non-Goals](#non-goals)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [TOTP / 2FA](#totp--2fa)
- [Exception Model](#exception-model)
- [Session Lifecycle](#session-lifecycle)
- [Retry, Backoff, and Circuit Breaker](#retry-backoff-and-circuit-breaker)
- [Concurrency and Thread Safety](#concurrency-and-thread-safety)
- [Logging and Observability](#logging-and-observability)
- [Security Considerations](#security-considerations)
- [CAS Compatibility](#cas-compatibility)
- [Testing](#testing)
- [Migration Guide](#migration-guide)
- [FAQ](#faq)
- [Versioning and Release](#versioning-and-release)
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
- **Type-safe** — complete type annotations. Public API fully documented with docstrings.
- **Log sanitisation** — passwords, tokens, and full cookie values are never
  logged in plain text.

### Non-Goals

- FIDO2 / WebAuthn / Passkey login (extension point for future versions).
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
| `totp_provider` | `Callable[[], str]` | `None` | Custom TOTP code provider. Takes precedence over `totp_secret`. |
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
    # Ask a hardware token, read from a file, query a password manager, etc.
    return external_token_source.get_code()

client = AuthClient(..., totp_provider=my_totp_provider)
```

### Manual Mode

When neither `totp_secret` nor `totp_provider` is configured, and the CAS server
requires 2FA, `login()` raises `TotpRequiredError`. The caller should prompt the
user for a code, call `client.submit_totp(code)`, then retry `login()`.

---

## Exception Model

All library exceptions inherit from `AuthError`. Callers may catch `AuthError`
for a broad handler or specific subclasses for fine-grained control.

| Exception | Meaning | Typical Response |
|-----------|---------|-----------------|
| `AuthError` | Base class for all errors. | Log and retry. |
| `NetworkError` | Connection refused, DNS failure, read timeout. | Retry with backoff. |
| `InvalidCredentialsError` | Wrong username/password or account not found. | Check `.env` / config; do not retry. |
| `CaptchaRequiredError` | CAS demands a CAPTCHA. | Wait (account temporarily restricted). |
| `TotpRequiredError` | 2FA required but not configured. | Provide `totp_secret` or prompt user. |
| `AccountLockedError` | Account locked by CAS. | Manual unlock required; do not retry. |
| `LoginBackoffError` | Login blocked by rate limit or backoff. | Wait and retry later. |
| `CircuitOpenError` | Circuit breaker open — login disabled. | Wait for circuit to expire. |
| `SessionExpiredError` | Session no longer valid. | Re-login via `ensure_logged_in()`. |
| `ParseError` | CAS page HTML structure changed. | Update parser or report issue. |

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
- Full TOTP codes (only the first 2 characters are logged for debugging, suffixed with `****`)

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

## Migration Guide

### From NWAFU DeepSeek Proxy (inline login logic)

If you currently use the login logic embedded in `nwafu_deepseek_proxy/server.py`,
migrate as follows:

**Before (proxy inline):**

```python
# Direct access to AuthSessionManager internals
session_mgr = AuthSessionManager()
client = await session_mgr.ensure_login()
# ... use client for proxy forwarding
```

**After (using wisedu_cas):**

```python
from wisedu_cas import AuthClient

client = AuthClient(
    auth_server=settings.auth_server,
    target_service=settings.target_base,
    username=settings.username,
    password=settings.password,
    totp_secret=settings.totp_secret,
    storage_path="./.data",
)
session = await client.ensure_logged_in()
# session.auth_headers() provides Host + Cookie for forwarding
```

**Key changes:**

1. `AuthSessionManager` → `AuthClient`.
2. `ensure_login()` → `ensure_logged_in()`.
3. `manager._client` → `session._client` (the httpx client is inside `AuthSession`).
4. `manager.state` → `client.state` (same `AuthState` enum).
5. Exception names are now importable from `wisedu_cas.exceptions`.
6. Cookie persistence is automatic when `storage_path` is set.
7. Encrypted password and TOTP secret are no longer read from env vars inside the
   library — they are passed explicitly via the constructor.

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

## Versioning and Release

This project follows [Semantic Versioning](https://semver.org/).

- **MAJOR** — backwards-incompatible API changes.
- **MINOR** — new features, backwards-compatible.
- **PATCH** — bug fixes, backwards-compatible.

### Release Process

```bash
# Build
python -m build

# Check
twine check dist/*

# Publish (PyPI)
twine upload dist/*
```

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

---

---

# 中文

## wisedu_cas

一个用于金智教育 (Wisedu) AuthServer CAS 统一身份认证的 Python 客户端库。
处理登录页面解析、AES 密码加密、TOTP 二次验证、会话管理，以及自动登录保护机制
（频率限制、指数退避与抖动、熔断器、单飞锁）。

适用于需要程序化访问 Wisedu CAS 后服务的场景——代理、机器人、自动化脚本，以及
任何需要已认证会话的无头集成。

---

## 目录

- [特性](#特性)
- [非目标](#非目标)
- [架构](#架构-1)
- [安装](#安装)
- [快速开始](#快速开始-1)
- [配置项详解](#配置项详解)
- [TOTP / 二次验证](#totp--二次验证)
- [异常模型](#异常模型-1)
- [会话生命周期](#会话生命周期-1)
- [重试、退避与熔断](#重试退避与熔断)
- [并发与线程安全](#并发与线程安全)
- [日志与可观测性](#日志与可观测性)
- [安全建议](#安全建议)
- [CAS 兼容性](#cas-兼容性)
- [测试](#测试)
- [迁移指南](#迁移指南-1)
- [FAQ（中文）](#faq中文)
- [版本策略与发布](#版本策略与发布)
- [贡献指南](#贡献指南)
- [许可证与免责声明](#许可证与免责声明)

---

## 特性

- **完整 CAS 登录流程** — 获取登录页、AES 加密密码、提交表单、跟随重定向链、
  完成 TOTP 二次验证、验证会话。
- **TGC 复用** — 检测已有有效 TGC Cookie 时跳过表单提交。
- **TOTP 二次验证** — 从 Base32 密钥自动生成验证码，或注入自定义提供函数。
  包含 TOTP 时间窗对齐与被拒后自动重试一次。
- **会话管理** — `cookies_dict()`、`cookie_header()`、`auth_headers()`，
  以及可选的基于文件持久化（save/load）。
- **保护层级**（由内到外）:
  1. 失败分类 — 区分账号锁定、验证码、密码错误、系统维护。
  2. 熔断器 — 连续失败 N 次后开启，在可配置时长内阻止登录。
  3. 指数退避 — `base * multiplier^n`，含随机抖动。
  4. 频率限制 — 基于滑动窗口的每小时登录次数限制。
  5. 登录冷却 — 两次登录尝试之间的最小间隔。
  6. 单飞锁 — 并发调用者中仅执行一次真实登录。
- **状态机** — `OK → SUSPECT → EXPIRED → LOGIN_BACKOFF → CIRCUIT_OPEN`。
  仅明确的 CAS 登录重定向（匹配 `auth_server` 主机名）触发重新登录。
  网络错误和上游异常转为 `SUSPECT`，不触发登录风暴。
- **通用性** — 不硬编码学校域名。`auth_server` 和 `target_service` 均为构造参数。
- **类型安全** — 完整的类型标注，公开 API 全部包含 docstring。
- **日志脱敏** — 密码、token 和完整 cookie 值不会以明文写入日志。

### 非目标

- FIDO2 / WebAuthn / Passkey 登录（未来版本的扩展点）。
- OAuth / OIDC 流程。
- HTTP 反向代理或请求转发。
- TOTP 输入 Web UI（库在手动模式下抛出 `TotpRequiredError`，由调用方提供 UI）。

---

## 架构

```
                    ┌──────────────────────────────┐
                    │         AuthClient            │
                    │  (编排、状态机、保护层)         │
                    └──────────┬───────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
   │  transport  │    │    parser    │    │    retry     │
   │  (httpx +   │    │  (CAS 页面   │    │  (退避、      │
   │   重试)      │    │   HTML 解析)  │    │   熔断、限速)  │
   └─────────────┘    └──────────────┘    └──────────────┘
          │                                        │
          ▼                                        ▼
   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
   │   crypto    │    │   session    │    │    state     │
   │  (AES-CBC)  │    │ (Cookie Jar, │    │  (AuthState  │
   │             │    │  会话验证)     │    │   枚举)       │
   └─────────────┘    └──────────────┘    └──────────────┘
```

---

## 安装

### 从 PyPI（推荐）

```bash
pip install wisedu_cas
```

### 从源码安装

```bash
git clone https://github.com/majianyu2007/wisedu_cas.git
cd wisedu_cas
pip install -e .
```

### 开发环境安装

```bash
pip install -e ".[dev]"
```

---

## 快速开始

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

带 TOTP：

```python
client = AuthClient(
    auth_server="https://authserver.example.edu.cn",
    target_service="https://target.example.edu.cn",
    username="your_username",
    password="your_password",
    totp_secret="JBSWY3DPEHPK3PXP",  # 认证器 APP 中的 Base32 密钥
)
session = await client.login()
```

日常使用推荐 `ensure_logged_in()`，它会复用现有有效会话：

```python
session = await client.ensure_logged_in()
```

---

## 配置项详解

### 必选参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `auth_server` | `str` | Wisedu AuthServer 基础 URL，如 `https://authserver.example.edu.cn`。 |
| `target_service` | `str` | CAS 保护的目标服务基础 URL，如 `https://target.example.edu.cn`。 |
| `username` | `str` | CAS 登录用户名。 |
| `password` | `str` | CAS 登录密码（明文）。 |

### 可选参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `totp_secret` | `str` | `""` | TOTP Base32 密钥。为空且需要二次验证时抛出 `TotpRequiredError`。 |
| `totp_provider` | `Callable[[], str]` | `None` | 自定义 TOTP 码提供函数，优先级高于 `totp_secret`。 |
| `retry_config` | `RetryConfig` | `RetryConfig()` | 自定义保护层参数。 |
| `storage_path` | `str \| None` | `None` | 持久化限速状态和 Cookie 的目录。`None` 时仅内存。 |
| `http_timeout` | `float` | `60.0` | HTTP 请求超时（秒）。 |
| `http_connect_timeout` | `float` | `15.0` | HTTP 连接超时（秒）。 |
| `login_min_interval` | `float` | `60` | 两次登录之间的最小间隔（秒，防风暴）。 |
| `cookie_ttl_seconds` | `float` | `7200` | 会话本地 TTL，影响 `is_session_valid()` 判断。 |

### RetryConfig 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `max_logins_per_hour` | `6` | 每小时最大登录尝试次数。 |
| `login_window_seconds` | `3600` | 频率限制窗口长度（秒）。 |
| `max_consecutive_failures` | `3` | 触发熔断的连续失败次数。 |
| `backoff_base` | `5` | 退避基数秒：`base * multiplier^n`。 |
| `backoff_multiplier` | `4` | 退避乘数：5 → 20 → 80 → 320 → 900（封顶）。 |
| `backoff_max_normal` | `900` | 普通失败最大退避（15分钟）。 |
| `backoff_max_critical` | `14400` | 严重失败最大退避（4小时）。 |
| `circuit_normal_duration` | `900` | 普通失败熔断时长（15分钟）。 |
| `circuit_critical_duration` | `21600` | 严重失败熔断时长（6小时）。 |
| `circuit_captcha_duration` | `7200` | 验证码失败熔断时长（2小时）。 |
| `circuit_password_error_duration` | `3600` | 密码错误熔断时长（1小时）。 |

---

## TOTP / 二次验证

自 2026 年 5 月起，Wisedu AuthServer 部署可能要求基于 TOTP 的二次验证。

### 自动模式（默认）

提供 `totp_secret`（认证器 APP 中的 Base32 密钥）。库自动生成验证码，
包含 TOTP 时间窗对齐（窗口内 ≥3 秒）和在被拒后使用下一窗口的验证码重试一次。

密钥可接受以下格式：

- 原始 Base32：`JBSWY3DPEHPK3PXP`
- `otpauth://` URI：`otpauth://totp/...?secret=JBSWY3DPEHPK3PXP&...`

### 自定义提供函数

```python
def my_totp_provider() -> str:
    return external_token_source.get_code()

client = AuthClient(..., totp_provider=my_totp_provider)
```

### 手动模式

如未配置 `totp_secret` 或 `totp_provider`，而 CAS 服务器要求二次验证，
`login()` 将抛出 `TotpRequiredError`。调用方应提示用户输入验证码，
调用 `client.submit_totp(code)`，然后重试 `login()`。

---

## 异常模型

所有库异常继承自 `AuthError`。调用方可捕获 `AuthError` 进行宽泛处理，
或捕获特定子类做精细控制。

| 异常类 | 含义 | 典型响应 |
|--------|------|---------|
| `AuthError` | 所有错误的基类。 | 记录日志并重试。 |
| `NetworkError` | 连接被拒、DNS 失败、读取超时。 | 退避后重试。 |
| `InvalidCredentialsError` | 用户名/密码错误或账户不存在。 | 检查配置；不要重试。 |
| `CaptchaRequiredError` | CAS 要求输入验证码。 | 等待（账户临时受限）。 |
| `TotpRequiredError` | 需要二次验证但未配置。 | 提供 `totp_secret` 或提示用户。 |
| `AccountLockedError` | 账户被 CAS 锁定。 | 需手动解锁；不要重试。 |
| `LoginBackoffError` | 登录被频率限制或退避阻止。 | 等待后重试。 |
| `CircuitOpenError` | 熔断器开启——登录被禁用。 | 等待熔断结束。 |
| `SessionExpiredError` | 会话不再有效。 | 通过 `ensure_logged_in()` 重新登录。 |
| `ParseError` | CAS 页面 HTML 结构变化。 | 更新解析器或报告问题。 |

---

## 会话生命周期

### 获取会话

- `login()` — 始终执行全新登录。用于初始认证。
- `ensure_logged_in()` — 如果有有效会话则复用，否则通过全部保护层登录。
  用于日常访问。

### 会话有效性

- `is_session_valid()` — 本地启发式判断（状态为 `OK` 且 Cookie TTL 未过）。
  不发起网络请求。
- `session.validate()` — 向目标服务发送 `HEAD` 请求，检查 CAS 重定向。
  网络错误视为"有效"（瞬时故障，非过期）。

### Cookie 持久化

```python
# 保存
session.save("./.cas/cookies.json")

# 恢复
restored = await AuthSession.load(
    "./.cas/cookies.json",
    target_service="https://target.example.edu.cn",
    auth_server="https://authserver.example.edu.cn",
)
```

`load()` 方法同时接受库自身格式和浏览器导出的 Cookie 数组格式。

---

## 重试、退避与熔断

### 指数退避

序列（默认 `base=5, multiplier=4`）：**5秒 → 20秒 → 80秒 → 320秒 → 900秒（封顶）**。
每步加入 ±25% 随机抖动以避免惊群效应。

两档上限：`backoff_max_normal`（900s）用于普通失败，
`backoff_max_critical`（14400s）用于严重失败（账号锁定、验证码）。

### 熔断器

连续失败达到 `max_consecutive_failures`（默认 3）次后开启。开启期间，
所有登录尝试抛出 `CircuitOpenError`。不同失败类型使用不同熔断时长：

| 失败类型 | 熔断时长（默认） |
|---------|-----------------|
| 普通 / 未知 | 15 分钟 |
| 密码错误 | 1 小时 |
| 需要验证码 | 2 小时 |
| 账号锁定 | 6 小时 |

### 频率限制

滑动窗口：每 `login_window_seconds`（默认 3600s）内最多
`max_logins_per_hour`（默认 6）次登录尝试。状态可选持久化到
`{storage_path}/login_state.json`，进程重启后保留。

---

## 并发与线程安全

`AuthClient` 使用 `asyncio.Lock` 实现单飞锁，设计为**异步**使用。
**不**支持同步 `threading` 场景的线程安全。

- 多个 `asyncio.Task` 并发调用 `ensure_logged_in()` 时会串行化：
  仅执行一次真实登录，其他调用者复用结果。
- 如需线程安全访问，使用 `asyncio.run()` 包裹或外部管理同步。

---

## 日志与可观测性

库向 `wisedu_cas` 日志层次输出：

- `wisedu_cas.client` — 状态迁移、登录尝试、结果。
- `wisedu_cas.transport` — 网络重试。
- `wisedu_cas.retry` — 熔断器事件。
- `wisedu_cas.session` — Cookie 保存/加载事件。

### 脱敏

以下内容**不会**以明文写入日志：

- `password` 参数
- 完整 cookie 值（仅记录 cookie 名称和数量）
- 完整 TOTP 码（仅记录前 2 字符用于调试，后跟 `****`）

### 集成

```python
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("wisedu_cas").setLevel(logging.DEBUG)
```

---

## 安全建议

1. **凭证存储** — 通过环境变量或密钥管理器传递 `password` 和 `totp_secret`。
   切勿硬编码在源文件中。
2. **Cookie 文件** — `save()` 以明文 JSON 写入 Cookie。若存盘，请限制文件权限
   （`chmod 600`）。
3. **日志输出** — 库已对密码和 token 脱敏，但调用代码应避免记录
   `session.cookies_dict()` 原始输出。
4. **传输安全** — 生产环境中始终对 `auth_server` 和 `target_service` 使用 `https://`。
5. **最小权限** — 若目标服务支持限域 API Key 或 Token，优先使用它们而非完整
   会话 Cookie。

---

## CAS 兼容性

本库针对**金智教育 (Wisedu) AuthServer** 部署。已在西北农林科技大学 (NWAFU)
AuthServer 上测试（截至 2026 年 5 月）。

### 已知兼容性因素

| 方面 | 路径/字段 | 备注 |
|------|----------|------|
| 登录页路径 | `/authserver/login` | Wisedu 标准路径。 |
| 表单字段 | `username`, `password`, `execution`, `pwdEncryptSalt`, `rememberMe` | 标准字段。 |
| AES 加密 | AES-128-CBC，64 字符随机前缀 + 16 字符 IV | 与 `encrypt.js` 一致。 |
| TOTP 二次验证 | `reAuthCheck/reAuthLoginView.do` → `changeReAuthType.do` → `reAuthSubmit.do` | 不同 Wisedu 版本可能有差异。 |
| 错误响应 | JSON `resultCode` 或 HTML `<div id="formErrorTip">` | 两种格式均已处理。 |
| Service URL 模式 | `{target}/.auth/login/cas/callback?return_to={target}/` | Open WebUI 标准模式。 |

### 可扩展性

若不同 Wisedu 部署使用不同的表单字段 ID、错误模式或二次验证端点，
`parser.py`（基于正则）和 `client.py` 中的 `_complete_2fa()` 方法
是扩展点。欢迎贡献额外的变体适配。

---

## 测试

### 运行测试

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行全部测试
pytest

# 含覆盖率
pytest --cov=wisedu_cas --cov-report=term-missing
```

### 覆盖范围

| 测试模块 | 范围 |
|---------|------|
| `test_parser.py` | CAS HTML 解析 —— execution/salt 提取、错误文本、CAS 字段检测。 |
| `test_state_machine.py` | `AuthState` 枚举 —— 值、相等性、字符串表示。 |
| `test_retry_and_circuit.py` | 频率限制、退避计算、熔断器 —— 开启/关闭/过期。 |
| `test_session_validation.py` | `AuthSession` —— cookies_dict、cookie_header、auth_headers、save/load、CAS URL 检测、验证探测。 |
| `test_client.py` | `AuthClient` —— 完整登录流程、TGC 复用、错误分类（JSON 和 HTML）、快速路径、熔断器集成、频率限制、单飞并发。 |

所有测试使用 `pytest-httpx` 模拟 HTTP 响应，不需要真实校园网络。

---

## 迁移指南

### 从 NWAFU DeepSeek Proxy 内联登录逻辑迁移

**迁移前（代理内联）：**

```python
session_mgr = AuthSessionManager()
client = await session_mgr.ensure_login()
```

**迁移后（使用 wisedu_cas）：**

```python
from wisedu_cas import AuthClient

client = AuthClient(
    auth_server=settings.auth_server,
    target_service=settings.target_base,
    username=settings.username,
    password=settings.password,
    totp_secret=settings.totp_secret,
    storage_path="./.data",
)
session = await client.ensure_logged_in()
```

**关键变更：**

1. `AuthSessionManager` → `AuthClient`。
2. `ensure_login()` → `ensure_logged_in()`。
3. `manager._client` → `session._client`（httpx client 在 `AuthSession` 内）。
4. `manager.state` → `client.state`（相同 `AuthState` 枚举）。
5. 异常类现可从 `wisedu_cas.exceptions` 导入。
6. 设置 `storage_path` 后 Cookie 自动持久化。
7. 加密密码和 TOTP 密钥不再在库内部从环境变量读取——通过构造参数显式传入。

---

## FAQ（中文）

**Q: 这个库能用于非 Wisedu 的 CAS 服务器吗？**

不能。本库专用于金智教育 (Wisedu) AuthServer。通用 CAS（Jasig/Apereo）服务器
使用不同的表单字段、无 AES 加密，且二次验证流程不同。

**Q: CAS 服务器宕机时会发生什么？**

`login()` 抛出 `NetworkError`。状态机转为 `SUSPECT`。不会发生登录重试风暴——
只有明确的 CAS 登录重定向才会触发重新登录。

**Q: 可以同步使用吗？**

`AuthClient` 仅支持异步。如需同步，使用 `asyncio.run()` 包裹。

**Q: 如何在进程重启后保留 Cookie？**

在构造函数中设置 `storage_path`。登录成功后 Cookie 自动保存。下次构建时，
状态（频率限制、熔断）会自动恢复，调用方可在 `ensure_logged_in()` 前使用
`AuthSession.load()` 恢复 Cookie。

**Q: 如果学校使用不同的二次验证方式怎么办？**

当前实现仅支持 TOTP。其他方式（短信、邮件、FIDO2）尚未支持。
`client.py` 中的 `_complete_2fa()` 方法可通过子类化或 monkey-patch 覆盖。

**Q: 硬编码密码安全吗？**

不安全。始终从环境变量、`.env` 文件或密钥管理器加载凭证。

---

## 版本策略与发布

本项目遵循 [语义化版本 (Semantic Versioning)](https://semver.org/lang/zh-CN/)。

- **主版本号 (MAJOR)** — 不兼容的 API 变更。
- **次版本号 (MINOR)** — 向后兼容的新功能。
- **修订号 (PATCH)** — 向后兼容的问题修复。

### 发布流程

```bash
# 构建
python -m build

# 检查
twine check dist/*

# 发布（PyPI）
twine upload dist/*
```

---

## 贡献指南

欢迎贡献。请遵循以下流程：

1. 先开 Issue 讨论变更再实施。
2. 为新功能添加测试。
3. 确保 `pytest` 通过。
4. 在 `[Unreleased]` 下更新 `CHANGELOG.md`。
5. 向 `main` 分支提交 Pull Request。

### 开发环境

```bash
git clone https://github.com/majianyu2007/wisedu_cas.git
cd wisedu_cas
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## 许可证与免责声明

MIT License。详见 [LICENSE](LICENSE) 文件。

**免责声明：** 本项目与金智教育 (Wisedu) 或任何特定高校无关联、未获背书亦无合作关系。
它是一个独立开源库，出于教育和工程目的开发。用户在使用本库进行自动认证时，
有责任遵守所在机构的可接受使用政策。
