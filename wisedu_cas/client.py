"""
AuthClient — primary entry point for Wisedu CAS authentication.

Orchestrates the full login flow: CAS form parsing, AES password encryption,
form submission, TOTP 2FA completion, redirect following, and session
validation, with all protection layers (rate limiting, backoff, circuit breaker,
single-flight lock) active.
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Callable, Literal, Optional, Tuple
from urllib.parse import parse_qs, quote, urljoin, urlparse

import httpx
import pyotp

from wisedu_cas.crypto import encrypt_password
from wisedu_cas.exceptions import (
    AccountLockedError,
    AuthError,
    CaptchaRequiredError,
    CircuitOpenError,
    Fido2AssertionError,
    Fido2NotConfiguredError,
    InvalidCredentialsError,
    LoginBackoffError,
    NetworkError,
    ParseError,
    SessionExpiredError,
    TotpRequiredError,
)
from wisedu_cas.fido2 import (
    Fido2Authenticator,
    Fido2Credential,
    extract_execution,
)
from wisedu_cas.models import CASFormFields, LoginResult
from wisedu_cas.parser import (
    body_contains_cas_fields,
    extract_error_text,
    parse_login_form,
)
from wisedu_cas.retry import (
    BackoffCalculator,
    CircuitBreaker,
    RateLimiter,
    RetryConfig,
    SingleFlightLock,
)
from wisedu_cas.session import AuthSession, _is_cas_login_url
from wisedu_cas.state import AuthState
from wisedu_cas.transport import (
    RETRIABLE_NET_ERRORS,
    create_http_client,
    retry_request,
)

logger = logging.getLogger("wisedu_cas.client")

# Matches the 2FA re-auth view URL path.
_RE_AUTH_VIEW = re.compile(r"/authserver/reAuthCheck/reAuthLoginView\.do", re.I)

# Minimum interval between two login attempts (anti-storm).
_DEFAULT_LOGIN_MIN_INTERVAL = 60

# Force-relogin throttle window.
_FORCE_RELOGIN_THROTTLE = 10


class AuthClient:
    """Wisedu CAS authentication client.

    Manages the complete session lifecycle against a Wisedu AuthServer,
    including login, 2FA/TOTP, session validation, cookie persistence,
    and all protection layers (rate limiting, exponential backoff, circuit breaker,
    single-flight lock).

    Supports two authentication methods (see *auth_method*):

    - ``"password"`` (default): AES-encrypted password + optional TOTP 2FA.
    - ``"fido2"``: FIDO2/WebAuthn passkey login using a pre-extracted credential.
    - ``"auto"``: Try FIDO2 first; fall back to password on failure.

    Args:
        auth_server: Base URL of the Wisedu AuthServer
            (e.g. ``"https://authserver.example.edu.cn"``).
        target_service: Base URL of the target service protected by CAS
            (e.g. ``"https://target.example.edu.cn"``).
        username: CAS login username.
        password: CAS login password (plain text; never logged). Required
            even in ``"fido2"`` mode — used by the Auto mode as a fallback.
        totp_secret: Base32 TOTP secret for 2FA. If omitted and 2FA is required,
            login will raise :class:`TotpRequiredError`.
        totp_provider: Optional callable ``() -> str`` that returns a TOTP
            code synchronously. Takes precedence over *totp_secret* when provided.
        auth_method: Authentication method: ``"password"``, ``"fido2"``, or
            ``"auto"`` (default ``"password"``).
        fido2_credential: A :class:`Fido2Credential` for passkey login.
            Required when *auth_method* is ``"fido2"``; optional for ``"auto"``.
        retry_config: Optional :class:`RetryConfig` to customize protection parameters.
        storage_path: Optional directory path for persisting login state
            (rate limits, circuit state). If ``None``, all state is in-memory.
        http_timeout: HTTP request timeout in seconds (default 60).
        http_connect_timeout: HTTP connect timeout in seconds (default 15).
    """

    def __init__(
        self,
        auth_server: str,
        target_service: str,
        username: str,
        password: str,
        *,
        totp_secret: str = "",
        totp_provider: Optional[Callable[[], str]] = None,
        auth_method: Literal["password", "fido2", "auto"] = "password",
        fido2_credential: Optional[Fido2Credential] = None,
        retry_config: Optional[RetryConfig] = None,
        storage_path: Optional[str] = None,
        http_timeout: float = 60.0,
        http_connect_timeout: float = 15.0,
        login_min_interval: float = _DEFAULT_LOGIN_MIN_INTERVAL,
        cookie_ttl_seconds: float = 7200,
    ) -> None:
        self.auth_server = auth_server.rstrip("/")
        self.target_service = target_service.rstrip("/")
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self._totp_provider = totp_provider
        allowed_auth_methods = {"password", "fido2", "auto"}
        if auth_method not in allowed_auth_methods:
            raise ValueError(
                f"Unsupported auth_method: {auth_method!r}. "
                f"Expected one of {sorted(allowed_auth_methods)}."
            )
        self._auth_method: Literal["password", "fido2", "auto"] = auth_method
        self._http_timeout = http_timeout
        self._http_connect_timeout = http_connect_timeout
        self._login_min_interval = login_min_interval
        self._cookie_ttl = cookie_ttl_seconds

        # FIDO2
        self._fido2_credential = fido2_credential
        self._fido2_auth: Optional[Fido2Authenticator] = None
        if fido2_credential and fido2_credential.is_valid():
            self._fido2_auth = Fido2Authenticator(
                auth_server=self.auth_server,
                username=self.username,
                credential=fido2_credential,
            )

        self._retry_config = retry_config or RetryConfig()

        # Storage paths
        state_path = None
        cookie_path = None
        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            state_path = os.path.join(storage_path, "login_state.json")
            cookie_path = os.path.join(storage_path, "cookies.json")
        self._state_path = state_path
        self._cookie_path = cookie_path

        # Protection layers
        self._rate_limiter = RateLimiter(self._retry_config, state_path)
        self._backoff = BackoffCalculator(self._retry_config)
        self._circuit = CircuitBreaker(
            self._retry_config,
            state_callback=self._on_circuit_state_change,
            storage_path=state_path,
        )
        self._single_flight = SingleFlightLock()

        # Session
        self._session: Optional[AuthSession] = None
        self._state: AuthState = AuthState.OK
        self._last_login_time: float = 0
        self._last_login_attempt_time: float = 0
        self._last_force_relogin_time: float = 0
        self._last_login_ok_time: float = 0

        # TOTP manual input
        self._totp_pending: bool = False
        self._totp_code: Optional[str] = None

        # Restore persisted state
        self._load_state()

    # ---- Public API ----

    @property
    def state(self) -> AuthState:
        """Current :class:`AuthState` of the client."""
        return self._state

    def is_session_valid(self) -> bool:
        """Check if the session is likely valid (local heuristic only).

        Returns ``True`` if the state is ``OK``, the session object exists,
        and the cookie TTL has not elapsed. This does **not** make a network
        request. For a definitive check, use :meth:`AuthSession.validate`.
        """
        if self._state != AuthState.OK:
            return False
        if self._session is None:
            return False
        elapsed = time.monotonic() - self._last_login_time
        return elapsed <= self._cookie_ttl

    async def login(self, totp_code: Optional[str] = None) -> AuthSession:
        """Execute a fresh CAS login.

        Forces the internal state to ``EXPIRED`` so that a new login attempt
        is made, then delegates to :meth:`ensure_logged_in`, which applies
        all active protection layers (rate limiting, backoff, circuit breaker,
        single-flight lock). If a circuit is already open, the call will still
        be blocked.

        Callers should prefer :meth:`ensure_logged_in` for routine use;
        use :meth:`login` only when a fresh authentication is explicitly
        required (e.g. after credential rotation or session expiry).

        Returns:
            An authenticated :class:`AuthSession`.

        Raises:
            CircuitOpenError: Circuit breaker is open.
            LoginBackoffError: Blocked by rate limit or backoff.
            InvalidCredentialsError: Wrong username/password.
            CaptchaRequiredError: CAS demands a CAPTCHA.
            AccountLockedError: Account is locked.
            TotpRequiredError: 2FA required but not configured.
            NetworkError: Network failure.
            ParseError: CAS page structure changed.
        """
        self._transition(AuthState.EXPIRED, "login:force")
        self._last_login_time = 0

        return await self.ensure_logged_in(totp_code=totp_code)

    async def ensure_logged_in(self, totp_code: Optional[str] = None) -> AuthSession:
        """Ensure an authenticated session exists, reusing or creating as needed.

        This is the primary method for routine use. It applies all protection
        layers:

        1. **Fast path**: if state is ``OK`` and TTL is valid, return immediately.
        2. **Circuit open**: if session exists, reuse it; otherwise raise.
        3. **SUSPECT**: reuse existing session without triggering login.
        4. **Single-flight lock**: at most one concurrent login across callers.
        5. **Double-check**: re-verify state under the lock.
        6. **Backoff / rate-limit / cooldown**: enforced before real login.

        Returns:
            An authenticated :class:`AuthSession`.

        Raises:
            CircuitOpenError: Circuit breaker is open and no session exists.
            LoginBackoffError: Login blocked by backoff timer.
            NetworkError: Network failure during login.
            InvalidCredentialsError: Wrong credentials.
            CaptchaRequiredError: CAPTCHA required.
            AccountLockedError: Account locked.
            TotpRequiredError: 2FA required but not configured.
            ParseError: CAS page changed.
        """
        now = time.monotonic()

        if totp_code is not None:
            normalized = self._normalize_totp_code(totp_code)
            if normalized is None:
                raise TotpRequiredError("Provided totp_code must be a 6-digit number.")
            self._totp_code = normalized

        # Fast path
        if (
            self._state == AuthState.OK
            and self._session is not None
            and (now - self._last_login_time) <= self._cookie_ttl
        ):
            return self._session

        # Circuit open with existing session
        if self._circuit.is_open:
            if self._session is not None:
                return self._session
            raise CircuitOpenError(
                "Login temporarily disabled to protect the campus account. "
                "Please retry later.",
                retry_after=self._circuit.remaining,
            )

        # SUSPECT: reuse old session
        if self._state == AuthState.SUSPECT and self._session is not None:
            return self._session

        # Single-flight lock
        async with self._single_flight:
            # Double-check
            now2 = time.monotonic()
            if (
                self._state == AuthState.OK
                and self._session is not None
                and (now2 - self._last_login_time) <= self._cookie_ttl
            ):
                return self._session

            if self._circuit.is_open:
                if self._session is not None:
                    return self._session
                raise CircuitOpenError(
                    "Login temporarily disabled.",
                    retry_after=self._circuit.remaining,
                )

            if self._state == AuthState.SUSPECT and self._session is not None:
                return self._session

            # Backoff check
            if self._state == AuthState.LOGIN_BACKOFF:
                if self._session is not None:
                    return self._session
                raise LoginBackoffError(
                    "Login is in backoff. Please retry later.",
                )

            # Rate limit check
            if not self._rate_limiter.check():
                if self._session is not None:
                    return self._session
                raise LoginBackoffError(
                    "Login rate limit exceeded. Please retry later."
                )

            # Cooldown check
            since_last = now2 - self._last_login_attempt_time
            if self._last_login_attempt_time > 0 and since_last < self._login_min_interval:
                if self._session is not None:
                    return self._session
                raise LoginBackoffError(
                    f"Login cooldown active ({int(self._login_min_interval - since_last)}s remaining)."
                )

            # Execute login
            return await self._do_login_with_protections()

    def submit_totp(self, code: str) -> bool:
        """Submit a TOTP code during manual 2FA mode.

        Call this after :class:`TotpRequiredError` indicates manual TOTP input
        is required (e.g. from a user prompt).

        Args:
            code: The 6-digit TOTP code.

        Returns:
            ``True`` if the code was accepted (login is pending).
        """
        if not self._totp_pending:
            return False
        normalized = self._normalize_totp_code(code)
        if normalized is None:
            logger.warning("event=totp_code_rejected reason=invalid_format")
            return False
        self._totp_code = normalized
        logger.info("event=totp_code_submitted")
        return True

    @property
    def totp_pending(self) -> bool:
        """``True`` if the client is waiting for a manual TOTP code."""
        return self._totp_pending

    # ---- Lifecycle ----

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        if self._session:
            await self._session.close()
            self._session = None

    # ---- State management ----

    def _transition(self, new_state: AuthState, reason: str) -> None:
        old = self._state
        if old == new_state:
            return
        self._state = new_state
        logger.info(
            "event=auth_state_change old_state=%s new_state=%s reason=%s",
            old.value, new_state.value, reason,
        )
        self._save_state()

    def _on_circuit_state_change(self, new_state: AuthState, reason: str) -> None:
        self._state = new_state
        logger.info(
            "event=circuit_state_change new_state=%s reason=%s",
            new_state.value, reason,
        )
        self._save_state()

    # ---- Persistence ----

    def _load_state(self) -> None:
        if not self._state_path:
            return
        try:
            with open(self._state_path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return

        self._backoff.consecutive_failures = data.get("consecutive_failures", 0)
        self._rate_limiter.from_dict(data)
        self._circuit.from_dict(data, self._backoff.consecutive_failures)
        if self._circuit.state == AuthState.CIRCUIT_OPEN:
            self._state = AuthState.CIRCUIT_OPEN
        elif self._backoff.consecutive_failures > 0:
            logger.info(
                "event=state_restored consecutive_failures=%d (circuit expired)",
                self._backoff.consecutive_failures,
            )

    def _save_state(self) -> None:
        if not self._state_path:
            return
        data = {
            "consecutive_failures": self._backoff.consecutive_failures,
        }
        data.update(self._rate_limiter.to_dict())
        data.update(self._circuit.to_dict())
        try:
            os.makedirs(os.path.dirname(self._state_path), exist_ok=True)
            with open(self._state_path, "w") as f:
                json.dump(data, f)
        except Exception:
            logger.debug("Failed to persist state", exc_info=True)

    # ---- Login execution ----

    async def _do_login_with_protections(self) -> AuthSession:
        logger.info(
            "event=login_attempt outcome=allowed state=%s consecutive_failures=%d",
            self._state.value, self._backoff.consecutive_failures,
        )
        self._last_login_attempt_time = time.monotonic()
        self._rate_limiter.record()

        try:
            session = await self._do_login()
            # Success
            self._backoff.reset()
            self._session = session
            self._transition(AuthState.OK, "login_success")
            self._last_login_time = time.monotonic()
            self._last_login_ok_time = time.monotonic()
            logger.info("event=login_result outcome=success")
            self._save_state()
            if self._cookie_path:
                session.save(self._cookie_path)
            return session
        except (TotpRequiredError, Fido2AssertionError) as e:
            self._backoff.consecutive_failures += 1
            error_type = "2fa_failed" if isinstance(e, TotpRequiredError) else "fido2_failed"
            self._transition(AuthState.LOGIN_BACKOFF, error_type)
            if self._backoff.consecutive_failures >= self._retry_config.max_consecutive_failures:
                self._circuit.open(
                    self._retry_config.circuit_normal_duration,
                    f"consecutive_failures={self._backoff.consecutive_failures}",
                )
            self._save_state()
            raise
        except Fido2NotConfiguredError as e:
            self._backoff.consecutive_failures += 1
            logger.error("event=login_result outcome=failure type=fido2_not_configured error=%s", e)
            self._circuit.open(
                self._retry_config.circuit_critical_duration, str(e),
            )
            self._save_state()
            raise
        except (
            AccountLockedError,
            CaptchaRequiredError,
            InvalidCredentialsError,
        ) as e:
            self._backoff.consecutive_failures += 1
            duration = self._retry_config.circuit_normal_duration
            if isinstance(e, AccountLockedError):
                duration = self._retry_config.circuit_critical_duration
            elif isinstance(e, CaptchaRequiredError):
                duration = self._retry_config.circuit_captcha_duration
            elif isinstance(e, InvalidCredentialsError):
                duration = self._retry_config.circuit_password_error_duration
            logger.error("event=login_result outcome=failure type=critical error=%s", e)
            self._circuit.open(duration, str(e))
            self._save_state()
            raise
        except Exception:
            self._backoff.consecutive_failures += 1
            backoff_secs = self._backoff.compute(is_critical=False)
            self._transition(AuthState.LOGIN_BACKOFF, f"login_failed")
            logger.error(
                "event=login_result outcome=failure type=normal backoff=%.1fs failures=%d",
                backoff_secs, self._backoff.consecutive_failures,
            )
            if self._backoff.consecutive_failures >= self._retry_config.max_consecutive_failures:
                self._circuit.open(
                    self._retry_config.circuit_normal_duration,
                    f"consecutive_failures={self._backoff.consecutive_failures}",
                )
            self._save_state()
            raise

    async def _do_login(self) -> AuthSession:
        """Execute the full CAS login flow (password or FIDO2)."""
        logger.info(
            "event=login_start target=%s method=%s",
            self.target_service, self._auth_method,
        )

        if self._session:
            await self._session.close()
            self._session = None

        client = create_http_client(
            timeout=self._http_timeout,
            connect_timeout=self._http_connect_timeout,
        )

        try:
            # Step 1: Fetch login page
            service_url = (
                f"{self.target_service}/.auth/login/cas/callback"
                f"?return_to={self.target_service}/"
            )
            encoded_service = quote(service_url, safe="")
            login_url = (
                f"{self.auth_server}/authserver/login"
                f"?service={encoded_service}"
            )

            resp = await retry_request(client, "GET", login_url, follow_redirects=False)

            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                logger.info("Existing TGC detected, following redirect")
                await self._handle_login_redirect(client, location)
                return AuthSession(
                    _client=client,
                    target_service=self.target_service,
                    auth_server=self.auth_server,
                )

            execution, salt = parse_login_form(resp.text)
            logger.info("Parsed form: salt=%s**** execution=%s...", salt[:4], execution[:20])

            # Step 2: Try FIDO2 if configured
            if self._auth_method in ("fido2", "auto") and self._fido2_auth is not None:
                fido2_result = await self._try_fido2_path(client, login_url, execution)
                if fido2_result is not None:
                    return fido2_result
                # fido2 mode: failure is fatal
                if self._auth_method == "fido2":
                    raise Fido2AssertionError("FIDO2 login failed")

            # Step 3: Password login (default, or fallback in "auto" mode)
            encrypted_pwd = encrypt_password(self.password, salt)

            login_data = {
                "username": self.username,
                "password": encrypted_pwd,
                "captcha": "",
                "rememberMe": "true",
                "_eventId": "submit",
                "cllt": "userNameLogin",
                "lt": "",
                "execution": execution,
            }

            resp = await retry_request(
                client, "POST", login_url, data=login_data, follow_redirects=False,
            )

            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                logger.info("Login form submitted, following redirect")
                await self._handle_login_redirect(client, location)
            else:
                self._classify_and_raise(resp)

            # Post-login session validation
            await self._validate_session(client)

            logger.info("Login complete, session ready")
            return AuthSession(
                _client=client,
                target_service=self.target_service,
                auth_server=self.auth_server,
            )

        except AuthError:
            try:
                await client.aclose()
            except Exception:
                pass
            raise
        except RETRIABLE_NET_ERRORS as e:
            try:
                await client.aclose()
            except Exception:
                pass
            raise NetworkError(str(e)) from e
        except Exception:
            try:
                await client.aclose()
            except Exception:
                pass
            raise

    async def _try_fido2_path(
        self,
        client: httpx.AsyncClient,
        login_url: str,
        execution: str,
    ) -> Optional[AuthSession]:
        """Attempt FIDO2 login. Returns a session on success, None on failure.

        FIDO2 login is a two-step process:
        1. Complete passkey authentication on the no-service login page to
           obtain a TGC (Ticket Granting Cookie).
        2. Present the TGC to the service-parameter login URL to obtain a
           service ticket (ST) and follow the redirect chain to the target.

        The *execution* parameter from the service-context login page is NOT
        used; the FIDO2 authenticator fetches its own execution from the
        no-service page.

        Raises:
            Fido2NotConfiguredError: If no FIDO2 authenticator is available
                and the auth method is ``"fido2"``.
            Fido2AssertionError: If any FIDO2 stage fails.
        """
        if self._fido2_auth is None:
            if self._auth_method == "fido2":
                raise Fido2NotConfiguredError(
                    "FIDO2 login requested but no valid credential is configured"
                )
            return None

        logger.info("event=fido2_attempt")

        # Step 1: FIDO2 passkey assertion on the no-service login page.
        # The server's FIDO form action is /authserver/login (no ?service=).
        # We must use an execution token from the same no-service context,
        # so we let the authenticator fetch its own login page rather than
        # passing the execution from the outer service-context page.
        try:
            resp = await self._fido2_auth.authenticate(
                client, execution=None
            )
        except (Fido2NotConfiguredError, Fido2AssertionError):
            if self._auth_method == "auto":
                logger.info(
                    "event=fido2_fallback reason=FIDO2 failed, falling back to password"
                )
                return None
            raise
        except AuthError:
            if self._auth_method == "auto":
                logger.info(
                    "event=fido2_fallback "
                    "reason=FIDO2 auth error, falling back to password"
                )
                return None
            raise
        except Exception as e:
            if self._auth_method == "auto":
                logger.info(
                    "event=fido2_fallback reason=%s, falling back to password", e
                )
                return None
            raise Fido2AssertionError(
                f"FIDO2 authentication failed: {e}"
            ) from e

        if resp.status_code not in (301, 302, 307, 308):
            err_text = (
                extract_error_text(resp.text) if hasattr(resp, "text") else None
            )
            msg = (
                "FIDO2 assertion rejected by AuthServer"
                + (f": {err_text}" if err_text else "")
            )
            if self._auth_method == "auto":
                logger.info(
                    "event=fido2_fallback reason=%s, falling back to password", msg
                )
                return None
            raise Fido2AssertionError(msg)

        # Follow the TGC redirect chain (no service ticket yet).
        location = resp.headers.get("location", "")
        logger.info("FIDO2 assertion accepted, following TGC redirect")
        await self._follow_cas_redirect(client, location)

        # Step 2: Present the TGC to the service-parameter login URL to
        # obtain a service ticket and follow the redirect to the target.
        logger.info("FIDO2 step 2: requesting ST via service URL")
        resp = await retry_request(
            client, "GET", login_url, follow_redirects=False,
        )
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            await self._handle_login_redirect(client, location)
        else:
            msg = (
                f"FIDO2 service-ticket request failed (status {resp.status_code})"
            )
            if self._auth_method == "auto":
                logger.info(
                    "event=fido2_fallback reason=%s, falling back to password", msg
                )
                return None
            raise Fido2AssertionError(msg)

        await self._validate_session(client)

        logger.info("FIDO2 login complete, session ready")
        return AuthSession(
            _client=client,
            target_service=self.target_service,
            auth_server=self.auth_server,
        )

    # ---- Redirect following ----

    async def _handle_login_redirect(
        self, client: httpx.AsyncClient, location: str
    ) -> None:
        """Follow redirect chain after login, detect and complete 2FA if needed."""
        final_url, _ = await self._follow_cas_redirect(client, location)

        # Check for 2FA redirect
        if _RE_AUTH_VIEW.search(final_url):
            logger.info("event=2fa_detected url=%s", final_url[:80])
            parsed = urlparse(final_url)
            params = parse_qs(parsed.query)
            service_url = params.get("service", [None])[0] or quote(
                f"{self.target_service}/.auth/login/cas/callback"
                f"?return_to={self.target_service}/"
            )
            await self._complete_2fa(client, service_url)

    async def _follow_cas_redirect(
        self, client: httpx.AsyncClient, location: str, max_redirects: int = 10
    ) -> Tuple[str, Optional[httpx.Response]]:
        """Follow a redirect chain. Returns ``(final_url, last_response)``."""
        current_url = location
        last_resp: Optional[httpx.Response] = None
        for i in range(max_redirects):
            if not current_url:
                break
            logger.debug("Following redirect [%d/%d]: %s...", i + 1, max_redirects, current_url[:80])
            last_resp = await retry_request(
                client, "GET", current_url, follow_redirects=False,
            )
            if last_resp.status_code in (301, 302, 307, 308):
                current_url = last_resp.headers.get("location", "")
                if current_url and not current_url.startswith("http"):
                    current_url = urljoin(str(last_resp.url), current_url)
            else:
                break
        return (str(last_resp.url) if last_resp else location, last_resp)

    # ---- 2FA / TOTP ----

    async def _complete_2fa(
        self, client: httpx.AsyncClient, service_url: str
    ) -> None:
        """Complete the TOTP-based 2FA flow."""
        logger.info("event=2fa_start service=%s", service_url[:60])

        # Step 1: Switch to security token (reAuthType=10)
        change_body = {
            "isMultifactor": "true",
            "reAuthType": "10",
            "service": service_url,
        }
        change_resp = await retry_request(
            client,
            "POST",
            f"{self.auth_server}/authserver/reAuthCheck/changeReAuthType.do",
            data=change_body,
            headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
        )
        if change_resp.status_code != 200:
            raise AuthError(f"2FA switch failed: HTTP {change_resp.status_code}")
        try:
            change_data = change_resp.json()
        except Exception:
            change_data = {}
        if change_data.get("code") != "1":
            raise AuthError(
                f"2FA switch rejected: {change_data.get('message', change_resp.text[:200])}"
            )
        logger.info(
            "event=2fa_switch reAuthType=10 name=%s",
            change_data.get("data", {}).get("reAuthTypeName", "?"),
        )

        # Step 2: Obtain TOTP code
        otp_code = await self._resolve_totp_code()

        if not otp_code:
            raise TotpRequiredError("Failed to obtain TOTP code.")

        # Step 3: Submit 2FA
        await self._submit_2fa(client, service_url, otp_code)
        # Follow redirect back to target
        await self._follow_cas_redirect(client, service_url)
        logger.info("event=2fa_complete")

    async def _submit_2fa(
        self, client: httpx.AsyncClient, service_url: str, otp_code: str
    ) -> None:
        submit_body = {
            "service": service_url,
            "reAuthType": "10",
            "isMultifactor": "true",
            "password": "",
            "dynamicCode": "",
            "uuid": "",
            "answer1": "",
            "answer2": "",
            "otpCode": otp_code,
            "skipTmpReAuth": "true",
        }
        submit_resp = await retry_request(
            client,
            "POST",
            f"{self.auth_server}/authserver/reAuthCheck/reAuthSubmit.do",
            data=submit_body,
            headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
        )
        if submit_resp.status_code != 200:
            raise AuthError(f"2FA submit failed: HTTP {submit_resp.status_code}")

        submit_data = {}
        try:
            submit_data = submit_resp.json()
        except Exception:
            pass

        if submit_data.get("code") != "reAuth_success":
            msg = submit_data.get("msg", submit_resp.text[:200])
            # Auto-retry with next window
            if "code" in msg.lower() or "fail" in msg.lower() or "error" in msg.lower():
                logger.warning("event=2fa_retry reason=code_rejected msg=%s", msg)
                await _wait_for_next_totp_window()
                await _wait_for_stable_totp_window()
                secret = self._normalize_totp_secret(self.totp_secret) if self.totp_secret else ""
                if secret:
                    new_code = pyotp.TOTP(secret).now()
                    submit_body["otpCode"] = new_code
                    logger.info("event=2fa_retry new_code=%s****", new_code[:2])
                    retry_resp = await retry_request(
                        client,
                        "POST",
                        f"{self.auth_server}/authserver/reAuthCheck/reAuthSubmit.do",
                        data=submit_body,
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
                        },
                    )
                    try:
                        retry_data = retry_resp.json()
                    except Exception:
                        retry_data = {}
                    if retry_data.get("code") == "reAuth_success":
                        logger.info("event=2fa_success_after_retry")
                        return
                    msg = retry_data.get("msg", retry_resp.text[:200])
            raise TotpRequiredError(f"2FA verification failed: {msg}")

        logger.info("event=2fa_success")

    async def _resolve_totp_code(self) -> str:
        """Resolve TOTP code from provider, secret, or manual submission."""
        if self._totp_provider is not None:
            code = self._normalize_totp_code(self._totp_provider())
            if code is None:
                raise TotpRequiredError("totp_provider returned an invalid code format.")
            return code

        if self.totp_secret:
            secret = self._normalize_totp_secret(self.totp_secret)
            totp = pyotp.TOTP(secret)
            await _wait_for_stable_totp_window()
            otp_code = totp.now()
            normalized = self._normalize_totp_code(otp_code)
            if normalized is None:
                raise TotpRequiredError("Generated TOTP code has invalid format.")
            logger.info(
                "event=2fa_totp_generated code=%s**** window_remaining=%ds",
                otp_code[:2],
                _totp_window_remaining_seconds(),
            )
            return normalized

        if self._totp_code is not None:
            code = self._totp_code
            self._totp_code = None
            self._totp_pending = False
            return code

        self._totp_pending = True
        raise TotpRequiredError(
            "TOTP 2FA is required. Prefer configuring totp_secret or totp_provider; "
            "or call submit_totp(code) and retry login()."
        )

    @staticmethod
    def _normalize_totp_code(code: str) -> Optional[str]:
        normalized = code.strip()
        if not re.fullmatch(r"\d{6}", normalized):
            return None
        return normalized

    @staticmethod
    def _normalize_totp_secret(raw: str) -> str:
        """Normalize TOTP secret from various formats."""
        secret = raw.strip()
        if secret.startswith("otpauth://"):
            parsed = urlparse(secret)
            params = parse_qs(parsed.query)
            secret = params.get("secret", [secret])[0]
        return re.sub(r"\s+", "", secret)

    # ---- Validation ----

    async def _validate_session(self, client: httpx.AsyncClient) -> None:
        """Verify the session is actually usable by probing the target service."""
        try:
            target_host = urlparse(self.target_service).hostname or ""
            probe_url = urljoin(self.target_service, "/api/config")
            resp = await client.head(
                probe_url,
                headers={"Host": target_host},
                follow_redirects=False,
            )
            if resp.status_code in (301, 302, 307):
                location = resp.headers.get("location", "")
                if _is_cas_login_url(location, self.auth_server):
                    raise SessionExpiredError(
                        f"Session validation failed: redirected to CAS login at {location[:80]}"
                    )
            logger.info("event=session_validated status=%d", resp.status_code)
        except RETRIABLE_NET_ERRORS as e:
            logger.warning("event=session_validation_skipped reason=network_error error=%s", e)
        except SessionExpiredError:
            raise

    # ---- Failure classification ----

    def _classify_and_raise(self, resp: httpx.Response) -> None:
        """Analyse a failed login response and raise the appropriate exception."""
        html_text = ""

        # Try JSON response first
        try:
            data = resp.json()
            code = data.get("resultCode", "")
            if code == "LOCK":
                raise AccountLockedError(
                    "Account is locked. Please unlock manually and retry."
                )
            if code == "CAPTCHA_NOTMATCH":
                raise CaptchaRequiredError(
                    "CAPTCHA required — account may be temporarily restricted."
                )
            if code == "FAIL_UPNOTMATCH":
                raise InvalidCredentialsError(
                    "Wrong password or account does not exist. Please check credentials."
                )
            if code:
                raise AuthError(f"AuthServer error: {code}")
        except (AccountLockedError, CaptchaRequiredError, InvalidCredentialsError):
            raise
        except AuthError:
            raise
        except Exception:
            html_text = resp.text[:2000]

        # Inspect HTML
        if html_text:
            if "锁定" in html_text or "LOCK" in html_text:
                raise AccountLockedError("Account may be locked — please check manually.")
            if "频繁" in html_text or "操作过于频繁" in html_text:
                raise CaptchaRequiredError(
                    "CAS indicates too many requests — account may be temporarily restricted."
                )
            if "验证码" in html_text or "captcha" in html_text.lower():
                raise CaptchaRequiredError(
                    "CAPTCHA required — account may be temporarily restricted."
                )
            if "维护" in html_text or "maintenance" in html_text.lower():
                raise AuthError("CAS system may be under maintenance.")

        err_text = extract_error_text(html_text) if html_text else None
        if err_text:
            raise AuthError(f"AuthServer login failed: {err_text}")

        raise AuthError("AuthServer login failed: unknown error.")


# ---- TOTP window helpers ----

def _totp_window_remaining_seconds() -> int:
    return 30 - (int(time.time()) % 30)


async def _wait_for_stable_totp_window() -> None:
    remaining = _totp_window_remaining_seconds()
    if remaining <= 3:
        await asyncio.sleep(remaining + 1)


async def _wait_for_next_totp_window() -> None:
    await asyncio.sleep(_totp_window_remaining_seconds() + 1)
