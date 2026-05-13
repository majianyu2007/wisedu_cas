"""Tests for AuthClient core flows — login, 2FA, error classification, state machine."""

import asyncio
import re

import httpx
import pytest
from pytest_httpx import HTTPXMock

from wisedu_cas import (
    AccountLockedError,
    AuthClient,
    AuthSession,
    AuthState,
    CaptchaRequiredError,
    CircuitOpenError,
    InvalidCredentialsError,
    LoginBackoffError,
    NetworkError,
    TotpRequiredError,
)

AUTH_SERVER = "https://authserver.example.edu.cn"
TARGET = "https://target.example.edu.cn"
LOGIN_PAGE_HTML = '''
<html>
<input type="hidden" id="execution" value="exec-abc"/>
<input type="hidden" id="pwdEncryptSalt" value="deadbeef12345678"/>
</html>
'''

AUTH_LOGIN_RE = re.compile(r"^https://authserver\.example\.edu\.cn/authserver/login.*")


def make_client(**kwargs) -> AuthClient:
    defaults = dict(
        auth_server=AUTH_SERVER,
        target_service=TARGET,
        username="testuser",
        password="testpass",
    )
    defaults.update(kwargs)
    return AuthClient(**defaults)


class TestAuthClientConstruction:
    def test_minimal_construction(self) -> None:
        client = make_client()
        assert client.auth_server == AUTH_SERVER
        assert client.target_service == TARGET
        assert client.username == "testuser"
        assert client.state == AuthState.OK

    def test_state_initial_ok(self) -> None:
        client = make_client()
        assert client.state == AuthState.OK
        assert client.is_session_valid() is False  # no session yet


class TestIsSessionValid:
    async def test_no_session_yet(self) -> None:
        client = make_client()
        assert client.is_session_valid() is False

    async def test_not_ok_state(self) -> None:
        client = make_client()
        client._state = AuthState.SUSPECT
        assert client.is_session_valid() is False


class TestLoginSuccess:
    async def test_full_password_login_flow(self, httpx_mock: HTTPXMock) -> None:
        """End-to-end successful password login without 2FA."""
        # Step 1: GET login page
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE,
            method="GET",
            status_code=200,
            html=LOGIN_PAGE_HTML,
        )
        # Step 2: POST login form → 302 to TGC-reuse URL
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE,
            method="POST",
            status_code=302,
            headers={
                "Location": f"{AUTH_SERVER}/authserver/login?service=callback"
            },
        )
        # Step 3: GET TGC-reuse redirect → 302 to target callback with ticket
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE,
            method="GET",
            status_code=302,
            headers={"Location": f"{TARGET}/.auth/login/cas/callback?ticket=ST-xxx"},
        )
        # Step 4: GET target callback with ticket
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/\.auth/login/cas/callback.*"),
            method="GET",
            status_code=200,
        )
        # Step 5: HEAD probe for session validation
        httpx_mock.add_response(
            url=f"{TARGET}/api/config",
            method="HEAD",
            status_code=200,
        )

        client = make_client()
        session = await client.login()

        assert isinstance(session, AuthSession)
        assert client.state == AuthState.OK
        assert client.is_session_valid() is True
        await client.close()

    async def test_tgc_reuse_flow(self, httpx_mock: HTTPXMock) -> None:
        """Existing TGC → redirect to callback without form submission."""
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE,
            method="GET",
            status_code=302,
            headers={"Location": f"{TARGET}/callback?ticket=ST-xxx"},
        )
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET",
            status_code=200,
        )
        # TGC reuse path returns early before _validate_session — no HEAD needed

        client = make_client()
        session = await client.login()
        assert client.state == AuthState.OK
        await client.close()


class TestErrorClassification:
    async def test_account_locked_json(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML,
        )
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200, json={"resultCode": "LOCK"},
        )

        client = make_client()
        with pytest.raises(AccountLockedError):
            await client.login()
        await client.close()

    async def test_captcha_json(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML,
        )
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200, json={"resultCode": "CAPTCHA_NOTMATCH"},
        )

        client = make_client()
        with pytest.raises(CaptchaRequiredError):
            await client.login()
        await client.close()

    async def test_password_error_json(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML,
        )
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200, json={"resultCode": "FAIL_UPNOTMATCH"},
        )

        client = make_client()
        with pytest.raises(InvalidCredentialsError):
            await client.login()
        await client.close()

    async def test_locked_from_html_keyword(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML,
        )
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200,
            html="<html>您的账户已被锁定</html>",
        )

        client = make_client()
        with pytest.raises(AccountLockedError):
            await client.login()
        await client.close()


class TestEnsureLoggedInFastPath:
    async def test_returns_session_when_ok(self, httpx_mock: HTTPXMock) -> None:
        """ensure_logged_in returns immediately when state=OK and TTL valid."""
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=302,
            headers={"Location": f"{TARGET}/callback?ticket=ST-xxx"},
        )
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET", status_code=200,
        )
        # TGC reuse path skips _validate_session; no HEAD needed

        client = make_client()
        session1 = await client.login()
        session2 = await client.ensure_logged_in()
        assert session2 is session1
        await client.close()


class TestCircuitBreakerIntegration:
    async def test_circuit_opens_after_consecutive_failures(self, httpx_mock: HTTPXMock) -> None:
        """2 consecutive password errors → CIRCUIT_OPEN."""
        from wisedu_cas.retry import RetryConfig

        retry_cfg = RetryConfig(
            max_consecutive_failures=2,
            circuit_password_error_duration=1,
        )

        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML,
        )
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200,
            json={"resultCode": "FAIL_UPNOTMATCH"},
        )

        client = make_client(retry_config=retry_cfg)

        with pytest.raises(InvalidCredentialsError):
            await client.login()

        assert client.state == AuthState.CIRCUIT_OPEN
        await client.close()


class TestRateLimit:
    async def test_rate_limit_blocks_excessive_logins(self, httpx_mock: HTTPXMock) -> None:
        """After max_logins_per_hour, ensure_logged_in raises LoginBackoffError."""
        from wisedu_cas.retry import RetryConfig

        retry_cfg = RetryConfig(max_logins_per_hour=1, login_window_seconds=3600)

        # First login succeeds
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=302,
            headers={"Location": f"{TARGET}/callback?ticket=ST-1"},
        )
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET", status_code=200,
        )
        client = make_client(retry_config=retry_cfg)
        await client.login()
        await client.close()

        # Second client — already has rate limit recorded, but it's in-memory only.
        # Actually rate limiter state is in-memory per-instance. Let's use same client.
        client2 = make_client(retry_config=retry_cfg)
        # Pre-record one attempt to hit the limit
        client2._rate_limiter.record()
        client2._state = AuthState.EXPIRED
        with pytest.raises(LoginBackoffError):
            await client2.ensure_logged_in()
        await client2.close()


class TestConcurrentSingleFlight:
    async def test_single_flight_lock(self, httpx_mock: HTTPXMock) -> None:
        """Concurrent calls to ensure_logged_in only trigger one real login."""
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML,
        )
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=302,
            headers={"Location": f"{TARGET}/callback?ticket=ST-xxx"},
        )
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET", status_code=200,
        )
        httpx_mock.add_response(
            url=f"{TARGET}/api/config", method="HEAD", status_code=200,
        )

        client = make_client()
        client._state = AuthState.EXPIRED

        results = []

        async def do_login():
            session = await client.ensure_logged_in()
            results.append(session)

        await asyncio.gather(do_login(), do_login(), do_login())
        assert len(results) == 3
        # All sessions should be the same object (single-flight)
        assert results[0] is results[1] is results[2]
        await client.close()


class TestStateTransitions:
    async def test_network_error_to_backoff(self, httpx_mock: HTTPXMock) -> None:
        """Network error during login → LOGIN_BACKOFF state."""
        # retry_request retries 3 times; need exception mock for each attempt
        for _ in range(3):
            httpx_mock.add_exception(
                httpx.ConnectError("Connection refused"),
                url=AUTH_LOGIN_RE,
                method="GET",
            )

        client = make_client()
        with pytest.raises(NetworkError):
            await client.login()
        assert client.state == AuthState.LOGIN_BACKOFF
        await client.close()
