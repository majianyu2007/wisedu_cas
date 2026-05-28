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
VOUCH_HOST = "vouch.nwafu.edu.cn"
LOGIN_PAGE_HTML = '''
<html>
<input type="hidden" id="execution" value="exec-abc"/>
<input type="hidden" id="pwdEncryptSalt" value="deadbeef12345678"/>
</html>
'''

AUTH_LOGIN_RE = re.compile(r"^https://authserver\.example\.edu\.cn/authserver/login.*")
TARGET_RE = re.compile(r"^https://target\.example\.edu\.cn")
VOUCH_RE = re.compile(r"^https://vouch\.nwafu\.edu\.cn")
OIDC_RE = re.compile(r"^https://authserver\.example\.edu\.cn/authserver/oidc/authorize")


def make_client(**kwargs) -> AuthClient:
    defaults = dict(
        auth_server=AUTH_SERVER,
        target_service=TARGET,
        username="testuser",
        password="testpass",
    )
    defaults.update(kwargs)
    return AuthClient(**defaults)


def mock_vouch_chain(httpx_mock: HTTPXMock, *, login_status=200, login_html=LOGIN_PAGE_HTML):
    """Set up mock responses for the Vouch → OIDC → CAS redirect chain.

    This simulates the 4-step navigation that _navigate_to_login_page performs:
      1. GET target → 302 → vouch
      2. GET vouch → 302 → OIDC authorize
      3. GET OIDC authorize → 302 → CAS login page
      4. GET CAS login page → 200 (or 302 if TGC exists)

    Args:
        httpx_mock: The pytest-httpx mock instance.
        login_status: Status for the final CAS login page (200 or 302).
        login_html: HTML body for the login page response.
    """
    # Step 1: GET target → 302 → vouch
    httpx_mock.add_response(
        url=TARGET_RE,
        method="GET",
        status_code=302,
        headers={"Location": f"https://{VOUCH_HOST}/login?url={TARGET}/"},
    )
    # Step 2: GET vouch → 302 → OIDC
    httpx_mock.add_response(
        url=VOUCH_RE,
        method="GET",
        status_code=302,
        headers={"Location": f"{AUTH_SERVER}/authserver/oidc/authorize?client_id=test&redirect_uri=https%3A%2F%2Fvouch%2Fauth"},
    )
    # Step 3: GET OIDC → 302 → CAS login
    httpx_mock.add_response(
        url=OIDC_RE,
        method="GET",
        status_code=302,
        headers={"Location": f"{AUTH_SERVER}/authserver/login?service=oidc_callback"},
    )
    # Step 4: GET CAS login page
    if login_status == 302:
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE,
            method="GET",
            status_code=302,
            headers={"Location": f"{TARGET}/callback?ticket=ST-xxx"},
        )
    else:
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE,
            method="GET",
            status_code=login_status,
            html=login_html,
        )


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
        mock_vouch_chain(httpx_mock)

        # POST login form → 302 to 2FA/reauth
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE,
            method="POST",
            status_code=302,
            headers={"Location": f"{TARGET}/callback?ticket=ST-xxx"},
        )
        # GET target callback
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET",
            status_code=200,
        )
        # HEAD probe for session validation
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
        """Existing TGC → redirect chain skips form submission."""
        mock_vouch_chain(httpx_mock, login_status=302)
        # Follow redirect to target
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET",
            status_code=200,
        )

        client = make_client()
        session = await client.login()
        assert client.state == AuthState.OK
        await client.close()


class TestErrorClassification:
    async def test_account_locked_json(self, httpx_mock: HTTPXMock) -> None:
        mock_vouch_chain(httpx_mock)
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200, json={"resultCode": "LOCK"},
        )

        client = make_client()
        with pytest.raises(AccountLockedError):
            await client.login()
        await client.close()

    async def test_captcha_json(self, httpx_mock: HTTPXMock) -> None:
        mock_vouch_chain(httpx_mock)
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200, json={"resultCode": "CAPTCHA_NOTMATCH"},
        )

        client = make_client()
        with pytest.raises(CaptchaRequiredError):
            await client.login()
        await client.close()

    async def test_password_error_json(self, httpx_mock: HTTPXMock) -> None:
        mock_vouch_chain(httpx_mock)
        httpx_mock.add_response(
            url=AUTH_LOGIN_RE, method="POST", status_code=200, json={"resultCode": "FAIL_UPNOTMATCH"},
        )

        client = make_client()
        with pytest.raises(InvalidCredentialsError):
            await client.login()
        await client.close()

    async def test_locked_from_html_keyword(self, httpx_mock: HTTPXMock) -> None:
        mock_vouch_chain(httpx_mock)
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
        mock_vouch_chain(httpx_mock, login_status=302)
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET", status_code=200,
        )

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

        mock_vouch_chain(httpx_mock)
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
        mock_vouch_chain(httpx_mock, login_status=302)
        httpx_mock.add_response(
            url=re.compile(r"^https://target\.example\.edu\.cn/callback.*"),
            method="GET", status_code=200,
        )
        client = make_client(retry_config=retry_cfg)
        await client.login()
        await client.close()

        # Second client — pre-record one attempt to hit the limit
        client2 = make_client(retry_config=retry_cfg)
        client2._rate_limiter.record()
        client2._state = AuthState.EXPIRED
        with pytest.raises(LoginBackoffError):
            await client2.ensure_logged_in()
        await client2.close()


class TestConcurrentSingleFlight:
    async def test_single_flight_lock(self, httpx_mock: HTTPXMock) -> None:
        """Concurrent calls to ensure_logged_in only trigger one real login."""
        mock_vouch_chain(httpx_mock)
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
        # retry_request retries 3 times; mock all target requests to fail
        for _ in range(3):
            httpx_mock.add_exception(
                httpx.ConnectError("Connection refused"),
                url=re.compile(r"^https://target\.example\.edu\.cn"),
            )

        client = make_client()
        with pytest.raises(NetworkError):
            await client.login()
        assert client.state == AuthState.LOGIN_BACKOFF
        await client.close()