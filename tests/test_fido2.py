"""Tests for FIDO2/WebAuthn passkey authentication."""

import base64
import json
import re

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from pytest_httpx import HTTPXMock

from wisedu_cas import (
    AuthClient,
    AuthSession,
    AuthState,
    Fido2Credential,
    Fido2Authenticator,
    Fido2AssertionError,
    Fido2NotConfiguredError,
)

AUTH_SERVER = "https://authserver.example.edu.cn"
TARGET = "https://target.example.edu.cn"
LOGIN_PAGE_HTML = '''
<html>
<input type="hidden" id="execution" name="execution" value="exec-fido"/>
<input type="hidden" id="pwdEncryptSalt" name="pwdEncryptSalt" value="deadbeef12345678"/>
</html>
'''

AUTH_LOGIN_RE = re.compile(r"^https://authserver\.example\.edu\.cn/authserver/login.*")


# ---- Test helpers ----

def _generate_test_credential() -> Fido2Credential:
    """Generate a throw-away ECDSA P-256 key pair for testing."""
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return Fido2Credential(
        credential_id="a99118bb1234567890abcdef1234567890abcdef",
        key_value=base64.b64encode(der).decode(),
        rp_id="authserver.example.edu.cn",
        user_handle="test-user-handle",
        device_binding_id="device-binding-uuid",
    )


_TEST_CRED = _generate_test_credential()


def _start_assertion_json():
    return {
        "result": {
            "success": True,
            "request": {
                "requestId": "req-123",
                "username": "test-user",
                "publicKeyCredentialRequestOptions": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2UtYWJjZGVm",
                    "rpId": "authserver.example.edu.cn",
                    "allowCredentials": [],
                    "userVerification": "required",
                    "extensions": {},
                },
            },
        }
    }


# ---- Credential model tests ----

class TestFido2Credential:
    def test_from_dict(self) -> None:
        data = {
            "credentialId": "abc-123",
            "keyValue": "MII...",
            "rpId": "auth.example.com",
            "userHandle": "user-x",
            "deviceBindingId": "dev-y",
        }
        cred = Fido2Credential.from_dict(data)
        assert cred.credential_id == "abc-123"
        assert cred.key_value == "MII..."
        assert cred.rp_id == "auth.example.com"
        assert cred.user_handle == "user-x"
        assert cred.device_binding_id == "dev-y"

    def test_is_valid_true(self) -> None:
        assert _TEST_CRED.is_valid() is True

    def test_is_valid_false_when_missing(self) -> None:
        cred = Fido2Credential("", "", "")
        assert cred.is_valid() is False
        cred2 = Fido2Credential("id", "key", "")
        assert cred2.is_valid() is False


# ---- Assertion building tests ----

class TestBuildAssertion:
    def test_build_succeeds(self) -> None:
        from wisedu_cas.fido2 import build_webauthn_assertion

        assertion = build_webauthn_assertion(
            _TEST_CRED, "ZmFrZSBjaGFsbGVuZ2UgZm9yIHRlc3Rpbmc", AUTH_SERVER,
        )
        assert assertion["type"] == "public-key"
        assert "id" in assertion
        assert "response" in assertion
        resp = assertion["response"]
        assert "authenticatorData" in resp
        assert "clientDataJSON" in resp
        assert "signature" in resp

    def test_build_fails_with_invalid_credential(self) -> None:
        from wisedu_cas.fido2 import build_webauthn_assertion

        cred = Fido2Credential("", "", "")
        with pytest.raises(Fido2AssertionError):
            build_webauthn_assertion(cred, "challenge", AUTH_SERVER)

    def test_build_fails_with_bad_key(self) -> None:
        from wisedu_cas.fido2 import build_webauthn_assertion

        cred = Fido2Credential("abc123", "not-a-valid-key", "rp.example.com")
        with pytest.raises(Fido2AssertionError):
            build_webauthn_assertion(cred, "challenge", AUTH_SERVER)


# ---- startAssertion + parse tests ----

class TestStartAssertion:
    async def test_success(self, httpx_mock: HTTPXMock) -> None:
        from wisedu_cas.fido2 import start_assertion

        httpx_mock.add_response(
            url=re.compile(r".*/startAssertion$"),
            method="POST",
            json=_start_assertion_json(),
        )
        client = httpx.AsyncClient()
        result = await start_assertion(client, AUTH_SERVER, "testuser", "device-binding-id")
        assert result["success"] is True
        await client.aclose()

    async def test_server_rejects(self, httpx_mock: HTTPXMock) -> None:
        from wisedu_cas.fido2 import start_assertion

        httpx_mock.add_response(
            url=re.compile(r".*/startAssertion$"),
            method="POST",
            json={"result": {"success": False, "message": "No such device"}},
        )
        client = httpx.AsyncClient()
        with pytest.raises(Fido2AssertionError, match="rejected"):
            await start_assertion(client, AUTH_SERVER, "testuser", "bad-id")
        await client.aclose()


class TestParseAssertionOptions:
    def test_success(self) -> None:
        from wisedu_cas.fido2 import parse_assertion_options

        result = _start_assertion_json()["result"]
        challenge, rp_id, request_id = parse_assertion_options(result)
        assert challenge == "dGVzdC1jaGFsbGVuZ2UtYWJjZGVm"
        assert rp_id == "authserver.example.edu.cn"
        assert request_id == "req-123"

    def test_missing_fields_raises(self) -> None:
        from wisedu_cas.fido2 import parse_assertion_options

        with pytest.raises(Fido2AssertionError):
            parse_assertion_options({})
        with pytest.raises(Fido2AssertionError):
            parse_assertion_options({"request": {}})


# ---- Fido2Authenticator full flow ----

class TestFido2AuthenticatorFlow:
    async def test_full_flow_sets_tgc(self, httpx_mock: HTTPXMock) -> None:
        """FIDO2 submission returns 302 → TGC obtained."""
        # GET login page (no header, no service param)
        httpx_mock.add_response(
            url=f"{AUTH_SERVER}/authserver/login",
            method="GET",
            status_code=200,
            html=LOGIN_PAGE_HTML,
        )
        # startAssertion
        httpx_mock.add_response(
            url=re.compile(r".*/startAssertion$"),
            method="POST",
            json=_start_assertion_json(),
        )
        # Submit assertion → 302
        httpx_mock.add_response(
            url=f"{AUTH_SERVER}/authserver/login",
            method="POST",
            status_code=302,
            headers={"Location": f"{AUTH_SERVER}/personalInfo"},
        )

        auth = Fido2Authenticator(AUTH_SERVER, "testuser", _TEST_CRED)
        client = httpx.AsyncClient()
        resp = await auth.authenticate(client)
        assert resp.status_code == 302
        await client.aclose()

    async def test_raises_when_not_configured(self) -> None:
        cred = Fido2Credential("", "", "")
        auth = Fido2Authenticator(AUTH_SERVER, "testuser", cred)
        client = httpx.AsyncClient()
        with pytest.raises(Fido2NotConfiguredError):
            await auth.authenticate(client)
        await client.aclose()


# ---- AuthClient FIDO2 integration ----

def make_client(**kwargs):
    defaults = dict(
        auth_server=AUTH_SERVER,
        target_service=TARGET,
        username="testuser",
        password="testpass",
    )
    defaults.update(kwargs)
    return AuthClient(**defaults)


class TestAuthClientFido2:
    async def test_auth_method_fido2_success(self, httpx_mock: HTTPXMock) -> None:
        """Full FIDO2 login via AuthClient."""
        httpx_mock.add_response(url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML)
        httpx_mock.add_response(
            url=re.compile(r".*/startAssertion$"),
            method="POST",
            json=_start_assertion_json(),
        )
        # FIDO2 form submission → 302
        httpx_mock.add_response(
            url=f"{AUTH_SERVER}/authserver/login",
            method="POST",
            status_code=302,
            headers={"Location": f"{TARGET}/callback?ticket=ST-xxx"},
        )
        httpx_mock.add_response(
            url=re.compile(r"^https://target.*/callback.*"),
            method="GET", status_code=200,
        )
        httpx_mock.add_response(url=f"{TARGET}/api/config", method="HEAD", status_code=200)

        client = make_client(auth_method="fido2", fido2_credential=_TEST_CRED)
        session = await client.login()
        assert isinstance(session, AuthSession)
        assert client.state == AuthState.OK
        assert client.is_session_valid()
        await client.close()

    async def test_auth_method_auto_falls_back_to_password(self, httpx_mock: HTTPXMock) -> None:
        """auto mode: FIDO2 fails → password succeeds."""
        httpx_mock.add_response(url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML)
        httpx_mock.add_response(
            url=re.compile(r".*/startAssertion$"),
            method="POST",
            json={"result": {"success": False}},
        )
        # Password form POST → 302
        httpx_mock.add_response(url=AUTH_LOGIN_RE, method="POST", status_code=302,
                                headers={"Location": f"{TARGET}/callback?ticket=ST-xxx"})
        httpx_mock.add_response(
            url=re.compile(r"^https://target.*/callback.*"),
            method="GET", status_code=200,
        )
        httpx_mock.add_response(url=f"{TARGET}/api/config", method="HEAD", status_code=200)

        client = make_client(auth_method="auto", fido2_credential=_TEST_CRED)
        session = await client.login()
        assert client.state == AuthState.OK
        await client.close()

    async def test_auth_method_fido2_raises_on_rejection(self, httpx_mock: HTTPXMock) -> None:
        """fido2 mode: assertion rejected → Fido2AssertionError."""
        httpx_mock.add_response(url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML)
        httpx_mock.add_response(
            url=re.compile(r".*/startAssertion$"),
            method="POST",
            json=_start_assertion_json(),
        )
        httpx_mock.add_response(
            url=f"{AUTH_SERVER}/authserver/login",
            method="POST",
            status_code=200,
            text="<html>Assertion rejected</html>",
        )

        client = make_client(auth_method="fido2", fido2_credential=_TEST_CRED)
        with pytest.raises(Fido2AssertionError):
            await client.login()
        await client.close()

    async def test_fido2_hits_circuit_on_consecutive_failures(self, httpx_mock: HTTPXMock) -> None:
        """FIDO2 failures feed into circuit breaker."""
        from wisedu_cas.retry import RetryConfig
        from wisedu_cas import CircuitOpenError

        retry_cfg = RetryConfig(max_consecutive_failures=2, circuit_normal_duration=1)

        # 2 failing rounds
        for _ in range(2):
            httpx_mock.add_response(url=AUTH_LOGIN_RE, method="GET", status_code=200, html=LOGIN_PAGE_HTML)
            httpx_mock.add_response(
                url=re.compile(r".*/startAssertion$"),
                method="POST",
                json=_start_assertion_json(),
            )
            httpx_mock.add_response(
                url=f"{AUTH_SERVER}/authserver/login",
                method="POST",
                status_code=200,
                text="<html>Rejected</html>",
            )

        client = make_client(
            auth_method="fido2", fido2_credential=_TEST_CRED,
            retry_config=retry_cfg, login_min_interval=0,
        )

        with pytest.raises(Fido2AssertionError):
            await client.login()
        with pytest.raises(Fido2AssertionError):
            await client.login()
        with pytest.raises(CircuitOpenError):
            await client.login()
        await client.close()
