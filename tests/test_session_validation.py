"""Tests for AuthSession and session validation."""

import json
import tempfile
from pathlib import Path

import httpx
import pytest
from pytest_httpx import HTTPXMock

from wisedu_cas.exceptions import SessionExpiredError
from wisedu_cas.session import AuthSession, _is_cas_login_url


class TestIsCasLoginUrl:
    def test_matches_authserver_host(self) -> None:
        assert _is_cas_login_url(
            "https://authserver.example.edu.cn/authserver/login?service=foo",
            "https://authserver.example.edu.cn",
        ) is True

    def test_rejects_different_host(self) -> None:
        assert _is_cas_login_url(
            "https://other.example.com/authserver/login",
            "https://authserver.example.edu.cn",
        ) is False

    def test_rejects_wrong_path(self) -> None:
        assert _is_cas_login_url(
            "https://authserver.example.edu.cn/other/path",
            "https://authserver.example.edu.cn",
        ) is False

    def test_empty_url(self) -> None:
        assert _is_cas_login_url("", "https://authserver.example.edu.cn") is False

    def test_none_url(self) -> None:
        assert _is_cas_login_url(None, "https://authserver.example.edu.cn") is False  # type: ignore[arg-type]


class TestAuthSessionCookies:
    async def _make_client(self) -> httpx.AsyncClient:
        client = httpx.AsyncClient()
        client.cookies.set("TGC", "tgc-value", "target.example.edu.cn", "/")
        client.cookies.set("JSESSIONID", "session-id", "target.example.edu.cn", "/")
        return client

    async def test_cookies_dict(self) -> None:
        client = await self._make_client()
        session = AuthSession(
            _client=client,
            target_service="https://target.example.edu.cn",
            auth_server="https://authserver.example.edu.cn",
        )
        cookies = session.cookies_dict()
        assert cookies.get("TGC") == "tgc-value"
        assert cookies.get("JSESSIONID") == "session-id"
        await client.aclose()

    async def test_cookie_header(self) -> None:
        client = await self._make_client()
        session = AuthSession(
            _client=client,
            target_service="https://target.example.edu.cn",
            auth_server="https://authserver.example.edu.cn",
        )
        header = session.cookie_header()
        assert "TGC=tgc-value" in header
        assert "JSESSIONID=session-id" in header
        await client.aclose()

    async def test_auth_headers(self) -> None:
        client = await self._make_client()
        session = AuthSession(
            _client=client,
            target_service="https://target.example.edu.cn",
            auth_server="https://authserver.example.edu.cn",
        )
        headers = session.auth_headers()
        assert headers["Host"] == "target.example.edu.cn"
        assert "Cookie" in headers
        assert "TGC=tgc-value" in headers["Cookie"]
        await client.aclose()


class TestAuthSessionPersistence:
    async def _make_client(self) -> httpx.AsyncClient:
        client = httpx.AsyncClient()
        client.cookies.set("TGC", "persist-test-tgc", "target.example.edu.cn", "/")
        return client

    async def test_save_and_load(self) -> None:
        client = await self._make_client()
        session = AuthSession(
            _client=client,
            target_service="https://target.example.edu.cn",
            auth_server="https://authserver.example.edu.cn",
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            session.save(path)
            loaded = await AuthSession.load(
                path,
                target_service="https://target.example.edu.cn",
                auth_server="https://authserver.example.edu.cn",
            )
            assert loaded is not None
            cookies = loaded.cookies_dict()
            assert cookies.get("TGC") == "persist-test-tgc"
            await loaded.close()
        finally:
            Path(path).unlink(missing_ok=True)

        await client.aclose()

    async def test_load_nonexistent_file(self) -> None:
        loaded = await AuthSession.load(
            "/nonexistent/path/cookies.json",
            target_service="https://target.example.edu.cn",
            auth_server="https://authserver.example.edu.cn",
        )
        assert loaded is None

    async def test_load_browser_format(self) -> None:
        data = [
            {"name": "TGC", "value": "browser-tgc", "domain": "target.example.edu.cn", "path": "/"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        try:
            loaded = await AuthSession.load(
                path,
                target_service="https://target.example.edu.cn",
                auth_server="https://authserver.example.edu.cn",
            )
            assert loaded is not None
            assert loaded.cookies_dict().get("TGC") == "browser-tgc"
            await loaded.close()
        finally:
            Path(path).unlink(missing_ok=True)


class TestAuthSessionValidate:
    async def test_validate_success(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="HEAD",
            url="https://target.example.edu.cn/api/config",
            status_code=200,
        )
        client = httpx.AsyncClient()
        session = AuthSession(
            _client=client,
            target_service="https://target.example.edu.cn",
            auth_server="https://authserver.example.edu.cn",
        )
        valid = await session.validate()
        assert valid is True
        await client.aclose()

    async def test_validate_detects_cas_redirect(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="HEAD",
            url="https://target.example.edu.cn/api/config",
            status_code=302,
            headers={
                "Location": "https://authserver.example.edu.cn/authserver/login?service=x"
            },
        )
        client = httpx.AsyncClient()
        session = AuthSession(
            _client=client,
            target_service="https://target.example.edu.cn",
            auth_server="https://authserver.example.edu.cn",
        )
        with pytest.raises(SessionExpiredError):
            await session.validate()
        await client.aclose()
