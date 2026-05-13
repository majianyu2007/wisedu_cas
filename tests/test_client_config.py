import pytest

from wisedu_cas.client import AuthClient
from wisedu_cas.exceptions import TotpRequiredError


def _mk_client(**kwargs):
    return AuthClient(
        auth_server="https://auth.example.edu.cn",
        target_service="https://portal.example.edu.cn",
        username="alice",
        password="secret",
        **kwargs,
    )


def test_invalid_auth_method_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Unsupported auth_method"):
        _mk_client(auth_method="magic")


def test_submit_totp_rejects_non_digit_or_non_six_length() -> None:
    client = _mk_client()
    client._totp_pending = True

    assert client.submit_totp("12345") is False
    assert client.submit_totp("12a456") is False
    assert client.submit_totp(" 1234567 ") is False


def test_submit_totp_accepts_six_digit_code() -> None:
    client = _mk_client()
    client._totp_pending = True

    assert client.submit_totp(" 123456 ") is True
    assert client._totp_code == "123456"


@pytest.mark.anyio
async def test_manual_totp_mode_requires_submit_then_retry() -> None:
    client = _mk_client()

    with pytest.raises(TotpRequiredError, match="totp_secret"):
        await client._resolve_totp_code()

    assert client.totp_pending is True
    assert client.submit_totp("654321") is True
    code = await client._resolve_totp_code()
    assert code == "654321"
    assert client.totp_pending is False


@pytest.mark.anyio
async def test_totp_provider_invalid_code_raises() -> None:
    client = _mk_client(totp_provider=lambda: "abc")

    with pytest.raises(TotpRequiredError, match="totp_provider"):
        await client._resolve_totp_code()


@pytest.mark.anyio
async def test_ensure_logged_in_rejects_invalid_inline_totp_code() -> None:
    client = _mk_client()

    with pytest.raises(TotpRequiredError, match="6-digit"):
        await client.ensure_logged_in(totp_code="12ab")


@pytest.mark.anyio
async def test_ensure_logged_in_sets_inline_totp_code(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _mk_client()

    async def fake_login():
        return "ok"

    monkeypatch.setattr(client, "_do_login_with_protections", fake_login)
    client._state = client._state.EXPIRED
    result = await client.ensure_logged_in(totp_code="123456")

    assert result == "ok"
    assert client._totp_code == "123456"
