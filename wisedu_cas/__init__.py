"""
wisedu_cas — A Python client library for Wisedu (金智教育) CAS authentication.

Usage (password + TOTP)::

    import asyncio
    from wisedu_cas import AuthClient

    async def main():
        client = AuthClient(
            auth_server="https://authserver.example.edu.cn",
            target_service="https://target.example.edu.cn",
            username="your_username",
            password="your_password",
            totp_secret="BASE32SECRET",  # optional
        )
        session = await client.login()
        print(session.cookies_dict())

    asyncio.run(main())

Usage (FIDO2 passkey)::

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
        password="your_password",  # fallback in "auto" mode
        fido2_credential=cred,
        auth_method="fido2",
    )
    session = await client.login()

See the `README.md <https://github.com/majianyu2007/wisedu_cas>`_ for full documentation.
"""

from wisedu_cas.client import AuthClient
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
from wisedu_cas.fido2 import Fido2Authenticator, Fido2Credential
from wisedu_cas.session import AuthSession
from wisedu_cas.state import AuthState

__all__ = [
    "AuthClient",
    "AuthSession",
    "AuthState",
    "AuthError",
    "NetworkError",
    "InvalidCredentialsError",
    "CaptchaRequiredError",
    "TotpRequiredError",
    "AccountLockedError",
    "LoginBackoffError",
    "CircuitOpenError",
    "SessionExpiredError",
    "ParseError",
    "Fido2NotConfiguredError",
    "Fido2AssertionError",
    "Fido2Credential",
    "Fido2Authenticator",
]

__version__ = "0.2.1"
