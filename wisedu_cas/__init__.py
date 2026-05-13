"""
wisedu_cas — A Python client library for Wisedu (金智教育) CAS authentication.

Usage::

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

See the `README.md <https://github.com/majianyu2007/wisedu_cas>`_ for full documentation.
"""

from wisedu_cas.client import AuthClient
from wisedu_cas.exceptions import (
    AccountLockedError,
    AuthError,
    CaptchaRequiredError,
    CircuitOpenError,
    InvalidCredentialsError,
    LoginBackoffError,
    NetworkError,
    ParseError,
    SessionExpiredError,
    TotpRequiredError,
)
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
]

__version__ = "0.1.0"
