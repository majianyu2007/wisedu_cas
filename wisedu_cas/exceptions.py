"""
Exception hierarchy for wisedu_cas.

All library exceptions inherit from :class:`AuthError`, allowing callers
to catch a single base type or specific sub-types for fine-grained handling.
"""


class AuthError(Exception):
    """Base exception for all authentication-related errors."""


class NetworkError(AuthError):
    """Low-level network failure (connect timeout, DNS, read error)."""


class InvalidCredentialsError(AuthError):
    """Wrong username/password or account does not exist."""


class CaptchaRequiredError(AuthError):
    """CAS demands a CAPTCHA — the account may be temporarily restricted."""


class TotpRequiredError(AuthError):
    """Server requires TOTP 2FA but no secret or provider was configured."""


class AccountLockedError(AuthError):
    """Account has been locked by the CAS server."""


class LoginBackoffError(AuthError):
    """Login blocked by exponential backoff — retry later.

    Attributes:
        retry_after: Seconds until the next login attempt is allowed.
    """

    def __init__(self, message: str, retry_after: float = 0) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class CircuitOpenError(AuthError):
    """Circuit breaker open — login disabled to protect the account.

    Attributes:
        retry_after: Approximate seconds until the circuit closes.
    """

    def __init__(self, message: str, retry_after: float = 0) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class SessionExpiredError(AuthError):
    """The current session is no longer valid (CAS redirect detected)."""


class ParseError(AuthError):
    """HTML parsing failed — the CAS login page structure may have changed."""
