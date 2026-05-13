"""Data models for wisedu_cas library."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceTicket:
    """A CAS Service Ticket (ST).

    Attributes:
        ticket: The opaque ST string issued by the CAS server.
        service: The service URL this ticket is valid for.
    """

    ticket: str
    service: str


@dataclass
class LoginResult:
    """Result of a login attempt.

    Attributes:
        success: Whether the login completed successfully.
        session: The authenticated session (if success is True).
        error: The exception that caused failure (if success is False).
        failure_type: Short classification string, e.g. ``"password_error"``,
            ``"captcha"``, ``"account_locked"``, ``"network_error"``.
    """

    success: bool
    session: Optional["AuthSession"] = None  # noqa: F821
    error: Optional[Exception] = None
    failure_type: Optional[str] = None


@dataclass
class CASFormFields:
    """Extracted hidden fields from a CAS login page.

    Attributes:
        execution: The ``execution`` token required for form submission.
        pwd_encrypt_salt: The ``pwdEncryptSalt`` used for AES password encryption.
    """

    execution: str
    pwd_encrypt_salt: str
