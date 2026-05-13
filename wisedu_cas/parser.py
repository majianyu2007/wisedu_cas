"""
HTML parsing utilities for Wisedu CAS login pages.

All parsing is done via stdlib :mod:`re` — no heavy HTML parser dependency.
"""

import re
from typing import Optional, Tuple

from wisedu_cas.exceptions import ParseError

# Matches an <input> tag with a specific id attribute.
_RE_INPUT_BY_ID = lambda name: re.compile(
    rf'<input\b[^>]*\bid=["\']{re.escape(name)}["\'][^>]*>', re.I
)

# Extracts the value attribute from an <input> tag.
_RE_VALUE_ATTR = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.I)

# Extracts error message from the CAS form error tip element.
_RE_ERROR_TIP = re.compile(
    r'id=["\']formErrorTip["\'][^>]*>.*?<span[^>]*>([^<]+)</span>',
    re.S | re.I,
)

# Matches CAS form-specific hidden fields (execution, pwdEncryptSalt).
_RE_CAS_FORM_FIELDS = re.compile(
    r'<input\b[^>]*\bid=["\'](?:execution|pwdEncryptSalt)["\'][^>]*>', re.I
)

# Body sample size for CAS field detection.
_BODY_SAMPLE_MAX_BYTES = 4096


def _extract_input_value(html: str, input_id: str) -> Optional[str]:
    """Extract the ``value`` attribute of an ``<input id="...">`` element.

    Args:
        html: Raw HTML string.
        input_id: The ``id`` attribute value to search for.

    Returns:
        The ``value`` attribute content, or ``None`` if not found.
    """
    tag_match = _RE_INPUT_BY_ID(input_id).search(html)
    if not tag_match:
        return None
    val = _RE_VALUE_ATTR.search(tag_match.group(0))
    return val.group(1) if val else ""


def parse_login_form(html: str) -> Tuple[str, str]:
    """Extract the ``execution`` token and ``pwdEncryptSalt`` from a CAS login page.

    Args:
        html: Full HTML of the CAS login page.

    Returns:
        A ``(execution, pwdEncryptSalt)`` tuple.

    Raises:
        ParseError: If either field cannot be extracted.
    """
    execution = _extract_input_value(html, "execution")
    salt = _extract_input_value(html, "pwdEncryptSalt")
    if execution is None or salt is None:
        raise ParseError(
            "CAS login page structure changed: "
            "cannot extract execution/pwdEncryptSalt fields"
        )
    return execution, salt


def extract_error_text(html: str) -> Optional[str]:
    """Extract the error tip text from a CAS login page, if present.

    Args:
        html: Raw HTML of the CAS page (usually a failed login response).

    Returns:
        The error message string, or ``None`` if no error tip was found.
    """
    m = _RE_ERROR_TIP.search(html)
    return m.group(1).strip() if m else None


def body_contains_cas_fields(body_bytes: bytes) -> bool:
    """Check if a response body likely contains a CAS login form.

    Examines the first 4 KiB of *body_bytes* for ``execution`` and
    ``pwdEncryptSalt`` hidden input fields.

    Args:
        body_bytes: Raw response body bytes.

    Returns:
        ``True`` if both form fields were detected.
    """
    sample = body_bytes[:_BODY_SAMPLE_MAX_BYTES].decode("utf-8", errors="ignore")
    found: set[str] = set()
    for m in _RE_CAS_FORM_FIELDS.finditer(sample):
        tag = m.group(0).lower()
        if 'id="execution"' in tag or "id='execution'" in tag:
            found.add("execution")
        if 'id="pwdencryptsalt"' in tag or "id='pwdencryptsalt'" in tag:
            found.add("pwdEncryptSalt")
    return "execution" in found and "pwdEncryptSalt" in found
