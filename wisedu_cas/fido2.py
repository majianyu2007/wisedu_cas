"""
FIDO2/WebAuthn (passkey) authentication for Wisedu AuthServer.

Provides the full client-side FIDO2 flow:
    1. Request a challenge from the AuthServer (startAssertion).
    2. Build and sign a WebAuthn assertion from a pre-extracted credential.
    3. Submit the assertion to complete CAS login.
    4. Follow redirects to obtain TGC and ST tickets.

Requires a pre-extracted credential containing an ECDSA P-256 private key,
typically exported from a browser passkey store (e.g. Bitwarden).
"""

import base64
import hashlib
import json
import logging
import re
import struct
from typing import Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from wisedu_cas.exceptions import Fido2AssertionError, Fido2NotConfiguredError

logger = logging.getLogger("wisedu_cas.fido2")

# Matches the 2FA re-auth view URL path (shared with client.py).
_RE_AUTH_VIEW = re.compile(r"/authserver/reAuthCheck/reAuthLoginView\.do", re.I)


# ---- Data model ----

class Fido2Credential:
    """A pre-extracted FIDO2 / WebAuthn credential.

    Attributes:
        credential_id: The hex credential ID (e.g. from Bitwarden export).
        key_value: Base64-encoded ECDSA P-256 private key (DER format).
        rp_id: The Relying Party ID (AuthServer hostname without scheme).
        user_handle: Optional user handle string.
        device_binding_id: Optional device-binding UUID for the CAS
                           startAssertion request.
    """

    def __init__(
        self,
        credential_id: str,
        key_value: str,
        rp_id: str,
        user_handle: str = "",
        device_binding_id: str = "",
    ) -> None:
        self.credential_id = credential_id
        self.key_value = key_value
        self.rp_id = rp_id
        self.user_handle = user_handle
        self.device_binding_id = device_binding_id

    @classmethod
    def from_dict(cls, data: dict) -> "Fido2Credential":
        """Build a :class:`Fido2Credential` from a dict (e.g. parsed JSON).

        Expected keys: ``credentialId``, ``keyValue``, ``rpId``.
        Optional keys: ``userHandle``, ``deviceBindingId``.
        """
        return cls(
            credential_id=data.get("credentialId", ""),
            key_value=data.get("keyValue", ""),
            rp_id=data.get("rpId", data.get("rpID", "")),
            user_handle=data.get("userHandle", ""),
            device_binding_id=data.get("deviceBindingId", ""),
        )

    def is_valid(self) -> bool:
        """Return ``True`` if the credential has the minimum required fields."""
        return bool(self.credential_id and self.key_value and self.rp_id)


# ---- Crypto helpers ----

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=").replace("+", "-").replace("/", "_")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---- Private key loading ----

def load_private_key(key_value_b64: str) -> ec.EllipticCurvePrivateKey:
    """Parse an ECDSA P-256 private key.

    Accepts both standard Base64 and Base64URL encodings.

    Args:
        key_value_b64: The Base64-encoded DER private key.

    Returns:
        An :class:`ec.EllipticCurvePrivateKey`.

    Raises:
        ValueError: If the key cannot be parsed.
    """
    try:
        der = base64.b64decode(key_value_b64)
    except Exception:
        der = _b64url_decode(key_value_b64)
    return serialization.load_der_private_key(der, password=None, backend=default_backend())  # type: ignore[return-value]


# ---- Assertion building ----

def build_client_data(challenge_b64: str, rp_id: str, origin: str) -> Tuple[bytes, bytes]:
    """Build ``clientDataJSON``.

    Args:
        challenge_b64: Base64URL challenge from the server.
        rp_id: Relying Party ID (AuthServer hostname).
        origin: The origin URL (AuthServer base URL).

    Returns:
        A ``(json_bytes, sha256_hash)`` tuple.
    """
    client_data = {
        "type": "webauthn.get",
        "challenge": challenge_b64,
        "origin": origin,
        "crossOrigin": False,
    }
    json_bytes = json.dumps(client_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return json_bytes, _sha256(json_bytes)


def build_authenticator_data(rp_id: str, sign_count: int = 0, flags: int = 0x1D) -> bytes:
    """Build ``authenticatorData``.

    Default flags ``0x1D`` = UP | UV | BE | BS, matching browser passkey behaviour.

    Args:
        rp_id: Relying Party ID.
        sign_count: Signature counter (usually 0).
        flags: Authenticator flags byte.

    Returns:
        The raw ``authenticatorData`` bytes.
    """
    rp_id_hash = _sha256(rp_id.encode("utf-8"))
    counter = struct.pack(">I", sign_count)
    return rp_id_hash + bytes([flags]) + counter


def build_webauthn_assertion(
    credential: "Fido2Credential",
    challenge_b64: str,
    origin: str,
) -> dict:
    """Build a signed WebAuthn assertion ready for submission.

    Args:
        credential: The :class:`Fido2Credential`.
        challenge_b64: Base64URL challenge from ``startAssertion``.
        origin: The AuthServer origin URL (e.g. ``https://authserver.example.edu.cn``).

    Returns:
        A dict matching the browser ``responseToObject`` structure:
        ``{"id": ..., "type": "public-key", "response": {...}, "clientExtensionResults": {}}``.

    Raises:
        Fido2AssertionError: If signing fails or the credential is invalid.
    """
    if not credential.is_valid():
        raise Fido2AssertionError("FIDO2 credential is missing required fields")

    try:
        raw_id = bytes.fromhex(credential.credential_id.replace("-", ""))
    except ValueError as e:
        raise Fido2AssertionError(f"Invalid credentialId format: {e}") from e

    credential_id_b64 = _b64url_encode(raw_id)

    try:
        private_key = load_private_key(credential.key_value)
    except Exception as e:
        raise Fido2AssertionError(f"Failed to load private key: {e}") from e

    client_data_bytes, client_data_hash = build_client_data(
        challenge_b64, credential.rp_id, origin
    )
    auth_data = build_authenticator_data(credential.rp_id, flags=0x1D)

    signed_data = auth_data + client_data_hash
    try:
        signature_der = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        raise Fido2AssertionError(f"Signing failed: {e}") from e

    result: dict = {
        "id": credential_id_b64,
        "type": "public-key",
        "response": {
            "authenticatorData": _b64url_encode(auth_data),
            "clientDataJSON": _b64url_encode(client_data_bytes),
            "signature": _b64url_encode(signature_der),
        },
        "clientExtensionResults": {},
    }
    if credential.user_handle:
        result["response"]["userHandle"] = credential.user_handle
    return result


# ---- Network operations (against AuthServer) ----

async def start_assertion(
    client: httpx.AsyncClient,
    auth_server: str,
    username: str,
    device_binding_id: str,
) -> dict:
    """Request a FIDO2 challenge from the AuthServer.

    Args:
        client: An :class:`httpx.AsyncClient`.
        auth_server: AuthServer base URL.
        username: CAS username (will be Base64-encoded).
        device_binding_id: The device-binding UUID from the credential.

    Returns:
        The parsed JSON response dict.

    Raises:
        Fido2AssertionError: If the server rejects the request or the
            response structure is unexpected.
    """
    resp = await client.post(
        f"{auth_server}/authserver/startAssertion",
        json={
            "userId": base64.b64encode(username.encode()).decode(),
            "id": device_binding_id,
        },
        headers={"Content-Type": "application/json;charset=utf-8"},
    )
    try:
        data = resp.json()
    except Exception as e:
        raise Fido2AssertionError(f"startAssertion returned non-JSON: {e}") from e

    result = data.get("result", {})
    if not result.get("success"):
        raise Fido2AssertionError(
            f"startAssertion rejected: {json.dumps(data, ensure_ascii=False)[:200]}"
        )
    return result


def parse_assertion_options(start_result: dict) -> Tuple[str, str, str]:
    """Extract challenge, rpId, and requestId from a ``startAssertion`` response.

    Args:
        start_result: The ``result`` dict from the ``startAssertion`` JSON response.

    Returns:
        A ``(challenge_b64, rp_id, request_id)`` tuple.

    Raises:
        Fido2AssertionError: If required fields are missing.
    """
    req = start_result.get("request", {})
    if not req:
        raise Fido2AssertionError("startAssertion response missing 'request' field")
    opts = req.get("publicKeyCredentialRequestOptions", {})
    if not opts:
        raise Fido2AssertionError(
            "startAssertion response missing 'publicKeyCredentialRequestOptions'"
        )
    challenge = opts.get("challenge", "")
    rp_id = opts.get("rpId", "")
    request_id = req.get("requestId", "")
    if not challenge or not rp_id or not request_id:
        raise Fido2AssertionError(
            "startAssertion response missing challenge, rpId, or requestId"
        )
    return challenge, rp_id, request_id


async def submit_assertion(
    client: httpx.AsyncClient,
    auth_server: str,
    username: str,
    execution: str,
    request_id: str,
    assertion: dict,
) -> httpx.Response:
    """Submit a signed FIDO2 assertion to the CAS login endpoint.

    Args:
        client: An :class:`httpx.AsyncClient`.
        auth_server: AuthServer base URL.
        username: CAS username (will be Base64-encoded).
        execution: The ``execution`` token from the CAS login page.
        request_id: The ``requestId`` from ``startAssertion``.
        assertion: The assertion dict from :func:`build_webauthn_assertion`.

    Returns:
        The HTTP response. A 302/307 indicates success (TGC obtained).

    Raises:
        Fido2AssertionError: On network errors.
    """
    response_json = json.dumps(
        {"requestId": request_id, "credential": assertion, "sessionToken": None},
        separators=(",", ":"),
    )
    form = {
        "username": base64.b64encode(username.encode()).decode(),
        "responseJson": response_json,
        "_eventId": "submit",
        "cllt": "fidoLogin",
        "dllt": "generalLogin",
        "lt": "",
        "execution": execution,
    }
    try:
        return await client.post(
            f"{auth_server}/authserver/login",
            data=form,
            follow_redirects=False,
        )
    except Exception as e:
        raise Fido2AssertionError(f"Assertion submission failed: {e}") from e


async def extract_execution(html: str) -> str:
    """Extract the ``execution`` token from a CAS login page HTML.

    Args:
        html: Raw HTML of the CAS login page.

    Returns:
        The execution token value.

    Raises:
        Fido2AssertionError: If the execution token cannot be found.
    """
    m = re.search(r'name="execution"[^>]*value="([^"]+)"', html)
    if not m:
        raise Fido2AssertionError("Cannot extract execution token from CAS login page")
    return m.group(1)


# ---- Full FIDO2 authenticator ----

class Fido2Authenticator:
    """Orchestrates a full FIDO2 passkey login against a Wisedu AuthServer.

    Args:
        auth_server: AuthServer base URL (e.g. ``https://authserver.example.edu.cn``).
        username: CAS username.
        credential: A :class:`Fido2Credential` with the pre-extracted key material.
    """

    def __init__(
        self,
        auth_server: str,
        username: str,
        credential: "Fido2Credential",
    ) -> None:
        self.auth_server = auth_server.rstrip("/")
        self.username = username
        self.credential = credential

    async def authenticate(
        self,
        client: httpx.AsyncClient,
        execution: Optional[str] = None,
    ) -> httpx.Response:
        """Execute the full FIDO2 login flow.

        1. Fetch the login page for an execution token (if not provided).
        2. Call ``startAssertion``.
        3. Build and sign the WebAuthn assertion.
        4. Submit the assertion to the CAS login endpoint.

        Args:
            client: An :class:`httpx.AsyncClient` to use for HTTP requests.
            execution: The execution token from the CAS login page. If ``None``,
                the login page will be fetched to extract one.

        Returns:
            The HTTP response from the assertion submission. A ``302/307``
            status indicates success (TGC cookie set).

        Raises:
            Fido2AssertionError: At any stage of the flow.
            Fido2NotConfiguredError: If the credential is not valid.
        """
        if not self.credential.is_valid():
            raise Fido2NotConfiguredError(
                "FIDO2 credential is missing required fields "
                "(credentialId, keyValue, rpId)"
            )

        # Step 1: Obtain execution token
        if execution is None:
            resp = await client.get(
                f"{self.auth_server}/authserver/login",
                follow_redirects=False,
            )
            execution = await extract_execution(resp.text)
            logger.debug("FIDO2: execution=%s...", execution[:30])

        # Step 2: startAssertion
        start = await start_assertion(
            client,
            self.auth_server,
            self.username,
            self.credential.device_binding_id,
        )
        challenge, rp_id, request_id = parse_assertion_options(start)
        logger.debug("FIDO2: challenge obtained, rpId=%s", rp_id)

        # Step 3: Build signed assertion
        assertion = build_webauthn_assertion(
            self.credential, challenge, self.auth_server
        )
        logger.debug("FIDO2: assertion built")

        # Step 4: Submit
        resp = await submit_assertion(
            client,
            self.auth_server,
            self.username,
            execution,
            request_id,
            assertion,
        )
        return resp
