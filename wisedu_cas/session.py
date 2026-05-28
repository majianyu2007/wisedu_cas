"""
AuthSession — represents an authenticated CAS session with cookie management.

Provides cookie serialization, validation, and header generation for use
in downstream HTTP requests to the target service.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from wisedu_cas.exceptions import SessionExpiredError
from wisedu_cas.transport import RETRIABLE_NET_ERRORS

logger = logging.getLogger("wisedu_cas.session")


@dataclass
class AuthSession:
    """An authenticated CAS session, backed by an :class:`httpx.AsyncClient` cookie jar.

    Typically obtained via :meth:`AuthClient.login` or :meth:`AuthClient.ensure_logged_in`.
    """

    _client: httpx.AsyncClient
    target_service: str
    auth_server: str
    _created_at: float = field(default_factory=time.monotonic)

    # ---- Cookie utilities ----

    def cookies_dict(self) -> dict[str, str]:
        """Return all cookies as a ``{name: value}`` dict for the target service domain.

        Only cookies matching the target service hostname are included.
        """
        result: dict[str, str] = {}
        try:
            target_host = urlparse(self.target_service).hostname or ""
            for cookie in self._client.cookies.jar:
                domain = cookie.domain.lstrip(".")
                if target_host == domain or target_host.endswith(f".{domain}"):
                    result[cookie.name] = cookie.value
        except Exception:
            pass
        return result

    def cookie_header(self) -> str:
        """Return a ``Cookie`` header value string for the target service.

        Returns:
            A string like ``"TGC=...; JSESSIONID=..."`` or ``""`` if no cookies match.
        """
        pairs = []
        try:
            target_host = urlparse(self.target_service).hostname or ""
            for cookie in self._client.cookies.jar:
                domain = cookie.domain.lstrip(".")
                if target_host == domain or target_host.endswith(f".{domain}"):
                    pairs.append(f"{cookie.name}={cookie.value}")
        except Exception:
            pass
        return "; ".join(pairs)

    def auth_headers(self) -> dict[str, str]:
        """Return headers suitable for forwarding to the target service.

        Currently includes ``Host`` and ``Cookie`` headers. Additional headers
        (e.g. ``Authorization``) should be added by the caller as needed.
        """
        headers: dict[str, str] = {}
        target_host = urlparse(self.target_service).hostname or ""
        if target_host:
            headers["Host"] = target_host
        cookie = self.cookie_header()
        if cookie:
            headers["Cookie"] = cookie
        return headers

    # ---- Validation ----

    def is_expired(self) -> bool:
        """Heuristic check: returns ``True`` if the session has exceeded the default TTL.

        This does not make a network request. For a definitive check, call
        :meth:`validate`.
        """
        return (time.monotonic() - self._created_at) > 7200  # 2h default

    async def validate(
        self,
        probe_url: Optional[str] = None,
        follow_redirects: bool = False,
    ) -> bool:
        """Probe the target service to verify the session is still valid.

        Sends a lightweight ``HEAD`` request and checks for a CAS login redirect.

        Args:
            probe_url: URL to probe (defaults to ``{target_service}/api/config``).
            follow_redirects: Whether to follow redirects on the probe request.

        Returns:
            ``True`` if the probe returned a non-CAS-redirect response.

        Raises:
            SessionExpiredError: If a definitive CAS redirect was detected.
        """
        url = probe_url or urljoin(self.target_service, "/api/config")
        target_host = urlparse(self.target_service).hostname or ""
        try:
            resp = await self._client.head(
                url,
                headers={"Host": target_host},
                follow_redirects=follow_redirects,
            )
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                if _is_auth_redirect(location, self.auth_server):
                    raise SessionExpiredError(
                        f"Session expired: redirected to auth at {location[:80]}"
                    )
            return True
        except RETRIABLE_NET_ERRORS:
            logger.debug("Session validation skipped due to network error")
            return True  # network hiccup — don't invalidate
        except SessionExpiredError:
            raise

    # ---- Lifecycle ----

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        try:
            await self._client.aclose()
        except Exception:
            pass

    # ---- Persistence (optional) ----

    def save(self, path: str) -> None:
        """Persist session cookies to a JSON file.

        Args:
            path: File path for the cookie JSON file.
        """
        cookies = []
        for cookie in self._client.cookies.jar:
            cookies.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
            })
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"cookies": cookies, "saved_at": time.time()}, f)
        logger.info("event=cookies_saved count=%d path=%s", len(cookies), path)

    @staticmethod
    async def load(
        path: str,
        target_service: str,
        auth_server: str,
        http_timeout: float = 60.0,
        http_connect_timeout: float = 15.0,
    ) -> Optional["AuthSession"]:
        """Restore a session from a persisted cookie file.

        Supports two JSON formats:
          1. ``{"cookies": [...], "saved_at": ...}`` (library format).
          2. ``[{"name": ..., "value": ...}, ...]`` (browser-export arrays).

        Args:
            path: Path to the cookie JSON file.
            target_service: Target service base URL.
            auth_server: AuthServer base URL.
            http_timeout: HTTP timeout for the restored client.
            http_connect_timeout: HTTP connect timeout.

        Returns:
            An :class:`AuthSession` if restoration succeeded, or ``None``.
        """
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

        if isinstance(data, list):
            cookies = data
            saved_at = 0
        elif isinstance(data, dict):
            cookies = data.get("cookies", [])
            saved_at = data.get("saved_at", 0)
        else:
            return None

        if not cookies:
            return None

        from wisedu_cas.transport import create_http_client

        client = create_http_client(
            timeout=http_timeout,
            connect_timeout=http_connect_timeout,
        )
        for c in cookies:
            name = c.get("name", "")
            value = c.get("value", "")
            domain = c.get("domain", c.get("Domain", ""))
            path = c.get("path", c.get("Path", "/"))
            client.cookies.set(name, value, domain, path)

        age_hint = ""
        if saved_at:
            age_days = (time.time() - saved_at) / 86400
            age_hint = f" saved_ago={age_days:.1f}d"

        logger.info("event=cookies_loaded count=%d%s", len(cookies), age_hint)
        return AuthSession(
            _client=client,
            target_service=target_service,
            auth_server=auth_server,
        )


def _is_cas_login_url(url: str, auth_server: str) -> bool:
    """Check if *url* is a CAS login page redirect for the given AuthServer.

    Args:
        url: The URL to inspect.
        auth_server: The AuthServer base URL (e.g. ``https://authserver.example.edu.cn``).

    Returns:
        ``True`` if the URL hostname matches *auth_server* and the path starts
        with ``/authserver/login``.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        auth_parsed = urlparse(auth_server)
    except Exception:
        return False
    if parsed.hostname == auth_parsed.hostname and parsed.path.startswith(
        "/authserver/login"
    ):
        return True
    return False


def _is_vouch_login_url(url: str) -> bool:
    """Check if *url* is a Vouch Proxy login redirect.

    Returns ``True`` if the URL hostname is ``vouch.nwafu.edu.cn`` and the
    path starts with ``/login``.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.hostname == "vouch.nwafu.edu.cn" and parsed.path.startswith("/login")


def _is_auth_redirect(url: str, auth_server: str) -> bool:
    """Check if *url* indicates an authentication redirect (CAS login or Vouch Proxy)."""
    return _is_cas_login_url(url, auth_server) or _is_vouch_login_url(url)
