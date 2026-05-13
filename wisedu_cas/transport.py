"""
HTTP transport layer wrapping :mod:`httpx`.

Provides an async HTTP client factory with built-in network retry logic,
cookie jar management, and configurable timeouts.
"""

import asyncio
import logging
from typing import Optional

import httpx

logger = logging.getLogger("wisedu_cas.transport")

# Network errors that are safe to retry.
RETRIABLE_NET_ERRORS = (
    httpx.ConnectError,
    httpx.NetworkError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
)

_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_DEFAULT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_DEFAULT_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8"


def create_http_client(
    timeout: float = 60.0,
    connect_timeout: float = 15.0,
    max_connections: int = 30,
    max_keepalive: int = 15,
    custom_headers: Optional[dict[str, str]] = None,
) -> httpx.AsyncClient:
    """Create a pre-configured :class:`httpx.AsyncClient` for CAS interactions.

    Args:
        timeout: Total request timeout in seconds.
        connect_timeout: Connection timeout in seconds.
        max_connections: Maximum concurrent connections.
        max_keepalive: Maximum keep-alive connections.
        custom_headers: Additional default headers to merge.

    Returns:
        A configured async HTTP client. The caller is responsible for closing it.
    """
    headers = {
        "User-Agent": _DEFAULT_USER_AGENT,
        "Accept": _DEFAULT_ACCEPT,
        "Accept-Language": _DEFAULT_ACCEPT_LANGUAGE,
    }
    if custom_headers:
        headers.update(custom_headers)

    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=connect_timeout),
        follow_redirects=True,
        trust_env=False,
        limits=httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive,
        ),
        headers=headers,
    )


async def retry_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_retries: int = 3,
    follow_redirects: bool = False,
    **kwargs,
) -> httpx.Response:
    """Perform an HTTP request with automatic retry on transient network errors.

    Args:
        client: The HTTP client to use.
        method: HTTP method (``GET``, ``POST``, etc.).
        url: Target URL.
        max_retries: Maximum number of attempts (including the first).
        follow_redirects: Whether to follow redirects on this request.
        **kwargs: Additional arguments forwarded to ``client.request()``.

    Returns:
        The HTTP response.

    Raises:
        httpx.ConnectError: If all retries are exhausted on connection failure.
        httpx.NetworkError: If all retries are exhausted on network error.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            return await client.request(
                method, url, follow_redirects=follow_redirects, **kwargs
            )
        except RETRIABLE_NET_ERRORS as e:
            last_exc = e
            if attempt < max_retries - 1:
                logger.warning(
                    "event=network_retry method=%s url=%s error=%s attempt=%d",
                    method, str(url)[:60], e, attempt + 1,
                )
                await asyncio.sleep(1.0 * (2 ** attempt))
                continue
            raise
    assert last_exc is not None
    raise last_exc
