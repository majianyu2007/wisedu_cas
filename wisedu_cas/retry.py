"""
Login protection layers: rate limiter, exponential backoff with jitter,
circuit breaker, and single-flight lock.

All time-related parameters are expressed in seconds.
"""

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Optional

from wisedu_cas.exceptions import CircuitOpenError, LoginBackoffError
from wisedu_cas.state import AuthState

logger = logging.getLogger("wisedu_cas.retry")


# ---- Constants ----

_DEFAULT_MAX_LOGINS_PER_HOUR = 6
_DEFAULT_LOGIN_WINDOW = 3600
_DEFAULT_BACKOFF_BASE = 5
_DEFAULT_BACKOFF_MULTIPLIER = 4
_DEFAULT_BACKOFF_MAX_NORMAL = 900        # 15 min
_DEFAULT_BACKOFF_MAX_CRITICAL = 14400    # 4 hours
_DEFAULT_CIRCUIT_NORMAL = 900            # 15 min
_DEFAULT_CIRCUIT_CRITICAL = 21600        # 6 hours
_DEFAULT_CIRCUIT_CAPTCHA = 7200          # 2 hours
_DEFAULT_CIRCUIT_PASSWORD_ERROR = 3600   # 1 hour
_DEFAULT_MAX_CONSECUTIVE_FAILURES = 3


@dataclass
class RetryConfig:
    """Configuration for all login protection layers.

    Attributes:
        max_logins_per_hour: Maximum login attempts allowed in a rolling 1-hour window.
        login_window_seconds: Length of the rolling rate-limit window.
        max_consecutive_failures: Consecutive failures that trigger circuit breaker.
        backoff_base: Base seconds for exponential backoff calculation.
        backoff_multiplier: Multiplier applied per consecutive failure.
        backoff_max_normal: Maximum backoff for non-critical failures.
        backoff_max_critical: Maximum backoff for critical failures (lock, captcha).
        circuit_normal_duration: Circuit breaker duration for normal failures.
        circuit_critical_duration: Circuit breaker duration for critical failures.
        circuit_captcha_duration: Circuit breaker duration for captcha-detected failures.
        circuit_password_error_duration: Circuit breaker duration for password errors.
    """

    max_logins_per_hour: int = _DEFAULT_MAX_LOGINS_PER_HOUR
    login_window_seconds: int = _DEFAULT_LOGIN_WINDOW
    max_consecutive_failures: int = _DEFAULT_MAX_CONSECUTIVE_FAILURES
    backoff_base: float = _DEFAULT_BACKOFF_BASE
    backoff_multiplier: float = _DEFAULT_BACKOFF_MULTIPLIER
    backoff_max_normal: float = _DEFAULT_BACKOFF_MAX_NORMAL
    backoff_max_critical: float = _DEFAULT_BACKOFF_MAX_CRITICAL
    circuit_normal_duration: float = _DEFAULT_CIRCUIT_NORMAL
    circuit_critical_duration: float = _DEFAULT_CIRCUIT_CRITICAL
    circuit_captcha_duration: float = _DEFAULT_CIRCUIT_CAPTCHA
    circuit_password_error_duration: float = _DEFAULT_CIRCUIT_PASSWORD_ERROR


class RateLimiter:
    """Rolling-window rate limiter with optional file-backed persistence."""

    def __init__(self, config: RetryConfig, storage_path: Optional[str] = None) -> None:
        self._config = config
        self._storage_path = storage_path
        self._attempt_times: list[float] = []
        self._load()

    def check(self) -> bool:
        """Return ``True`` if a login attempt is allowed under the rate limit."""
        now = time.time()
        self._attempt_times = [
            t for t in self._attempt_times
            if now - t < self._config.login_window_seconds
        ]
        return len(self._attempt_times) < self._config.max_logins_per_hour

    def record(self) -> None:
        """Record a login attempt."""
        self._attempt_times.append(time.time())
        self._save()

    def _load(self) -> None:
        if not self._storage_path:
            return
        try:
            with open(self._storage_path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        now = time.time()
        self._attempt_times = [
            t for t in data.get("attempts", [])
            if now - t < self._config.login_window_seconds
        ]

    def _save(self) -> None:
        if not self._storage_path:
            return
        try:
            os.makedirs(os.path.dirname(self._storage_path), exist_ok=True)
            with open(self._storage_path, "w") as f:
                json.dump({"attempts": self._attempt_times}, f)
        except Exception:
            logger.debug("Failed to persist rate limit state", exc_info=True)

    def to_dict(self) -> dict:
        """Export state for combined persistence."""
        return {"attempts": self._attempt_times}

    def from_dict(self, data: dict) -> None:
        """Restore state from a combined persistence dict."""
        now = time.time()
        self._attempt_times = [
            t for t in data.get("attempts", [])
            if now - t < self._config.login_window_seconds
        ]


class BackoffCalculator:
    """Exponential backoff with jitter."""

    def __init__(self, config: RetryConfig) -> None:
        self._config = config
        self.consecutive_failures: int = 0

    def compute(self, is_critical: bool = False) -> float:
        """Compute a backoff duration in seconds.

        Args:
            is_critical: If ``True``, use the critical-failure maximum.

        Returns:
            Backoff duration in seconds (with jitter applied).
        """
        max_delay = (
            self._config.backoff_max_critical
            if is_critical
            else self._config.backoff_max_normal
        )
        raw = min(
            self._config.backoff_base
            * (self._config.backoff_multiplier ** max(0, self.consecutive_failures - 1)),
            max_delay,
        )
        jitter = raw * (0.75 + random.random() * 0.5)
        return jitter

    def reset(self) -> None:
        """Reset consecutive failure counter (call on successful login)."""
        self.consecutive_failures = 0


class CircuitBreaker:
    """Circuit breaker that opens after consecutive failures and auto-closes after a duration.

    Attributes:
        state: The current :class:`AuthState` reflecting circuit status.
    """

    def __init__(
        self,
        config: RetryConfig,
        state_callback: Optional[callable] = None,
        storage_path: Optional[str] = None,
    ) -> None:
        self._config = config
        self._state_callback = state_callback
        self._storage_path = storage_path
        self._circuit_until: float = 0
        self._circuit_duration: float = 0
        self.state: AuthState = AuthState.EXPIRED  # managed externally

    @property
    def is_open(self) -> bool:
        """Return ``True`` if the circuit is currently open."""
        if self.state != AuthState.CIRCUIT_OPEN:
            return False
        if time.monotonic() >= self._circuit_until:
            self._close("circuit_expired")
            return False
        return True

    def _close(self, reason: str) -> None:
        self.state = AuthState.EXPIRED
        if self._state_callback:
            self._state_callback(AuthState.EXPIRED, reason)
        logger.info("event=circuit state=closed")

    def open(self, duration: float, reason: str) -> None:
        """Open the circuit for *duration* seconds.

        Args:
            duration: How long the circuit should stay open.
            reason: Human-readable reason for logging.
        """
        self.state = AuthState.CIRCUIT_OPEN
        self._circuit_duration = duration
        self._circuit_until = time.monotonic() + duration
        if self._state_callback:
            self._state_callback(AuthState.CIRCUIT_OPEN, f"circuit_open:{reason}")
        logger.warning("event=circuit state=open duration=%ds reason=%s", int(duration), reason)

    def check_or_raise(self) -> None:
        """Check if the circuit is open; if so, raise :class:`CircuitOpenError`.

        If the circuit has expired, close it silently.
        """
        if self.state != AuthState.CIRCUIT_OPEN:
            return
        remaining = self._circuit_until - time.monotonic()
        if remaining <= 0:
            self._close("circuit_expired")
            return
        raise CircuitOpenError(
            "Login temporarily disabled to protect the campus account. "
            "Please retry later.",
            retry_after=remaining,
        )

    @property
    def remaining(self) -> float:
        """Seconds until the circuit closes, or 0."""
        if self.state != AuthState.CIRCUIT_OPEN:
            return 0
        return max(0.0, self._circuit_until - time.monotonic())

    @property
    def circuit_until(self) -> float:
        return self._circuit_until

    @property
    def circuit_duration(self) -> float:
        return self._circuit_duration

    def to_dict(self) -> dict:
        return {
            "circuit_remaining": int(self.remaining),
            "circuit_duration": int(self._circuit_duration) if self.state == AuthState.CIRCUIT_OPEN else 0,
        }

    def from_dict(self, data: dict, consecutive_failures: int) -> None:
        circuit_remaining = data.get("circuit_remaining", 0)
        circuit_duration = data.get("circuit_duration", 0)
        if circuit_remaining > 0:
            self.state = AuthState.CIRCUIT_OPEN
            self._circuit_until = time.monotonic() + circuit_remaining
            self._circuit_duration = circuit_duration
            logger.info(
                "event=state_restored state=circuit_open "
                "consecutive_failures=%d remaining=%ds",
                consecutive_failures, circuit_remaining,
            )


class SingleFlightLock:
    """Ensures only one login operation executes at a time across concurrent callers.

    Uses a double-check pattern under :class:`asyncio.Lock`.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire the single-flight lock."""
        await self._lock.acquire()

    def release(self) -> None:
        """Release the single-flight lock."""
        try:
            self._lock.release()
        except RuntimeError:
            pass  # already released

    async def __aenter__(self) -> "SingleFlightLock":
        await self.acquire()
        return self

    async def __aexit__(self, *args) -> None:
        self.release()
