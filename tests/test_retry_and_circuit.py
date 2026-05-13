"""Tests for rate limiting, backoff, and circuit breaker."""

import time

import pytest

from wisedu_cas.exceptions import CircuitOpenError
from wisedu_cas.retry import (
    BackoffCalculator,
    CircuitBreaker,
    RateLimiter,
    RetryConfig,
)
from wisedu_cas.state import AuthState


class TestRateLimiter:
    def test_allows_first_attempts(self) -> None:
        config = RetryConfig(max_logins_per_hour=3, login_window_seconds=3600)
        rl = RateLimiter(config)
        for _ in range(3):
            assert rl.check() is True
            rl.record()

    def test_blocks_after_limit(self) -> None:
        config = RetryConfig(max_logins_per_hour=2, login_window_seconds=3600)
        rl = RateLimiter(config)
        assert rl.check()
        rl.record()
        assert rl.check()
        rl.record()
        assert rl.check() is False

    def test_old_attempts_rotate_out(self) -> None:
        config = RetryConfig(max_logins_per_hour=2, login_window_seconds=3600)
        rl = RateLimiter(config)
        rl.record()
        rl.record()
        assert rl.check() is False
        # Simulate window expiry by clearing attempts directly
        rl._attempt_times = []
        assert rl.check() is True


class TestBackoffCalculator:
    def test_first_backoff_is_base(self) -> None:
        calc = BackoffCalculator(RetryConfig(backoff_base=5))
        calc.consecutive_failures = 1
        backoff = calc.compute()
        # With jitter, range is 3.75..7.5
        assert 3.0 <= backoff <= 7.5

    def test_backoff_grows_exponentially(self) -> None:
        calc = BackoffCalculator(RetryConfig(backoff_base=5, backoff_multiplier=4))
        calc.consecutive_failures = 3
        backoff = calc.compute()
        # raw = 5 * 4^2 = 80; jitter 60..120
        assert 50 <= backoff <= 120

    def test_respects_max(self) -> None:
        config = RetryConfig(backoff_base=5, backoff_max_normal=10)
        calc = BackoffCalculator(config)
        calc.consecutive_failures = 100
        backoff = calc.compute()
        # raw=HUGE capped at 10; jitter 7.5..15
        assert backoff <= 15

    def test_critical_uses_longer_max(self) -> None:
        config = RetryConfig(
            backoff_max_normal=10,
            backoff_max_critical=100,
        )
        calc = BackoffCalculator(config)
        calc.consecutive_failures = 100
        normal = calc.compute(is_critical=False)
        critical = calc.compute(is_critical=True)
        assert critical > normal

    def test_reset_clears_count(self) -> None:
        calc = BackoffCalculator(RetryConfig())
        calc.consecutive_failures = 5
        calc.reset()
        assert calc.consecutive_failures == 0


class TestCircuitBreaker:
    def test_initially_closed(self) -> None:
        cb = CircuitBreaker(RetryConfig())
        assert cb.is_open is False

    def test_open_sets_state(self) -> None:
        cb = CircuitBreaker(RetryConfig())
        cb.state = AuthState.EXPIRED
        cb.open(5, "test")
        assert cb.state == AuthState.CIRCUIT_OPEN
        assert cb.is_open is True
        assert cb.remaining > 0

    def test_expired_circuit_closes(self) -> None:
        cb = CircuitBreaker(RetryConfig())
        cb.state = AuthState.EXPIRED
        cb.open(10, "test")
        assert cb.is_open is True
        # Manually expire
        cb._circuit_until = time.monotonic() - 1
        assert cb.is_open is False
        assert cb.state == AuthState.EXPIRED

    def test_check_or_raise_when_open(self) -> None:
        cb = CircuitBreaker(RetryConfig())
        cb.state = AuthState.EXPIRED
        cb.open(3600, "test")
        assert cb.state == AuthState.CIRCUIT_OPEN
        with pytest.raises(CircuitOpenError) as exc:
            cb.check_or_raise()
        assert exc.value.retry_after > 0

    def test_check_or_raise_when_closed(self) -> None:
        cb = CircuitBreaker(RetryConfig())
        cb.check_or_raise()  # no exception
