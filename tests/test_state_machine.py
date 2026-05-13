"""Tests for AuthState and state machine transitions."""

from wisedu_cas.state import AuthState


class TestAuthState:
    def test_all_states_defined(self) -> None:
        states = {s.value for s in AuthState}
        assert states == {"ok", "suspect", "expired", "backoff", "circuit_open"}

    def test_str_returns_value(self) -> None:
        assert str(AuthState.OK) == "ok"
        assert str(AuthState.CIRCUIT_OPEN) == "circuit_open"

    def test_equality(self) -> None:
        assert AuthState.OK == AuthState.OK
        assert AuthState.OK != AuthState.SUSPECT

    def test_is_not_truthy_for_comparison(self) -> None:
        # States with different values are distinct
        assert AuthState("ok") == AuthState.OK
