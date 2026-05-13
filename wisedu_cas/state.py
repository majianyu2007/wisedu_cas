"""
Auth state machine for Wisedu CAS session lifecycle.

States:
    OK              — Session valid, normal operation.
    SUSPECT         — Anomaly detected (network error, upstream non-2xx)
                      but not confirmed as auth expiry. Does NOT trigger login.
    EXPIRED         — Definitive CAS login redirect detected.
                      Will trigger re-login through protection layers.
    LOGIN_BACKOFF   — Login failed, waiting for exponential backoff.
    CIRCUIT_OPEN    — Too many consecutive failures; login blocked
                      to protect the campus account.
"""

import enum


class AuthState(enum.Enum):
    OK = "ok"
    SUSPECT = "suspect"
    EXPIRED = "expired"
    LOGIN_BACKOFF = "backoff"
    CIRCUIT_OPEN = "circuit_open"

    def __str__(self) -> str:
        return self.value
