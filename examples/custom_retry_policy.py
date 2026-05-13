#!/usr/bin/env python3
"""
Custom retry policy example — tune backoff, circuit breaker, and rate limiting.

Usage:
    python examples/custom_retry_policy.py
"""

import asyncio
import os

from wisedu_cas import AuthClient, AuthSession
from wisedu_cas.retry import RetryConfig


async def main() -> None:
    # Customise all protection parameters
    config = RetryConfig(
        max_logins_per_hour=3,
        max_consecutive_failures=5,
        backoff_base=10,
        backoff_multiplier=3,
        backoff_max_normal=600,            # 10 min
        backoff_max_critical=7200,         # 2 hours
        circuit_normal_duration=1800,      # 30 min
        circuit_critical_duration=14400,   # 4 hours
        circuit_captcha_duration=3600,     # 1 hour
        circuit_password_error_duration=1800,  # 30 min
    )

    client = AuthClient(
        auth_server=os.getenv("AUTH_SERVER", "https://authserver.example.edu.cn"),
        target_service=os.getenv("TARGET_SERVICE", "https://target.example.edu.cn"),
        username=os.getenv("CAS_USERNAME", "your_username"),
        password=os.getenv("CAS_PASSWORD", "your_password"),
        totp_secret=os.getenv("CAS_TOTP_SECRET", ""),
        retry_config=config,
        http_timeout=30.0,
        http_connect_timeout=10.0,
        # Persist state across restarts
        storage_path="./.cas_state",
    )

    try:
        session: AuthSession = await client.ensure_logged_in()
        print(f"Session ready: {session.cookies_dict()}")
    except Exception as e:
        print(f"Login failed: {type(e).__name__}: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
