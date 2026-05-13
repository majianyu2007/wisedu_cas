#!/usr/bin/env python3
"""
Basic login example — authenticate with username/password and print session cookies.

Usage:
    python examples/basic_login.py

Requires environment variables or edit the script to set credentials.
"""

import asyncio
import os

from wisedu_cas import AuthClient, AuthSession


async def main() -> None:
    client = AuthClient(
        auth_server=os.getenv("AUTH_SERVER", "https://authserver.example.edu.cn"),
        target_service=os.getenv("TARGET_SERVICE", "https://target.example.edu.cn"),
        username=os.getenv("CAS_USERNAME", "your_username"),
        password=os.getenv("CAS_PASSWORD", "your_password"),
    )

    try:
        session: AuthSession = await client.login()
        print("Login succeeded!")
        print(f"State: {client.state.value}")
        print(f"Session valid: {client.is_session_valid()}")
        print(f"Cookies: {session.cookies_dict()}")

        # Use auth_headers() to forward to the target service
        headers = session.auth_headers()
        print(f"Auth headers: {headers}")

    except Exception as e:
        print(f"Login failed: {type(e).__name__}: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
