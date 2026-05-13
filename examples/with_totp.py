#!/usr/bin/env python3
"""
TOTP 2FA login example — authenticate with username/password + TOTP secret.

Usage:
    python examples/with_totp.py

The TOTP secret should be a Base32 string from your authenticator app.
Set it via CAS_TOTP_SECRET environment variable.
"""

import asyncio
import os

from wisedu_cas import AuthClient, AuthSession, TotpRequiredError


async def main() -> None:
    client = AuthClient(
        auth_server=os.getenv("AUTH_SERVER", "https://authserver.example.edu.cn"),
        target_service=os.getenv("TARGET_SERVICE", "https://target.example.edu.cn"),
        username=os.getenv("CAS_USERNAME", "your_username"),
        password=os.getenv("CAS_PASSWORD", "your_password"),
        totp_secret=os.getenv("CAS_TOTP_SECRET", ""),
    )

    try:
        session: AuthSession = await client.login()
        print("Login with TOTP succeeded!")
        print(f"Cookies: {session.cookies_dict()}")

    except TotpRequiredError:
        print(
            "2FA is required but no TOTP secret was configured. "
            "Set CAS_TOTP_SECRET to your Base32 key."
        )
    except Exception as e:
        print(f"Login failed: {type(e).__name__}: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
