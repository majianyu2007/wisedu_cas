#!/usr/bin/env python3
"""
Auto auth method example — try FIDO2 first, fall back to password+TOTP.

Usage:
    python examples/auto_auth_method.py

In "auto" mode, the library will:
  1. Attempt FIDO2/passkey login if a valid credential is configured.
  2. Fall back to password + AES + optional TOTP on any FIDO2 failure.

This provides the best of both worlds: faster, phishing-resistant FIDO2 when
available, with a transparent fallback to password authentication.
"""

import asyncio
import json
import os

from wisedu_cas import AuthClient, AuthSession, Fido2Credential


async def main() -> None:
    # Load optional FIDO2 credential
    cred = None
    cred_path = os.getenv("FIDO2_CREDENTIAL_FILE", "./fido2_credential.json")
    try:
        with open(cred_path, "r") as f:
            data = json.load(f)
        cred = Fido2Credential.from_dict(data)
        print(f"FIDO2 credential loaded: rpId={cred.rp_id}")
    except FileNotFoundError:
        print("No FIDO2 credential found — will use password only.")

    client = AuthClient(
        auth_server=os.getenv("AUTH_SERVER", "https://authserver.example.edu.cn"),
        target_service=os.getenv("TARGET_SERVICE", "https://target.example.edu.cn"),
        username=os.getenv("CAS_USERNAME", "your_username"),
        password=os.getenv("CAS_PASSWORD", "your_password"),
        totp_secret=os.getenv("CAS_TOTP_SECRET", ""),
        auth_method="auto",
        fido2_credential=cred,
    )

    try:
        session: AuthSession = await client.ensure_logged_in()
        print("Auth session ready!")
        print(f"State: {client.state.value}")
        print(f"Cookies: {list(session.cookies_dict().keys())}")
    except Exception as e:
        print(f"Login failed: {type(e).__name__}: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
