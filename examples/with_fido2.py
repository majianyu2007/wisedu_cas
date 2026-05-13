#!/usr/bin/env python3
"""
FIDO2/Passkey login example — authenticate with a pre-extracted WebAuthn credential.

Usage:
    python examples/with_fido2.py

Requires a FIDO2 credential JSON file. The credential must contain an ECDSA P-256
private key (keyValue), a credential ID (credentialId), a Relying Party ID (rpId),
and optionally a deviceBindingId for Wisedu AuthServer.

Set the credential file path via FIDO2_CREDENTIAL_FILE env variable,
or hardcode it below.
"""

import asyncio
import json
import os

from wisedu_cas import AuthClient, AuthSession, Fido2Credential


def load_credential(path: str) -> Fido2Credential:
    """Load a FIDO2 credential from a JSON file."""
    with open(path, "r") as f:
        data = json.load(f)
    return Fido2Credential.from_dict(data)


async def main() -> None:
    # Load credential
    cred_path = os.getenv("FIDO2_CREDENTIAL_FILE", "./fido2_credential.json")
    try:
        cred = load_credential(cred_path)
    except FileNotFoundError:
        print(f"Credential file not found: {cred_path}")
        print("Export your passkey from a browser extension and save as JSON.")
        return

    client = AuthClient(
        auth_server=os.getenv("AUTH_SERVER", "https://authserver.example.edu.cn"),
        target_service=os.getenv("TARGET_SERVICE", "https://target.example.edu.cn"),
        username=os.getenv("CAS_USERNAME", "your_username"),
        password=os.getenv("CAS_PASSWORD", "your_password"),
        auth_method="fido2",
        fido2_credential=cred,
    )

    try:
        session: AuthSession = await client.login()
        print("FIDO2 login succeeded!")
        print(f"Cookies: {list(session.cookies_dict().keys())}")
        print(f"Auth headers: {list(session.auth_headers().keys())}")
    except Exception as e:
        print(f"Login failed: {type(e).__name__}: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
