"""
AES-CBC password encryption matching the Wisedu AuthServer frontend ``encrypt.js``.

The encryption scheme:
    1. Generate a 64-char random prefix and a 16-char random IV.
    2. Concatenate: ``random_prefix + plaintext_password``.
    3. Encrypt with AES-CBC using the provided salt as key and random IV.
    4. Base64-encode the ciphertext.
"""

import base64
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

_AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"


def _random_string(length: int) -> str:
    return "".join(secrets.choice(_AES_CHARS) for _ in range(length))


def encrypt_password(password: str, salt: str) -> str:
    """Encrypt a password using the Wisedu AES-CBC scheme.

    Args:
        password: The plain-text password.
        salt: The ``pwdEncryptSalt`` value extracted from the CAS login page.

    Returns:
        Base64-encoded ciphertext string ready for form submission.

    If *salt* is empty, the *password* is returned unchanged.
    """
    if not salt:
        return password
    random_prefix = _random_string(64)
    random_iv = _random_string(16)
    data = (random_prefix + password).encode("utf-8")
    key = salt.strip().encode("utf-8")
    iv = random_iv.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")
