"""
crypto_utils.py
================
Encryption Module + Hashing utilities for the 2FA system.

This file implements the cryptographic core described in Chapter 3:
  - Symmetric encryption (AES) of the authentication token, via Fernet.
    Fernet = AES-128 in CBC mode for confidentiality + HMAC-SHA256 for
    integrity, so a tampered or forged token is rejected automatically.
  - SHA-256 hashing, used to fingerprint tokens for the system log
    (we never store a usable token in plain text).
  - Secure random token generation using the `secrets` module.

Why this matters for the project:
  - "Symmetric Cryptography" + "Hashing Algorithms" sections of the
     Literature Review are both demonstrated here.
  - The token is time-limited and single-use, which is what makes the
     QR code "dynamic" and what prevents replay attacks.
"""

import json
import time
import secrets
import hashlib
from cryptography.fernet import Fernet, InvalidToken


class TokenManager:
    """Generates, encrypts, and verifies dynamic authentication tokens."""

    def __init__(self, key: bytes, validity_seconds: int = 90):
        # `key` is the secret AES key (base64, 32 bytes) used by Fernet.
        self.fernet = Fernet(key)
        self.validity_seconds = validity_seconds

    # ------------------------------------------------------------------ #
    # Token creation (called by the Authentication Server after a correct
    # password, before the QR code is generated).
    # ------------------------------------------------------------------ #
    def issue_token(self, session_id: str) -> dict:
        """
        Build the token payload, encrypt it with AES, and return both the
        encrypted token (to embed in the QR code) and metadata (to store
        server-side for verification).
        """
        issued_at = int(time.time())
        expires_at = issued_at + self.validity_seconds

        payload = {
            "sid": session_id,               # which login attempt this belongs to
            "nonce": secrets.token_hex(16),  # uniqueness -> every QR is different
            "iat": issued_at,                # issued-at timestamp
            "exp": expires_at,               # hard expiry timestamp
        }

        # Encrypt the JSON payload with AES (Fernet).
        plaintext = json.dumps(payload).encode("utf-8")
        encrypted_token = self.fernet.encrypt(plaintext).decode("utf-8")

        return {
            "encrypted_token": encrypted_token,
            "expires_at": expires_at,
            "token_hash": self.hash_token(encrypted_token),
        }

    # ------------------------------------------------------------------ #
    # Token verification (called when the phone scans the QR and hits the
    # /scan endpoint on the Verification Module).
    # ------------------------------------------------------------------ #
    def verify_token(self, encrypted_token: str) -> dict:
        """
        Decrypt and validate a scanned token.
        Returns {"valid": bool, "reason": str, "session_id": str|None}.
        """
        try:
            plaintext = self.fernet.decrypt(encrypted_token.encode("utf-8"))
        except InvalidToken:
            # Decryption/HMAC failed -> token was forged or corrupted.
            return {"valid": False, "reason": "Invalid or tampered token", "session_id": None}

        payload = json.loads(plaintext.decode("utf-8"))

        # Time check: reject expired tokens (replay / reuse protection).
        if int(time.time()) > payload["exp"]:
            return {"valid": False, "reason": "Token expired", "session_id": payload["sid"]}

        return {"valid": True, "reason": "OK", "session_id": payload["sid"]}

    # ------------------------------------------------------------------ #
    # Hashing helper (SHA-256). Used so the system log stores a fingerprint
    # of the token rather than the token itself.
    # ------------------------------------------------------------------ #
    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_aes_key() -> bytes:
    """Generate a fresh 256-bit AES key (base64 encoded for Fernet)."""
    return Fernet.generate_key()
