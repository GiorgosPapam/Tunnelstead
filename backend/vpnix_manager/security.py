"""Cryptographic primitives. Nothing in this module logs or returns secret material."""
import base64
import hashlib
import hmac
import os
import secrets

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings

_ph = PasswordHasher()  # Argon2id with RFC 9106 low-memory defaults
_DUMMY = _ph.hash("constant-time-equalizer")
MIN_PASSWORD = 12
MAX_PASSWORD = 256


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, h: str | None) -> bool:
    """Always does the full Argon2 work, even for unknown users (no timing oracle)."""
    try:
        ok = _ph.verify(h or _DUMMY, pw)
    except (VerificationError, InvalidHashError):
        return False
    return ok and h is not None


def password_problem(pw: str, username: str = "") -> str | None:
    if len(pw) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters"
    if len(pw) > MAX_PASSWORD:
        return "Password is too long"
    if username and username.lower() in pw.lower():
        return "Password must not contain the username"
    if len(set(pw)) < 5:
        return "Password is too repetitive"
    return None


def generate_password(nbytes: int = 18) -> str:
    return secrets.token_urlsafe(nbytes)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _key() -> bytes:
    raw = base64.urlsafe_b64decode(get_settings().secret_key + "==")
    if len(raw) != 32:
        raise RuntimeError("VPNIX_SECRET_KEY must be 32 bytes (base64url)")
    return raw


def encrypt(plaintext: str, context: str) -> str:
    """AES-256-GCM; `context` is bound as associated data so ciphertext cannot be moved between rows."""
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, plaintext.encode(), context.encode())
    return "v1:" + base64.b64encode(nonce + ct).decode()


def decrypt(blob: str, context: str) -> str:
    if not blob.startswith("v1:"):
        raise ValueError("unknown ciphertext version")
    raw = base64.b64decode(blob[3:])
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], context.encode()).decode()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def recovery_codes(n: int = 10) -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return ["-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)) for _ in range(n)]
