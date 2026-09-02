"""Password hashing and JWT handling.

Passwords are stored as PBKDF2-HMAC-SHA256 digests with a per-user random salt
(the same construction Django uses by default). Plaintext passwords are never
stored, logged or returned by the API. Argon2id is the intended V2 upgrade.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.core.config import settings

PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 390_000
SALT_BYTES = 16


class TokenError(Exception):
    """Raised when a token is missing, malformed or expired."""


def hash_password(password: str) -> str:
    """Return an encoded password hash: ``pbkdf2_sha256$iterations$salt$hash``."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "$".join(
        [
            PBKDF2_ALGORITHM,
            str(PBKDF2_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, encoded: str | None) -> bool:
    """Constant-time verification of a password against an encoded hash."""
    if not encoded:
        return False
    try:
        algorithm, iterations, salt_b64, digest_b64 = encoded.split("$")
        if algorithm != PBKDF2_ALGORITHM:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    return hmac.compare_digest(candidate, expected)


def create_access_token(subject: str, *, extra_claims: dict[str, Any] | None = None) -> str:
    """Issue a signed HS256 access token for ``subject`` (the user id).

    Claims: ``sub``, ``iat``, ``nbf``, ``exp``, ``iss``, ``type``, ``jti`` and
    ``tv`` (the user's token version). ``jti`` gives every token an identity for
    audit correlation; ``tv`` is what makes bulk revocation possible without a
    server-side session store.
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_expire_minutes)).timestamp()),
        "iss": "aegisx",
        "type": "access",
        "jti": secrets.token_urlsafe(12),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a token, raising :class:`TokenError` when invalid."""
    if not token:
        raise TokenError("Missing token")
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer="aegisx",
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Invalid token") from exc

    if payload.get("type") != "access":
        raise TokenError("Unexpected token type")
    return payload
