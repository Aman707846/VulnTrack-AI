import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from backend.app.core.config import (
    JWT_ACCESS_TOKEN_EXPIRES_MINUTES,
    JWT_ALGORITHM,
    JWT_REFRESH_TOKEN_EXPIRES_DAYS,
    JWT_SECRET_KEY,
)


ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    return f"{salt}${password_hash.hex()}"


def verify_password(password: str, stored_password_hash: str) -> bool:
    salt, expected_hash = stored_password_hash.split("$", maxsplit=1)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    return hmac.compare_digest(password_hash.hex(), expected_hash)


def _base64url_encode(raw_value: bytes) -> str:
    return base64.urlsafe_b64encode(raw_value).rstrip(b"=").decode("ascii")


def _base64url_decode(encoded_value: str) -> bytes:
    padding = "=" * (-len(encoded_value) % 4)
    return base64.urlsafe_b64decode(encoded_value + padding)


def _create_token(payload: dict[str, Any], expires_seconds: int) -> str:
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    now = int(time.time())
    expires_at = now + expires_seconds
    claims = dict(payload)
    claims.setdefault("iat", now)
    claims["exp"] = expires_at

    encoded_header = _base64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    encoded_payload = _base64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_base64url_encode(signature)}"


def create_access_token(payload: dict[str, Any], expires_minutes: int | None = None) -> str:
    expires_seconds = 60 * (expires_minutes or JWT_ACCESS_TOKEN_EXPIRES_MINUTES)
    return _create_token(payload, expires_seconds)


def create_refresh_token(payload: dict[str, Any], expires_days: int | None = None) -> str:
    expires_seconds = 24 * 60 * 60 * (expires_days or JWT_REFRESH_TOKEN_EXPIRES_DAYS)
    return _create_token(payload, expires_seconds)


def decode_token(token: str, *, verify_exp: bool = True) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise ValueError("Invalid token format.") from exc

    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    expected_signature = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    received_signature = _base64url_decode(encoded_signature)
    if not hmac.compare_digest(expected_signature, received_signature):
        raise ValueError("Invalid token signature.")

    header = json.loads(_base64url_decode(encoded_header).decode("utf-8"))
    if header.get("alg") != JWT_ALGORITHM:
        raise ValueError("Unsupported token algorithm.")

    payload = json.loads(_base64url_decode(encoded_payload).decode("utf-8"))
    expires_at = int(payload.get("exp") or 0)
    if verify_exp and expires_at and expires_at < int(time.time()):
        raise ValueError("Token has expired.")

    return payload


def decode_access_token(token: str) -> dict[str, Any]:
    return decode_token(token)


def decode_refresh_token(token: str) -> dict[str, Any]:
    return decode_token(token)
