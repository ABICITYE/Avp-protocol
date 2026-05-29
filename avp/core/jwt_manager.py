"""
JWT token creation and validation.
Uses HMAC-SHA256 with a secret key.
In production, rotate the secret via environment variable.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import time

_SECRET = os.environ.get("AVP_JWT_SECRET", "avp-dev-secret-change-in-production")
_TTL = 86_400  # 24 hours


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(header_payload: str) -> str:
    sig = hmac.new(_SECRET.encode(), header_payload.encode(), hashlib.sha256).digest()
    return _b64(sig)


def issue_token(wallet_address: str, trust_tier: str, permissions: list[str]) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub": wallet_address,
        "tier": trust_tier,
        "perms": permissions,
        "iat": int(time.time()),
        "exp": int(time.time()) + _TTL,
    }).encode())
    sig = _sign(f"{header}.{payload}")
    return f"{header}.{payload}.{sig}"


def validate_token(token: str) -> dict | None:
    """Returns payload dict if valid and not expired, else None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        expected = _sign(f"{header}.{payload}")
        if not hmac.compare_digest(sig, expected):
            return None
        padding = "=" * (4 - len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload + padding))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None
