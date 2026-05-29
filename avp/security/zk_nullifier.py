"""
Layer 4 — ZK Nullifier Registry.
Backed by SQLite via avp.db.
"""
from __future__ import annotations
import hashlib
import os

_SALT = os.environ.get("AVP_NULLIFIER_SALT", "avp-nullifier-salt-v1")


def compute_nullifier(wallet_address: str) -> str:
    raw = f"{wallet_address.lower()}:{_SALT}"
    return hashlib.sha256(raw.encode()).hexdigest()


def register_nullifier(wallet_address: str) -> tuple[bool, str]:
    from avp.db import insert_nullifier
    nullifier = compute_nullifier(wallet_address)
    ok = insert_nullifier(nullifier, wallet_address)
    return ok, nullifier


def is_nullifier_registered(wallet_address: str) -> bool:
    from avp.db import nullifier_exists
    return nullifier_exists(compute_nullifier(wallet_address))


def revoke_nullifier(wallet_address: str) -> bool:
    from avp.db import delete_nullifier
    return delete_nullifier(compute_nullifier(wallet_address))
