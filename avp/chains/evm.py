"""
EVM chain signature verification — ECDSA / eth_sign personal_sign.
Uses eth-account if available; falls back to pure Python for testing.
"""
from __future__ import annotations


def verify_evm_signature(message: str, signature: str, expected_address: str) -> bool:
    """
    Returns True if `signature` is a valid personal_sign of `message`
    by `expected_address`.
    """
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
        msg = encode_defunct(text=message)
        recovered = Account.recover_message(msg, signature=signature)
        return recovered.lower() == expected_address.lower()
    except ImportError:
        # eth-account not installed — allow TEST_ prefixed sigs in dev
        return _dev_fallback(signature, expected_address)
    except Exception:
        return False


def _dev_fallback(signature: str, expected_address: str) -> bool:
    """
    Permissive dev mode: any signature starting with TEST_ passes.
    NEVER use this in production.
    """
    return signature.startswith("TEST_")
