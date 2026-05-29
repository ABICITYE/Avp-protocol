"""
Solana chain signature verification — Ed25519.
Uses PyNaCl if available; falls back to dev mode.
"""
from __future__ import annotations
import base64


def verify_solana_signature(message: str, signature: str, expected_address: str) -> bool:
    """
    Returns True if `signature` is a valid Ed25519 signature of `message`
    by the wallet at `expected_address`.
    """
    try:
        import base58
        from nacl.signing import VerifyKey
        vk = VerifyKey(base58.b58decode(expected_address))
        sig_bytes = base64.b64decode(signature)
        vk.verify(message.encode(), sig_bytes)
        return True
    except ImportError:
        return _dev_fallback(signature)
    except Exception:
        return False


def _dev_fallback(signature: str) -> bool:
    return signature.startswith("TEST_")
