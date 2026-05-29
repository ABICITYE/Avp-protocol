"""
AVP — Agent Verification Protocol
Data models using stdlib dataclasses (no Pydantic required for core logic).
FastAPI integration uses Pydantic — see api.py for schema classes.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time
import uuid


class Chain(str, Enum):
    ETHEREUM = "ethereum"
    POLYGON  = "polygon"
    SOLANA   = "solana"
    BSC      = "bsc"


class TrustTier(str, Enum):
    SOVEREIGN = "sovereign"
    VERIFIED  = "verified"
    BASIC     = "basic"
    UNTRUSTED = "untrusted"


@dataclass
class ChallengeRecord:
    challenge_id: str
    wallet_address: str
    chain: Chain
    message: str
    created_at: float
    expires_at: float
    used: bool = False

    @classmethod
    def create(cls, wallet_address: str, chain: Chain) -> "ChallengeRecord":
        now = time.time()
        cid = str(uuid.uuid4())
        message = (
            f"AVP Authentication\n"
            f"Wallet: {wallet_address}\n"
            f"Chain: {chain.value}\n"
            f"Nonce: {cid[:8]}\n"
            f"Timestamp: {int(now)}\n"
            f"This signature proves wallet ownership."
        )
        return cls(
            challenge_id=cid,
            wallet_address=wallet_address,
            chain=chain,
            message=message,
            created_at=now,
            expires_at=now + 300,
        )

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class ChallengeResponse:
    challenge_id: str
    message: str
    expires_at: float
    chain: Chain


@dataclass
class OperatorRecord:
    operator_id: str
    stake_amount: float = 0.0
    slash_count: int = 0
    verified_count: int = 0
    trust_multiplier: float = 1.0

    def model_dump(self):
        return {
            "operator_id": self.operator_id,
            "stake_amount": self.stake_amount,
            "slash_count": self.slash_count,
            "verified_count": self.verified_count,
            "trust_multiplier": self.trust_multiplier,
        }


@dataclass
class NullifierRecord:
    nullifier_hash: str
    wallet_address: str
    registered_at: float


@dataclass
class VerifyResponse:
    success: bool
    wallet_address: str
    trust_score: int
    trust_tier: TrustTier
    permissions: list
    jwt_token: Optional[str] = None
    error: Optional[str] = None

# ─── FastAPI request/response schemas ───

@dataclass
class ChallengeRequest:
    wallet_address: str
    chain: Chain

@dataclass 
class VerifyRequest:
    challenge_id: str
    wallet_address: str
    chain: Chain
    signature: str
    operator_id: str = None
    device_fingerprint: str = None

@dataclass
class TokenValidationResponse:
    valid: bool
    wallet_address: str = None
    trust_tier: str = None
    permissions: list = None
    error: str = None
