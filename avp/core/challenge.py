"""
Layer 1 — Challenge generation and management.
Backed by SQLite via avp.db.
"""
from __future__ import annotations
from avp.models import Chain, ChallengeRecord, ChallengeResponse
from avp.db import insert_challenge, fetch_and_consume_challenge


def create_challenge(wallet_address: str, chain: Chain) -> ChallengeResponse:
    record = ChallengeRecord.create(wallet_address, chain)
    insert_challenge(record)
    return ChallengeResponse(
        challenge_id=record.challenge_id,
        message=record.message,
        expires_at=record.expires_at,
        chain=record.chain,
    )


def consume_challenge(challenge_id: str, wallet_address: str) -> ChallengeRecord | None:
    row = fetch_and_consume_challenge(challenge_id, wallet_address)
    if row is None:
        return None
    return ChallengeRecord(
        challenge_id=row["challenge_id"],
        wallet_address=row["wallet_address"],
        chain=Chain(row["chain"]),
        message=row["message"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        used=True,
    )
