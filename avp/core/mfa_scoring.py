"""
Layer 2 — Multi-factor trust scoring.
Wallet history backed by SQLite via avp.db.
"""
from __future__ import annotations
from avp.models import OperatorRecord
from avp.db import get_wallet_verify_count, increment_wallet_history


def compute_trust_score(
    wallet_address: str,
    operator: OperatorRecord | None,
    device_fingerprint: str | None,
) -> int:
    score = 40

    if operator is not None:
        if operator.stake_amount > 0:
            score += 15
        total_ops = operator.verified_count + operator.slash_count
        if total_ops > 0 and (operator.slash_count / total_ops) < 0.05:
            score += 10
        if operator.trust_multiplier >= 1.5:
            score += 15

    if device_fingerprint:
        score += 10

    history = get_wallet_verify_count(wallet_address)
    if history > 0:
        score += min(10, history * 2)

    return min(100, score)


def record_successful_verification(wallet_address: str) -> None:
    increment_wallet_history(wallet_address)
