"""
Layer 3 — Operator staking & slashing.
Backed by SQLite via avp.db.
"""
from __future__ import annotations
from avp.models import OperatorRecord
from avp.db import upsert_operator, get_operator_row, record_operator_verification

_MIN_STAKE = 0.1


def register_operator(operator_id: str, stake_amount: float) -> OperatorRecord:
    row = upsert_operator(operator_id, stake_amount)
    return _row_to_model(row)


def get_operator(operator_id: str) -> OperatorRecord | None:
    row = get_operator_row(operator_id)
    return _row_to_model(row) if row else None


def record_verification(operator_id: str, success: bool) -> None:
    record_operator_verification(operator_id, success)


def is_operator_active(operator_id: str) -> bool:
    row = get_operator_row(operator_id)
    return row is not None and row["stake_amount"] >= _MIN_STAKE


def _row_to_model(row: dict) -> OperatorRecord:
    return OperatorRecord(
        operator_id=row["operator_id"],
        stake_amount=row["stake_amount"],
        slash_count=row["slash_count"],
        verified_count=row["verified_count"],
        trust_multiplier=row["trust_multiplier"],
    )
