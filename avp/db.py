"""
AVP — SQLite persistence layer.

Single file, single connection pool.
All tables are created on first import.
Set AVP_DB_PATH env var to override default location.
"""
from __future__ import annotations
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("AVP_DB_PATH", "avp.db")

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """One connection per thread, reused across calls."""
    if not hasattr(_local, "conn") or _local.conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


@contextmanager
def tx():
    """Context manager that commits on exit, rolls back on exception."""
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    """Create all tables if they don't exist. Safe to call multiple times."""
    with tx() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS challenges (
            challenge_id  TEXT PRIMARY KEY,
            wallet_address TEXT NOT NULL,
            chain          TEXT NOT NULL,
            message        TEXT NOT NULL,
            created_at     REAL NOT NULL,
            expires_at     REAL NOT NULL,
            used           INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS nullifiers (
            nullifier_hash TEXT PRIMARY KEY,
            wallet_address TEXT NOT NULL,
            registered_at  REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS operators (
            operator_id      TEXT PRIMARY KEY,
            stake_amount     REAL NOT NULL DEFAULT 0,
            slash_count      INTEGER NOT NULL DEFAULT 0,
            verified_count   INTEGER NOT NULL DEFAULT 0,
            trust_multiplier REAL NOT NULL DEFAULT 1.0
        );

        CREATE TABLE IF NOT EXISTS rate_penalties (
            wallet_address TEXT PRIMARY KEY,
            penalty_until  REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wallet_history (
            wallet_address TEXT PRIMARY KEY,
            verify_count   INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_challenges_wallet
            ON challenges(wallet_address);
        CREATE INDEX IF NOT EXISTS idx_challenges_expires
            ON challenges(expires_at);
        """)


# ─────────────────────────────────────────────
# Challenge helpers
# ─────────────────────────────────────────────

def insert_challenge(c) -> None:
    with tx() as conn:
        conn.execute(
            """INSERT INTO challenges
               (challenge_id, wallet_address, chain, message, created_at, expires_at, used)
               VALUES (?,?,?,?,?,?,0)""",
            (c.challenge_id, c.wallet_address, c.chain.value,
             c.message, c.created_at, c.expires_at),
        )


def fetch_and_consume_challenge(challenge_id: str, wallet_address: str):
    """
    Returns the row if valid, unused, and not expired — and marks it used.
    Returns None otherwise.
    """
    now = time.time()
    with tx() as conn:
        row = conn.execute(
            "SELECT * FROM challenges WHERE challenge_id=?", (challenge_id,)
        ).fetchone()
        if row is None:
            return None
        if row["used"] or row["expires_at"] < now:
            return None
        if row["wallet_address"].lower() != wallet_address.lower():
            return None
        conn.execute(
            "UPDATE challenges SET used=1 WHERE challenge_id=?", (challenge_id,)
        )
        # Evict old expired rows while we're here
        conn.execute("DELETE FROM challenges WHERE expires_at < ?", (now - 3600,))
        return row


# ─────────────────────────────────────────────
# Nullifier helpers
# ─────────────────────────────────────────────

def insert_nullifier(nullifier_hash: str, wallet_address: str) -> bool:
    """Returns True if inserted, False if already exists."""
    try:
        with tx() as conn:
            conn.execute(
                "INSERT INTO nullifiers (nullifier_hash, wallet_address, registered_at) VALUES (?,?,?)",
                (nullifier_hash, wallet_address.lower(), time.time()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def nullifier_exists(nullifier_hash: str) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT 1 FROM nullifiers WHERE nullifier_hash=?", (nullifier_hash,)
    ).fetchone()
    return row is not None


def delete_nullifier(nullifier_hash: str) -> bool:
    with tx() as conn:
        cur = conn.execute(
            "DELETE FROM nullifiers WHERE nullifier_hash=?", (nullifier_hash,)
        )
        return cur.rowcount > 0


# ─────────────────────────────────────────────
# Operator helpers
# ─────────────────────────────────────────────

def upsert_operator(operator_id: str, extra_stake: float) -> dict:
    with tx() as conn:
        conn.execute(
            """INSERT INTO operators (operator_id, stake_amount)
               VALUES (?, ?)
               ON CONFLICT(operator_id) DO UPDATE
               SET stake_amount = stake_amount + excluded.stake_amount""",
            (operator_id, extra_stake),
        )
        row = conn.execute(
            "SELECT * FROM operators WHERE operator_id=?", (operator_id,)
        ).fetchone()
        return dict(row)


def get_operator_row(operator_id: str) -> dict | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM operators WHERE operator_id=?", (operator_id,)
    ).fetchone()
    return dict(row) if row else None


def record_operator_verification(operator_id: str, success: bool) -> None:
    with tx() as conn:
        if success:
            conn.execute(
                """UPDATE operators
                   SET verified_count = verified_count + 1,
                       trust_multiplier = MIN(3.0,
                           CASE WHEN (verified_count + 1) % 10 = 0
                                THEN trust_multiplier + 0.1
                                ELSE trust_multiplier END)
                   WHERE operator_id=?""",
                (operator_id,),
            )
        else:
            conn.execute(
                """UPDATE operators
                   SET slash_count    = slash_count + 1,
                       stake_amount   = MAX(0, stake_amount - stake_amount * 0.10),
                       trust_multiplier = MAX(0.5, trust_multiplier - 0.2)
                   WHERE operator_id=?""",
                (operator_id,),
            )


# ─────────────────────────────────────────────
# Rate limiter helpers
# ─────────────────────────────────────────────

def get_penalty_until(wallet_address: str) -> float:
    conn = _get_conn()
    row = conn.execute(
        "SELECT penalty_until FROM rate_penalties WHERE wallet_address=?",
        (wallet_address.lower(),),
    ).fetchone()
    return row["penalty_until"] if row else 0.0


def set_penalty(wallet_address: str, until: float) -> None:
    with tx() as conn:
        conn.execute(
            """INSERT INTO rate_penalties (wallet_address, penalty_until)
               VALUES (?, ?)
               ON CONFLICT(wallet_address) DO UPDATE
               SET penalty_until = excluded.penalty_until""",
            (wallet_address.lower(), until),
        )


def clear_penalty(wallet_address: str) -> None:
    with tx() as conn:
        conn.execute(
            "DELETE FROM rate_penalties WHERE wallet_address=?",
            (wallet_address.lower(),),
        )


# ─────────────────────────────────────────────
# Wallet history helpers
# ─────────────────────────────────────────────

def increment_wallet_history(wallet_address: str) -> None:
    with tx() as conn:
        conn.execute(
            """INSERT INTO wallet_history (wallet_address, verify_count)
               VALUES (?, 1)
               ON CONFLICT(wallet_address) DO UPDATE
               SET verify_count = verify_count + 1""",
            (wallet_address.lower(),),
        )


def get_wallet_verify_count(wallet_address: str) -> int:
    conn = _get_conn()
    row = conn.execute(
        "SELECT verify_count FROM wallet_history WHERE wallet_address=?",
        (wallet_address.lower(),),
    ).fetchone()
    return row["verify_count"] if row else 0


# Initialise on import
init_db()
