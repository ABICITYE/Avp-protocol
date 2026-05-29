"""
Layer 3 — Adaptive rate limiting.
Penalties backed by SQLite. Sliding window still in-memory (per-process).
"""
from __future__ import annotations
import threading
import time
from collections import deque
from avp.db import get_penalty_until, set_penalty, clear_penalty

_WINDOW = 60
_LIMIT_UNKNOWN = 5
_LIMIT_KNOWN = 20

_windows: dict[str, deque] = {}
_lock = threading.Lock()


def check_rate_limit(wallet_address: str, is_known: bool = False) -> tuple[bool, str]:
    key = wallet_address.lower()
    now = time.time()

    # DB-backed penalty check
    penalty_until = get_penalty_until(key)
    if now < penalty_until:
        wait = round(penalty_until - now, 1)
        return False, f"Rate limited: retry in {wait}s"

    with _lock:
        if key not in _windows:
            _windows[key] = deque()
        window = _windows[key]
        while window and window[0] < now - _WINDOW:
            window.popleft()
        limit = _LIMIT_KNOWN if is_known else _LIMIT_UNKNOWN
        if len(window) >= limit:
            return False, f"Too many requests: limit is {limit} per {_WINDOW}s"
        window.append(now)

    return True, "ok"


def record_failed_attempt(wallet_address: str) -> None:
    key = wallet_address.lower()
    now = time.time()
    current = get_penalty_until(key)
    current_wait = max(0, current - now)
    new_wait = min(600, max(5, current_wait * 5 or 5))
    set_penalty(key, now + new_wait)


def clear_penalties(wallet_address: str) -> None:
    clear_penalty(wallet_address.lower())
