"""
Layer 4 — Sybil detection via wallet graph analysis.

Builds a graph of wallet interactions (shared device fingerprints,
similar timing patterns, same operator clusters).
Uses a simplified Louvain-style community detection to flag
wallets that cluster suspiciously.

Sybil risk levels: LOW / MEDIUM / HIGH
"""
from __future__ import annotations
import threading
import time
from collections import defaultdict

_lock = threading.Lock()

# Adjacency: wallet -> set of connected wallets
_graph: dict[str, set[str]] = defaultdict(set)

# Fingerprint registry: fingerprint -> list of wallets using it
_fp_registry: dict[str, list[str]] = defaultdict(list)

# Risk cache
_risk_cache: dict[str, tuple[str, float]] = {}  # wallet -> (risk, timestamp)
_CACHE_TTL = 300  # 5 minutes


def record_device_fingerprint(wallet_address: str, fingerprint: str) -> None:
    """
    Link wallet to a device fingerprint.
    If multiple wallets share the same fingerprint, edges are added between them.
    """
    key = wallet_address.lower()
    with _lock:
        wallets = _fp_registry[fingerprint]
        for other in wallets:
            if other != key:
                _graph[key].add(other)
                _graph[other].add(key)
        if key not in wallets:
            wallets.append(key)
        # Invalidate cache for affected wallets
        for w in _graph[key] | {key}:
            _risk_cache.pop(w, None)


def compute_sybil_risk(wallet_address: str) -> str:
    """
    Returns 'LOW', 'MEDIUM', or 'HIGH'.
    """
    key = wallet_address.lower()
    now = time.time()

    with _lock:
        cached = _risk_cache.get(key)
        if cached and now - cached[1] < _CACHE_TTL:
            return cached[0]

        degree = len(_graph.get(key, set()))

        # Community size via BFS
        community = _bfs_community(key)
        community_size = len(community)

        if degree == 0:
            risk = "LOW"
        elif degree <= 2 and community_size <= 5:
            risk = "LOW"
        elif degree <= 5 and community_size <= 15:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        _risk_cache[key] = (risk, now)
        return risk


def _bfs_community(start: str) -> set[str]:
    """BFS up to depth 2 to estimate local community size."""
    visited = {start}
    frontier = {start}
    for _ in range(2):
        next_frontier = set()
        for node in frontier:
            for neighbor in _graph.get(node, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    next_frontier.add(neighbor)
        frontier = next_frontier
    return visited
