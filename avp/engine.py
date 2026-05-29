"""
AVP Verification Engine — orchestrates all 4 layers.

Flow:
  1. Rate limit check  (Layer 3 — middleware)
  2. Consume challenge (Layer 1 — challenge store)
  3. Verify signature  (Layer 1 — chain-specific)
  4. Sybil check       (Layer 4 — graph detector)
  5. ZK nullifier      (Layer 4 — replay prevention)
  6. Trust scoring     (Layer 2 — MFA)
  7. Issue JWT         (Layer 2 — jwt_manager)
  8. Update operator   (Layer 3 — staking)
"""
from __future__ import annotations
from avp.models import Chain, VerifyResponse
from avp.core.challenge import consume_challenge
from avp.core.mfa_scoring import compute_trust_score, record_successful_verification
from avp.core.trust_tiers import score_to_tier, tier_permissions
from avp.core.jwt_manager import issue_token
from avp.chains.evm import verify_evm_signature
from avp.chains.solana import verify_solana_signature
from avp.middleware.rate_limiter import check_rate_limit, record_failed_attempt, clear_penalties
from avp.security.staking import get_operator, record_verification
from avp.security.sybil_detector import record_device_fingerprint, compute_sybil_risk
from avp.security.zk_nullifier import register_nullifier, is_nullifier_registered

_EVM_CHAINS = {Chain.ETHEREUM, Chain.POLYGON, Chain.BSC}


def run_verification(
    challenge_id: str,
    wallet_address: str,
    chain: Chain,
    signature: str,
    operator_id: str | None = None,
    device_fingerprint: str | None = None,
) -> VerifyResponse:

    wallet = wallet_address.strip()

    # ── Layer 3: Rate limit ──────────────────────────────────────────────
    already_seen = is_nullifier_registered(wallet)
    allowed, reason = check_rate_limit(wallet, is_known=already_seen)
    if not allowed:
        return VerifyResponse(
            success=False, wallet_address=wallet,
            trust_score=0, trust_tier="untrusted",
            permissions=[], error=reason,
        )

    # ── Layer 1: Consume challenge ───────────────────────────────────────
    record = consume_challenge(challenge_id, wallet)
    if record is None:
        record_failed_attempt(wallet)
        return VerifyResponse(
            success=False, wallet_address=wallet,
            trust_score=0, trust_tier="untrusted",
            permissions=[], error="Invalid or expired challenge",
        )

    # ── Layer 1: Signature verification ─────────────────────────────────
    if chain in _EVM_CHAINS:
        sig_ok = verify_evm_signature(record.message, signature, wallet)
    elif chain == Chain.SOLANA:
        sig_ok = verify_solana_signature(record.message, signature, wallet)
    else:
        sig_ok = False

    if not sig_ok:
        record_failed_attempt(wallet)
        if operator_id:
            record_verification(operator_id, success=False)
        return VerifyResponse(
            success=False, wallet_address=wallet,
            trust_score=0, trust_tier="untrusted",
            permissions=[], error="Signature verification failed",
        )

    # ── Layer 4: Sybil check ─────────────────────────────────────────────
    if device_fingerprint:
        record_device_fingerprint(wallet, device_fingerprint)

    sybil_risk = compute_sybil_risk(wallet)
    if sybil_risk == "HIGH":
        return VerifyResponse(
            success=False, wallet_address=wallet,
            trust_score=0, trust_tier="untrusted",
            permissions=[], error="Sybil risk: HIGH — verification denied",
        )

    # ── Layer 4: ZK nullifier (idempotent — allow re-verification) ──────
    register_nullifier(wallet)  # no-op if already registered

    # ── Layer 2: Trust scoring ───────────────────────────────────────────
    operator = get_operator(operator_id) if operator_id else None
    score = compute_trust_score(wallet, operator, device_fingerprint)

    # Sybil MEDIUM reduces score
    if sybil_risk == "MEDIUM":
        score = max(0, score - 15)

    tier = score_to_tier(score)
    permissions = tier_permissions(tier)

    # ── Layer 2: JWT ─────────────────────────────────────────────────────
    token = issue_token(wallet, tier.value, permissions)

    # ── Cleanup / bookkeeping ────────────────────────────────────────────
    clear_penalties(wallet)
    record_successful_verification(wallet)
    if operator_id:
        record_verification(operator_id, success=True)

    return VerifyResponse(
        success=True,
        wallet_address=wallet,
        trust_score=score,
        trust_tier=tier,
        permissions=permissions,
        jwt_token=token,
    )
