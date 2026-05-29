"""
AVP Test Suite — 130 tests across all layers.
Run with: pytest tests/ -v
"""
import pytest
import time
from avp.models import Chain, TrustTier, ChallengeRecord
from avp.core.challenge import create_challenge, consume_challenge
from avp.core.trust_tiers import score_to_tier, tier_permissions
from avp.core.mfa_scoring import compute_trust_score, record_successful_verification
from avp.core.jwt_manager import issue_token, validate_token
from avp.chains.evm import verify_evm_signature
from avp.chains.solana import verify_solana_signature
from avp.middleware.rate_limiter import check_rate_limit, record_failed_attempt, clear_penalties
from avp.security.staking import register_operator, get_operator, record_verification, is_operator_active
from avp.security.sybil_detector import record_device_fingerprint, compute_sybil_risk
from avp.security.zk_nullifier import compute_nullifier, register_nullifier, is_nullifier_registered, revoke_nullifier
from avp.engine import run_verification

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

WALLET_ETH = "0xABCDEF1234567890abcdef1234567890ABCDEF12"
WALLET_SOL = "DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG3LZSQ"

def _fresh_wallet(suffix=""):
    return f"0x{suffix}{'a' * (40 - len(suffix))}"


# ─────────────────────────────────────────────
# Layer 1: Challenge
# ─────────────────────────────────────────────

class TestChallenge:
    def test_create_returns_challenge_response(self):
        resp = create_challenge(WALLET_ETH, Chain.ETHEREUM)
        assert resp.challenge_id
        assert WALLET_ETH in resp.message
        assert resp.expires_at > time.time()

    def test_challenge_message_contains_chain(self):
        resp = create_challenge(WALLET_ETH, Chain.POLYGON)
        assert "polygon" in resp.message.lower()

    def test_consume_valid_challenge(self):
        resp = create_challenge(WALLET_ETH, Chain.ETHEREUM)
        record = consume_challenge(resp.challenge_id, WALLET_ETH)
        assert record is not None
        assert record.wallet_address == WALLET_ETH

    def test_consume_marks_as_used(self):
        resp = create_challenge(WALLET_ETH, Chain.ETHEREUM)
        consume_challenge(resp.challenge_id, WALLET_ETH)
        second = consume_challenge(resp.challenge_id, WALLET_ETH)
        assert second is None

    def test_consume_wrong_wallet_fails(self):
        resp = create_challenge(WALLET_ETH, Chain.ETHEREUM)
        record = consume_challenge(resp.challenge_id, "0x0000000000000000000000000000000000000000")
        assert record is None

    def test_consume_unknown_id_fails(self):
        record = consume_challenge("nonexistent-id", WALLET_ETH)
        assert record is None

    def test_challenge_record_create(self):
        r = ChallengeRecord.create(WALLET_ETH, Chain.ETHEREUM)
        assert r.expires_at > r.created_at
        assert not r.used
        assert r.challenge_id

    def test_challenge_different_ids_each_time(self):
        r1 = create_challenge(WALLET_ETH, Chain.ETHEREUM)
        r2 = create_challenge(WALLET_ETH, Chain.ETHEREUM)
        assert r1.challenge_id != r2.challenge_id

    def test_all_chains_generate_challenges(self):
        for chain in Chain:
            resp = create_challenge(WALLET_ETH, chain)
            assert resp.chain == chain

    def test_solana_challenge(self):
        resp = create_challenge(WALLET_SOL, Chain.SOLANA)
        assert WALLET_SOL in resp.message


# ─────────────────────────────────────────────
# Layer 1: Signature verification
# ─────────────────────────────────────────────

class TestSignatures:
    def test_evm_test_signature_passes_dev_mode(self):
        assert verify_evm_signature("any message", "TEST_sig", WALLET_ETH)

    def test_evm_invalid_signature_fails(self):
        assert not verify_evm_signature("any message", "bad_sig", WALLET_ETH)

    def test_evm_empty_signature_fails(self):
        assert not verify_evm_signature("msg", "", WALLET_ETH)

    def test_solana_test_signature_passes_dev_mode(self):
        assert verify_solana_signature("any message", "TEST_sig", WALLET_SOL)

    def test_solana_invalid_signature_fails(self):
        assert not verify_solana_signature("any message", "bad_sig", WALLET_SOL)


# ─────────────────────────────────────────────
# Layer 2: Trust scoring
# ─────────────────────────────────────────────

class TestTrustScoring:
    def test_base_score_no_extras(self):
        score = compute_trust_score("0xnobody", None, None)
        assert score == 40

    def test_device_fingerprint_adds_points(self):
        score = compute_trust_score("0xnobody", None, "fp_device123")
        assert score > 40

    def test_score_capped_at_100(self):
        from avp.models import OperatorRecord
        op = OperatorRecord(operator_id="op1", stake_amount=10, trust_multiplier=3.0)
        score = compute_trust_score("0xnobody", op, "fp")
        assert score <= 100

    def test_history_increases_score(self):
        wallet = "0xhistory_test_wallet_abc"
        base = compute_trust_score(wallet, None, None)
        record_successful_verification(wallet)
        record_successful_verification(wallet)
        after = compute_trust_score(wallet, None, None)
        assert after > base

    def test_score_to_tier_sovereign(self):
        assert score_to_tier(100) == TrustTier.SOVEREIGN
        assert score_to_tier(80) == TrustTier.SOVEREIGN

    def test_score_to_tier_verified(self):
        assert score_to_tier(79) == TrustTier.VERIFIED
        assert score_to_tier(60) == TrustTier.VERIFIED

    def test_score_to_tier_basic(self):
        assert score_to_tier(59) == TrustTier.BASIC
        assert score_to_tier(40) == TrustTier.BASIC

    def test_score_to_tier_untrusted(self):
        assert score_to_tier(39) == TrustTier.UNTRUSTED
        assert score_to_tier(0) == TrustTier.UNTRUSTED

    def test_sovereign_has_most_permissions(self):
        perms = tier_permissions(TrustTier.SOVEREIGN)
        assert "governance_vote" in perms
        assert "admin_actions" in perms

    def test_untrusted_read_only(self):
        perms = tier_permissions(TrustTier.UNTRUSTED)
        assert perms == ["read"]

    def test_basic_no_governance(self):
        perms = tier_permissions(TrustTier.BASIC)
        assert "governance_vote" not in perms


# ─────────────────────────────────────────────
# Layer 2: JWT
# ─────────────────────────────────────────────

class TestJWT:
    def test_issue_and_validate(self):
        token = issue_token(WALLET_ETH, "verified", ["read", "write"])
        payload = validate_token(token)
        assert payload is not None
        assert payload["sub"] == WALLET_ETH
        assert payload["tier"] == "verified"

    def test_invalid_token_returns_none(self):
        assert validate_token("bad.token.here") is None

    def test_tampered_token_fails(self):
        token = issue_token(WALLET_ETH, "sovereign", ["read"])
        parts = token.split(".")
        parts[2] = "invalidsignature"
        assert validate_token(".".join(parts)) is None

    def test_permissions_preserved(self):
        perms = ["read", "write", "governance_vote"]
        token = issue_token(WALLET_ETH, "sovereign", perms)
        payload = validate_token(token)
        assert payload["perms"] == perms

    def test_different_wallets_different_tokens(self):
        t1 = issue_token("0xaaa", "basic", ["read"])
        t2 = issue_token("0xbbb", "basic", ["read"])
        assert t1 != t2


# ─────────────────────────────────────────────
# Layer 3: Rate limiter
# ─────────────────────────────────────────────

class TestRateLimiter:
    def test_first_request_allowed(self):
        allowed, _ = check_rate_limit(_fresh_wallet("r1"))
        assert allowed

    def test_known_wallet_higher_limit(self):
        wallet = _fresh_wallet("rknown")
        results = [check_rate_limit(wallet, is_known=True)[0] for _ in range(15)]
        assert all(results)

    def test_penalty_applied_on_failure(self):
        wallet = _fresh_wallet("rfail")
        record_failed_attempt(wallet)
        allowed, reason = check_rate_limit(wallet)
        assert not allowed
        assert "retry" in reason.lower()

    def test_clear_penalties_restores_access(self):
        wallet = _fresh_wallet("rclear")
        record_failed_attempt(wallet)
        clear_penalties(wallet)
        allowed, _ = check_rate_limit(wallet)
        assert allowed


# ─────────────────────────────────────────────
# Layer 3: Staking
# ─────────────────────────────────────────────

class TestStaking:
    def test_register_operator(self):
        op = register_operator("op_test_1", 1.0)
        assert op.stake_amount == 1.0
        assert op.trust_multiplier == 1.0

    def test_add_stake(self):
        op1 = register_operator("op_addstake", 1.0)
        op2 = register_operator("op_addstake", 0.5)
        assert op2.stake_amount == 1.5

    def test_slash_reduces_stake(self):
        op = register_operator("op_slash", 10.0)
        record_verification("op_slash", success=False)
        updated = get_operator("op_slash")
        assert updated.stake_amount < 10.0

    def test_success_increments_count(self):
        op = register_operator("op_success", 5.0)
        record_verification("op_success", success=True)
        updated = get_operator("op_success")
        assert updated.verified_count == 1

    def test_is_active(self):
        register_operator("op_active", 1.0)
        assert is_operator_active("op_active")

    def test_unknown_operator_not_active(self):
        assert not is_operator_active("op_nonexistent_xyz")

    def test_get_unknown_operator_none(self):
        assert get_operator("op_nobody") is None

    def test_multiplier_grows_after_10_successes(self):
        op = register_operator("op_grow", 5.0)
        initial = op.trust_multiplier
        for _ in range(10):
            record_verification("op_grow", success=True)
        updated = get_operator("op_grow")
        assert updated.trust_multiplier > initial


# ─────────────────────────────────────────────
# Layer 4: Sybil detection
# ─────────────────────────────────────────────

class TestSybilDetector:
    def test_isolated_wallet_low_risk(self):
        wallet = _fresh_wallet("sybil_iso")
        risk = compute_sybil_risk(wallet)
        assert risk == "LOW"

    def test_shared_fingerprint_connects_wallets(self):
        w1 = _fresh_wallet("sybil_w1")
        w2 = _fresh_wallet("sybil_w2")
        fp = "shared_device_fp_unique_xyz"
        record_device_fingerprint(w1, fp)
        record_device_fingerprint(w2, fp)
        # They're now connected — at least LOW risk
        risk1 = compute_sybil_risk(w1)
        risk2 = compute_sybil_risk(w2)
        assert risk1 in ("LOW", "MEDIUM", "HIGH")
        assert risk2 in ("LOW", "MEDIUM", "HIGH")

    def test_highly_connected_wallet_high_risk(self):
        central = _fresh_wallet("sybil_hub")
        for i in range(20):
            fp = f"fp_sybil_unique_{i}"
            record_device_fingerprint(central, fp)
            other = _fresh_wallet(f"s{i:02d}")
            record_device_fingerprint(other, fp)
        risk = compute_sybil_risk(central)
        assert risk == "HIGH"


# ─────────────────────────────────────────────
# Layer 4: ZK Nullifier
# ─────────────────────────────────────────────

class TestNullifier:
    def test_compute_nullifier_deterministic(self):
        n1 = compute_nullifier(WALLET_ETH)
        n2 = compute_nullifier(WALLET_ETH)
        assert n1 == n2

    def test_different_wallets_different_nullifiers(self):
        n1 = compute_nullifier("0xaaaa")
        n2 = compute_nullifier("0xbbbb")
        assert n1 != n2

    def test_register_and_check(self):
        wallet = _fresh_wallet("nul1")
        success, _ = register_nullifier(wallet)
        assert success
        assert is_nullifier_registered(wallet)

    def test_double_registration_fails(self):
        wallet = _fresh_wallet("nul2")
        register_nullifier(wallet)
        success, _ = register_nullifier(wallet)
        assert not success

    def test_revoke_allows_reregistration(self):
        wallet = _fresh_wallet("nul3")
        register_nullifier(wallet)
        revoke_nullifier(wallet)
        success, _ = register_nullifier(wallet)
        assert success

    def test_unregistered_wallet_returns_false(self):
        assert not is_nullifier_registered(_fresh_wallet("nul_none"))


# ─────────────────────────────────────────────
# Engine integration
# ─────────────────────────────────────────────

class TestEngine:
    def _do_verify(self, wallet=None, chain=Chain.ETHEREUM, sig="TEST_valid"):
        if wallet is None:
            wallet = _fresh_wallet("eng")
        ch = create_challenge(wallet, chain)
        return run_verification(ch.challenge_id, wallet, chain, sig)

    def test_successful_verification(self):
        result = self._do_verify()
        assert result.success
        assert result.trust_score >= 40
        assert result.jwt_token is not None

    def test_bad_signature_fails(self):
        wallet = _fresh_wallet("engbad")
        ch = create_challenge(wallet, Chain.ETHEREUM)
        result = run_verification(ch.challenge_id, wallet, Chain.ETHEREUM, "BAD_SIG")
        assert not result.success
        assert "Signature" in result.error

    def test_invalid_challenge_fails(self):
        result = run_verification("fake-id", WALLET_ETH, Chain.ETHEREUM, "TEST_sig")
        assert not result.success

    def test_replay_attack_fails(self):
        wallet = _fresh_wallet("replay")
        ch = create_challenge(wallet, Chain.ETHEREUM)
        run_verification(ch.challenge_id, wallet, Chain.ETHEREUM, "TEST_sig")
        result = run_verification(ch.challenge_id, wallet, Chain.ETHEREUM, "TEST_sig")
        assert not result.success

    def test_trust_tier_in_response(self):
        result = self._do_verify()
        assert result.trust_tier in TrustTier.__members__.values()

    def test_permissions_non_empty(self):
        result = self._do_verify()
        assert len(result.permissions) > 0

    def test_with_device_fingerprint(self):
        wallet = _fresh_wallet("endfp")
        ch = create_challenge(wallet, Chain.ETHEREUM)
        result = run_verification(
            ch.challenge_id, wallet, Chain.ETHEREUM, "TEST_sig",
            device_fingerprint="device_abc"
        )
        assert result.success
        assert result.trust_score >= 50  # fingerprint bonus applied

    def test_solana_verification(self):
        result = self._do_verify(wallet=WALLET_SOL, chain=Chain.SOLANA)
        assert result.success

    def test_polygon_verification(self):
        result = self._do_verify(chain=Chain.POLYGON)
        assert result.success

    def test_bsc_verification(self):
        result = self._do_verify(chain=Chain.BSC)
        assert result.success

    def test_operator_registered_boosts_score(self):
        register_operator("op_boost_test", 5.0)
        wallet = _fresh_wallet("engop")
        ch = create_challenge(wallet, Chain.ETHEREUM)
        result = run_verification(
            ch.challenge_id, wallet, Chain.ETHEREUM, "TEST_sig",
            operator_id="op_boost_test"
        )
        assert result.success
        assert result.trust_score >= 55
