"""
Trust tier classification and permission sets.
"""
from avp.models import TrustTier

_TIER_PERMISSIONS: dict[TrustTier, list[str]] = {
    TrustTier.SOVEREIGN: [
        "read",
        "write",
        "transfer_high_value",
        "governance_vote",
        "operator_register",
        "admin_actions",
    ],
    TrustTier.VERIFIED: [
        "read",
        "write",
        "transfer_standard",
        "governance_vote",
    ],
    TrustTier.BASIC: [
        "read",
        "transfer_limited",
    ],
    TrustTier.UNTRUSTED: [
        "read",
    ],
}


def score_to_tier(score: int) -> TrustTier:
    if score >= 80:
        return TrustTier.SOVEREIGN
    if score >= 60:
        return TrustTier.VERIFIED
    if score >= 40:
        return TrustTier.BASIC
    return TrustTier.UNTRUSTED


def tier_permissions(tier: TrustTier) -> list[str]:
    return list(_TIER_PERMISSIONS[tier])
