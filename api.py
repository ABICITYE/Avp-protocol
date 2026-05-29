"""
AVP — Agent Verification Protocol
FastAPI REST API
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from avp.models import (
    ChallengeRequest, ChallengeResponse,
    VerifyRequest, VerifyResponse,
    TokenValidationResponse,
)
from avp.core.challenge import create_challenge
from avp.core.jwt_manager import validate_token
from avp.engine import run_verification
from avp.security.staking import register_operator, get_operator

app = FastAPI(
    title="AVP — Agent Verification Protocol",
    description=(
        "Multi-chain wallet verification with trust scoring, "
        "adaptive rate limiting, Sybil resistance, and ZK nullifiers."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "protocol": "AVP", "version": "1.0.0"}


# ─────────────────────────────────────────────
# Challenge
# ─────────────────────────────────────────────

@app.post("/challenge", response_model=ChallengeResponse)
def challenge(req: ChallengeRequest):
    """
    Step 1 — Request a challenge message to sign with your wallet.
    Challenge expires in 5 minutes.
    """
    return create_challenge(req.wallet_address, req.chain)


# ─────────────────────────────────────────────
# Verify
# ─────────────────────────────────────────────

@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    """
    Step 2 — Submit your signed challenge.
    Returns a JWT token and trust score on success.
    """
    result = run_verification(
        challenge_id=req.challenge_id,
        wallet_address=req.wallet_address,
        chain=req.chain,
        signature=req.signature,
        operator_id=req.operator_id,
        device_fingerprint=req.device_fingerprint,
    )
    return result


# ─────────────────────────────────────────────
# Token validation
# ─────────────────────────────────────────────

@app.get("/validate", response_model=TokenValidationResponse)
def validate(token: str):
    """
    Validate a JWT token issued by AVP.
    Pass token as query param: GET /validate?token=<jwt>
    """
    payload = validate_token(token)
    if payload is None:
        return TokenValidationResponse(valid=False, error="Invalid or expired token")
    return TokenValidationResponse(
        valid=True,
        wallet_address=payload.get("sub"),
        trust_tier=payload.get("tier"),
        permissions=payload.get("perms", []),
    )


# ─────────────────────────────────────────────
# Operator management
# ─────────────────────────────────────────────

@app.post("/operators/register")
def operator_register(operator_id: str, stake_amount: float):
    """Register an operator with a stake amount (ETH-equivalent)."""
    if stake_amount <= 0:
        raise HTTPException(status_code=400, detail="stake_amount must be > 0")
    op = register_operator(operator_id, stake_amount)
    return {
        "operator_id": op.operator_id,
        "stake_amount": op.stake_amount,
        "trust_multiplier": op.trust_multiplier,
        "status": "active",
    }


@app.get("/operators/{operator_id}")
def operator_info(operator_id: str):
    """Get operator stats."""
    op = get_operator(operator_id)
    if op is None:
        raise HTTPException(status_code=404, detail="Operator not found")
    return op.model_dump()
