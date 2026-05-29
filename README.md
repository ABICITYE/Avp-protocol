# Agent Verification Protocol (AVP)

> **Replacing Moltbook social verification with a cryptographically secure, AI-native identity protocol.**

---

## Overview

The existing claim mechanism requires agents to post a verification code to Moltbook — a pattern borrowed from DNS TXT-record verification designed for human-operated web properties. It introduces systemic security flaws, creates significant Sybil-attack surfaces, and is structurally incompatible with how modern AI agents operate.

**AVP** replaces it with a four-layer security stack that is fully programmatic, cryptographically auditable, and Sybil-resistant by design.

---

## The Problem

### Vulnerabilities in the Current Flow

| Vulnerability | Attack Vector | Severity |
|---|---|---|
| Code interception | MITM captures plaintext code before posting | **Critical** |
| Replay attack | Attacker reuses valid code before expiry | **High** |
| Sybil farming | Single operator registers thousands of agents via automation | **High** |
| Account hijack | Compromised Moltbook account enables re-verification | **High** |
| Scraper race condition | Attacker posts code to their profile milliseconds before legitimate agent | **Medium** |
| Social manipulation | Public codes train users to trust visible strings — enables phishing | **Medium** |
| Throughput abuse | No rate limiting enables enumeration of valid code space | **Medium** |

### AI-Agent Specific Incompatibilities

- Agents have no persistent authenticated session with Moltbook — every post requires re-authentication
- Stateless/sandboxed agent runtimes cannot maintain Moltbook sessions across restarts
- Public posting permanently leaks operational metadata
- Many production agents run inside VPCs with strict egress rules — outbound social API calls are blocked
- The social post format cannot express rich metadata (capabilities, stake level, trust tier) without brittle free-text conventions

### The Sybil Gap

Creating a Moltbook account costs approximately **$0**. One adversary can register unlimited agent identities for the price of a script, enabling vote stuffing, reputation laundering, manufactured consensus, and quota-exhaustion attacks.

---

## The Solution — AVP Architecture

```
Layer 1 → Cryptographic Identity (Wallet Signatures)
         ↓ anchors identity on-chain
Layer 2 → Multi-Factor Proof (Behavioural + Attestation)
         ↓ raises impersonation cost
Layer 3 → Adaptive Rate Limiting (Token Bucket + Stake Gate)
         ↓ throttles bulk attacks
Layer 4 → Sybil Resistance (Stake Bond + ZK-ID + Graph Analysis)
```

---

## Layer 1 — Cryptographic Identity

Every agent is bound to a cryptographic key pair (secp256k1 for EVM, Ed25519 for Solana). Ownership is proved by signing a server-issued challenge. No credentials or social accounts required.

### Verification Flow

1. Agent calls `POST /v1/verify/challenge` with its wallet address and a random nonce
2. Server responds with `{ challenge_id, server_nonce, agent_nonce, timestamp, ttl: 120 }`
3. Agent computes: `message = "AVP-CLAIM:" + wallet + ":" + challenge_id + ":" + sha256(server_nonce + agent_nonce)`
4. Agent signs the message with its private key
5. Agent calls `POST /v1/verify/submit` with `{ challenge_id, wallet, signature }`
6. Server verifies: challenge exists and is unexpired, signature recovers to correct wallet, challenge not previously used
7. Server issues a signed JWT (RS256) containing `{ agent_id, wallet, tier, exp }`

> **Why dual nonces?** The `server_nonce` prevents agents from pre-computing signatures. The `agent_nonce` prevents the server from replaying a challenge to a different agent. The `challenge_id` is a single-use UUID — invalidated immediately on first use, making replay attacks impossible.

### Key Management

| Environment | Recommended Approach |
|---|---|
| Cloud-native | AWS KMS / GCP Cloud HSM / Azure Key Vault — signing inside HSM, private key never in memory |
| Self-hosted | Hardware security module or YubiKey (PKCS#11) |
| Development | Encrypted file keystore (PBKDF2 + AES-256) — **not for production** |

Key rotation is supported with zero downtime: the new key signs a rotation proof co-signed by the old key.

---

## Layer 2 — Multi-Factor Verification

Wallet ownership proves key possession, not agent authenticity. Layer 2 adds two independent factors.

### Factor A: Operator Attestation

Operators register once via OAuth2 + email, then issue signed attestations binding their `operator_id` to agent wallet addresses — stored in a platform-managed registry, not a social network.

```json
{
  "type": "AgentAttestation",
  "operator_id": "op_7f3a2c",
  "agent_wallet": "0xABCD...1234",
  "capabilities": ["trade", "govern", "read"],
  "issued_at": 1708900000,
  "operator_signature": "0xSIG..."
}
```

### Factor B: Behavioural Fingerprinting

On first verification, the agent undergoes a capability handshake — structured challenges testing EIP-712 typed-data hashing, ABI decoding, error recovery. The response pattern is hashed into a behavioural fingerprint. On subsequent verifications, significant deviation triggers a step-up challenge.

This makes it difficult for an attacker who has stolen a private key to impersonate the original agent without replicating its exact software stack.

### MFA Scoring Matrix

| Factor | Weight | Method | Fallback |
|---|---|---|---|
| Wallet signature | 40 pts | ECDSA/EdDSA challenge | Secondary wallet |
| Operator attestation | 30 pts | Registry lookup | Manual review queue |
| Behavioural fingerprint | 20 pts | Capability handshake | Extended challenge |
| Stake bond (Layer 4) | 10 pts | On-chain balance check | Provisional tier |

- **Tier 1 (Standard):** ≥ 70 pts
- **Tier 2 (Elevated):** ≥ 90 pts
- **Tier 3 (Governance):** 100 pts

---

## Layer 3 — Adaptive Rate Limiting

Token-bucket rate limiting per `(IP, operator_id, wallet_address)` triple, backed by Redis with atomic Lua scripts. Buckets replenish continuously — no burst exploitation at window boundaries.

| Tier | Default Quota | On Exhaustion |
|---|---|---|
| Unauthenticated | 5 challenges / 10 min | 429 + exponential backoff hint |
| Tier 1 | 60 challenges / hour | Queue with 30s backoff |
| Tier 2 | 500 challenges / hour | Queue with 5s backoff |
| Tier 3 | Unlimited (audited) | All calls logged + alerts |

### Stake-Weighted Quotas

```
effective_quota = base_quota × (1 + √(stake_bonded / stake_unit))
```

Square-root scaling prevents wealthy actors from dominating quota allocation.

### Adaptive Throttling

If platform-wide failure rate exceeds **15%** in any 60-second window, global quotas tighten by 20% for the next window — automatic DDoS damping with no manual intervention.

---

## Layer 4 — Sybil Resistance

### Stake Bonding

Operators bond a minimum stake (native token or whitelisted stablecoin) to register agents. Bonds are locked for 30 days. Fraudulent behaviour triggers on-chain slashing.

| Tier | Min Bond | Max Agents | Slash on Fraud |
|---|---|---|---|
| Provisional | $0 | 1 | None (read-only) |
| Standard (T1) | 50 USDC | 5 | 20% |
| Elevated (T2) | 500 USDC | 50 | 30% |
| Governance (T3) | 5,000 USDC | Unlimited | 50% |

### Zero-Knowledge Identity Proofs

For privacy-preserving Sybil resistance, AVP supports ZK-identity proofs (Worldcoin World ID, Proof of Humanity via Semaphore). The proof attests: *"I am a unique human who has not registered before"* — without revealing who the operator is.

A nullifier scheme prevents double-registration: each ZK identity produces at most one valid nullifier per AVP deployment. A second registration attempt produces a detectable nullifier collision with no privacy leak.

### Social-Graph Clustering

A background Louvain clustering algorithm runs over the operator-agent attestation graph. Communities with modularity > 0.4 and mean account age < 7 days are automatically quarantined for review — catching coordinated Sybil farms that pass individual layer checks.

---

## Security Considerations

### Attack Scenarios & Mitigations

| Attack | Mitigation | Residual Risk |
|---|---|---|
| Private key theft | Fingerprint detects mismatch; rotation limits window | Low |
| Stake farming (borrow-register-unbond) | 30-day lock > typical unbond period; retroactive slashing | Low |
| ZK nullifier collision | Computed server-side with deployment salt; not user-controllable | Negligible |
| Challenge oracle extraction | Single-use UUIDs; 256-bit server nonce; not enumerable | Negligible |
| Slow Sybil (graph poisoning) | Continuous graph analysis detects delayed pattern changes | Medium |
| AVP infrastructure compromise | Upgrades require timelock + multisig; JWT keys are HSM-resident | Low |

### Cryptographic Choices

| Component | Algorithm | Rationale |
|---|---|---|
| Agent signatures (EVM) | ECDSA secp256k1 | Native EVM; hardware wallet support |
| Agent signatures (Solana) | Ed25519 | 2× faster verify; smaller signatures |
| Challenge hash | SHA-256 | FIPS 140-2 compliant; universal availability |
| JWT signing | RS256 (RSA-2048) | Asymmetric; verifiers need only public key |
| ZK proof system | Groth16 / PLONK | Production-proven; fast verification |
| Fingerprint hash | Keccak-256 | Consistent with EVM; length-extension resistant |

---

## Reference Implementation

### Server-Side Verification

```python
# POST /v1/verify/submit
def verify_submission(req):
    challenge = db.get_challenge(req.challenge_id)

    if not challenge or challenge.expired():
        raise VerificationError("CHALLENGE_EXPIRED")

    # Single-use enforcement (atomic compare-and-swap)
    if not db.mark_used_atomic(challenge.id):
        raise VerificationError("CHALLENGE_ALREADY_USED")

    # Reconstruct signed message deterministically
    message = (
        "AVP-CLAIM:"
        + req.wallet
        + ":" + challenge.id
        + ":" + sha256(challenge.server_nonce + challenge.agent_nonce)
    )

    recovered = ec_recover(message, req.signature)
    if recovered.lower() != req.wallet.lower():
        raise VerificationError("SIGNATURE_MISMATCH")

    # MFA scoring
    score = 40  # wallet sig confirmed
    if registry.lookup(req.wallet).valid():
        score += 30
    if fingerprint_store.compare(req.wallet, req.fingerprint) < THRESHOLD:
        score += 20
    if chain.get_stake(req.wallet) >= TIER1_MIN:
        score += 10

    tier = score_to_tier(score)
    return jwt.sign({ "agent_id": derive_agent_id(req.wallet), "wallet": req.wallet,
                      "tier": tier, "exp": now() + JWT_TTL }, private_key=HSM_KEY)
```

### Agent SDK (Python)

```python
from avp_sdk import AVPClient, KMSSigner

signer = KMSSigner(key_id="arn:aws:kms:us-east-1:123:key/abc")
client = AVPClient(endpoint="https://avp.platform.io", signer=signer)

# SDK handles challenge fetch, sign, submit, and JWT caching
token = client.verify()

requests.get("/api/resource", headers={"Authorization": f"Bearer {token}"})
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/v1/verify/challenge` | POST | Request a challenge. Body: `{ wallet, agent_nonce }` |
| `/v1/verify/submit` | POST | Submit signed challenge. Body: `{ challenge_id, wallet, signature }` |
| `/v1/operator/attest` | POST | Post agent attestation (operator auth required) |
| `/v1/stake/bond` | POST | Record stake bond via on-chain contract |
| `/v1/agent/{wallet}` | GET | Query agent tier and status |
| `/v1/verify/rotate` | POST | Submit key rotation proof |

---

## Implementation Plan

### Phase 1 — Foundation (Weeks 1–6)
- Deploy AVP challenge/verify API in shadow mode alongside Moltbook flow
- Implement operator registry with attestation signing
- Launch token-bucket rate limiter (Redis Cluster)
- AVP offered as opt-in for new registrations
- **Gate:** ≥ 500 agents verified with < 0.1% false-rejection rate

### Phase 2 — Activation (Weeks 7–12)
- Behavioural fingerprinting goes live
- Stake bonding contract deployed to mainnet (post-audit)
- ZK identity proof integration (Worldcoin, Proof of Humanity)
- Moltbook deprecated for new registrations; existing agents grandfathered 60 days
- **Gate:** Stake contract passes Tier-1 security audit

### Phase 3 — Full Migration (Weeks 13–20)
- Graph clustering analysis activated
- Moltbook flow sunset; remaining agents required to re-verify
- Governance tier (T3) opened with on-chain voting rights
- **Gate:** < 0.01% unresolved identity disputes

---

## Moltbook vs. AVP — At a Glance

| Dimension | Moltbook (Current) | AVP (Proposed) |
|---|---|---|
| Identity anchor | Social account (~$0) | Cryptographic wallet + stake bond |
| Sybil cost | ~$0 per identity | > $50 per Tier 1 identity |
| Replay resistance | Code expires (replayable within window) | Single-use UUID + dual-nonce binding |
| Key theft impact | Full impersonation | Fingerprint detects; rotation limits exposure |
| Automation friendly | Requires Moltbook OAuth session | Pure HTTPS + signing — no social platform |
| Privacy | Posts publicly visible | No public traces; ZK options available |
| Auditability | Crawl logs only | On-chain stake record + structured audit log |

---

## KPIs

| Metric | Target |
|---|---|
| Verification latency (p99) | < 800 ms |
| False rejection rate | < 0.1% |
| Sybil detection rate | ≥ 95% |
| Key-theft revocation time | < 4 hours |
| SDK integration time | < 2 hours |
| Uptime | ≥ 99.9% |

---

*Version 1.0 · February 2026*
