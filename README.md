# AVP — Agent Verification Protocol

> A multi-chain wallet verification protocol with trust scoring, adaptive rate limiting, Sybil resistance, and zero-knowledge nullifiers for Web3 applications.

---

## The Problem

Current wallet authentication (SIWE, Web3Auth) is binary — you either signed or you didn't. There's no trust scoring, no cross-chain standard, and no protection against Sybil attacks.

This creates real vulnerabilities:

| Vulnerability | Attack Vector | Severity |
|---------------|--------------|----------|
| Replay attack | Attacker reuses valid signature before expiry | High |
| Sybil farming | Single operator registers thousands of wallets via automation | High |
| Account hijack | Compromised wallet enables re-verification | High |
| Throughput abuse | No rate limiting enables enumeration of valid wallets | Medium |

AVP fixes this with a 4-layer verification stack that is fully programmatic, cryptographically auditable, and Sybil-resistant by design.

---

## Architecture

```
┌──────────────────────────────────────────────┐
│           Layer 4: Sybil Shield              │
│   ZK Nullifiers · Graph Community Detection  │
├──────────────────────────────────────────────┤
│         Layer 3: Adaptive Security           │
│    Rate Limiting · Operator Staking/Slash    │
├──────────────────────────────────────────────┤
│          Layer 2: MFA Trust Score            │
│  Signature(40) · Operator(30) · Device(20)  │
│               · Time Window(10)             │
├──────────────────────────────────────────────┤
│         Layer 1: Challenge & Proof           │
│      EVM ECDSA · Solana Ed25519 · JWT        │
└──────────────────────────────────────────────┘
```

---

## Live API

| Endpoint | URL |
|----------|-----|
| Health | https://avp-protocol.onrender.com/health |
| Interactive Docs | https://avp-protocol.onrender.com/docs |
| Demo | https://avp-protocol.onrender.com/demo |

---

## Multi-Chain Support

| Chain    | Signature Scheme  | Status |
|----------|-------------------|--------|
| Ethereum | ECDSA (secp256k1) | ✅     |
| Polygon  | ECDSA (secp256k1) | ✅     |
| BSC      | ECDSA (secp256k1) | ✅     |
| Solana   | Ed25519           | ✅     |

---

## Trust Tiers

| Tier      | Score | Permissions |
|-----------|-------|-------------|
| SOVEREIGN | 80–100 | read, write, transfer_high_value, governance_vote, admin |
| VERIFIED  | 60–79  | read, write, transfer_standard, governance_vote |
| BASIC     | 40–59  | read, transfer_limited |
| UNTRUSTED | 0–39   | read only |

---

## How It Works

### Step 1 — Request a Challenge
```bash
POST /challenge
{
  "wallet_address": "0xYourWallet",
  "chain": "ethereum"
}
```
Returns a unique message to sign with your wallet. Expires in 5 minutes.

### Step 2 — Sign & Verify
```bash
POST /verify
{
  "challenge_id": "...",
  "wallet_address": "0xYourWallet",
  "chain": "ethereum",
  "signature": "0x...",
  "operator_id": "my-operator",
  "device_fingerprint": "fp-hash"
}
```
Returns a JWT token, trust score, tier, and permission set.

### Step 3 — Validate Token
```bash
GET /validate?token=<jwt>
```
Returns wallet address, trust tier, and permissions.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/ABICITYE/avp-protocol.git
cd avp-protocol
pip install -r requirements.txt

# Run the server
uvicorn api:app --reload

# Run tests
pytest tests/ -v
```

Interactive API docs available at `http://localhost:8000/docs`

---

## Project Structure

```
avp-protocol/
├── api.py                    # FastAPI REST API
├── avp/
│   ├── models.py             # All data models
│   ├── engine.py             # Verification engine (orchestrates all layers)
│   ├── db.py                 # SQLite persistence layer
│   ├── core/
│   │   ├── challenge.py      # Layer 1: Challenge generation
│   │   ├── mfa_scoring.py    # Layer 2: Multi-factor trust scoring
│   │   ├── jwt_manager.py    # JWT token creation & validation
│   │   └── trust_tiers.py   # Trust tier → permissions mapping
│   ├── chains/
│   │   ├── evm.py            # Ethereum ECDSA signature verification
│   │   └── solana.py         # Solana Ed25519 signature verification
│   ├── middleware/
│   │   └── rate_limiter.py   # Layer 3: Adaptive rate limiting
│   └── security/
│       ├── staking.py        # Layer 3: Operator staking & slashing
│       ├── sybil_detector.py # Layer 4: Graph community detection
│       └── zk_nullifier.py   # Layer 4: ZK nullifier registry
├── tests/
│   └── test_avp.py           # Comprehensive test suite
├── demo/
│   └── index.html            # Interactive demo page
├── Dockerfile
├── Procfile
└── railway.toml
```

---

## Security Features

**Adaptive Rate Limiting**
- Unknown wallets: 5 requests per 60 seconds
- Known wallets: 20 requests per 60 seconds
- Failed verifications trigger exponential back-off (5s → 25s → 125s → max 600s)

**Operator Staking & Slashing**
- Operators stake ETH-equivalent value to run verification services
- Each failed verification slashes 10% of stake
- Trust multiplier grows with successful verifications (capped at 3x)

**Sybil Resistance**
- Wallet interaction graph built from shared device fingerprints
- BFS community detection flags wallets with HIGH connection density
- HIGH risk wallets are denied verification entirely

**ZK Nullifiers**
- One-way commitment hash prevents double-verification
- Replay attacks blocked at the nullifier registry level
- Revokable for key rotation scenarios

**SQLite Persistence**
- All state survives server restarts
- Challenges, nullifiers, operators, penalties, wallet history
- WAL mode for concurrent read performance

---

## Deploy

### Render (recommended)
1. Push to GitHub
2. Go to [render.com](https://render.com), create a new Web Service
3. Connect your repo, set runtime to Python
4. Build command: `pip install -r requirements.txt`
5. Start command: `uvicorn api:app --host 0.0.0.0 --port $PORT`
6. Add environment variable: `AVP_JWT_SECRET=your-secret-here`

### Docker
```bash
docker build -t avp-protocol .
docker run -p 8000:8000 -e AVP_JWT_SECRET=your-secret avp-protocol
```

### Railway (for multi-service setups)
1. Push to GitHub
2. Go to [railway.app](https://railway.app), connect your repo
3. Add environment variable: `AVP_JWT_SECRET=your-secret-here`
4. Railway auto-detects and deploys

---

## Tech Stack

- **Python 3.12 + FastAPI** — async API framework
- **SQLite (stdlib)** — zero-dependency persistence
- **ECDSA** — Ethereum signature verification
- **Ed25519** — Solana signature verification
- **Louvain-style BFS** — graph community detection for Sybil resistance
- **HMAC-SHA256** — JWT implementation (no external JWT library)

---

## Roadmap

- [ ] Python SDK (`pip install avp-sdk`)
- [ ] JavaScript/TypeScript SDK (`npm install avp-sdk`)
- [ ] Documentation site
- [ ] Redis persistence option for horizontal scaling
- [ ] Webhook callbacks on verification events
- [ ] Polygon ID / zkProof integration
- [ ] Dashboard UI for operators

---

## License

MIT

---

## Author

Oyewole Emmanuel Abiodun ([@ABICITYE](https://github.com/ABICITYE))
