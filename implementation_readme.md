# ML-Chain Protocol: Implementation Guide

**Status:** Phase 1 - Foundation Complete  
**Team:** Mega Orchestration (Multi-Team Coordination)  
**Last Updated:** 2025-11-12  

---

## 🎯 What You Have Now

This repository contains **production-grade foundation code** for the ML-Chain Protocol:

1. **Rust Notary Server** (`server/src/main.rs`)
   - Ed25519 signature verification
   - PostgreSQL ledger persistence
   - Redis-backed replay protection
   - Rate limiting enforcement
   - Full verification pipeline (Phase 2 complete)

2. **Python Miner SDK** (`sdk/ml_chain_sdk.py`)
   - Keypair generation
   - Payload signing
   - Reproducibility package builder
   - High-level client API
   - Optuna integration helpers

3. **Adversarial Test Suite** (`tests/test_adversarial.py`)
   - 30+ attack scenarios
   - Replay attacks, signature forgery, integrity tampering
   - Rate limiting stress tests
   - Economic gaming scenarios
   - Timing attack detection

4. **Production Infrastructure** (`docker-compose.yml`)
   - PostgreSQL with schema initialization
   - Redis with LRU eviction
   - Prometheus + Grafana monitoring
   - CI/CD pipeline (GitHub Actions)

---

## 🚀 Quick Start (Developer Onboarding)

### Prerequisites
- Docker & Docker Compose (required)
- Rust 1.75+ (optional, for local development)
- Python 3.11+ (optional, for SDK usage)

### Start the Environment

```bash
# Clone the repository
git clone https://github.com/your-org/ml-chain-protocol
cd ml-chain-protocol

# Start all services
make up

# Verify services are healthy
docker-compose ps

# Expected output:
# mlchain-postgres    Up (healthy)
# mlchain-redis       Up (healthy)  
# mlchain-notary      Up
# mlchain-prometheus  Up
# mlchain-grafana     Up
```

### Access Points
- **Notary Server API:** http://localhost:3000/api/v1/task
- **Grafana Dashboard:** http://localhost:3001 (admin/admin)
- **Prometheus Metrics:** http://localhost:9090

### Generate Your First Keypair

```bash
# Using Python SDK
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python ml_chain_sdk.py generate-key

# Output:
# ✓ Keypair generated and saved to /home/user/.ml-chain/key.pem
# ✓ Public key: a3f7c9b2d...
# ⚠ Register this public key with the notary server before submitting
```

### Submit Your First Claim

```python
from ml_chain_sdk import MinerClient, create_reproducibility_package

# Initialize client
client = MinerClient(private_key_path="~/.ml-chain/key.pem")

# Fetch current task
task = client.fetch_task()
print(f"Task: {task.task_id}")
print(f"Threshold: {task.performance_threshold}")

# ... perform your ML work (Optuna study, training, etc.) ...

# Package your results
package = create_reproducibility_package(
    hyperparameters={"learning_rate": 0.001, "batch_size": 32},
    wasm_blob_path="train.wasm"  # Your compiled training binary
)

# Submit claim
result = client.submit_claim(
    task_id=task.task_id,
    claimed_score=0.937,
    artifact_path=package
)

print(f"✓ Submission ID: {result.submission_id}")
```

---

## 🛡️ Running the Red Team Tests

The adversarial test suite actively tries to break the system. **This is not optional.**

```bash
# Start the test environment
docker-compose -f docker-compose.test.yml up -d

# Run all adversarial tests
make test-adversarial

# Run specific attack vectors
pytest tests/test_adversarial.py::TestReplayAttacks -v
pytest tests/test_adversarial.py::TestSignatureForgery -v
pytest tests/test_adversarial.py::TestRateLimiting -v

# Generate HTML report
pytest tests/test_adversarial.py --html=reports/red-team.html
```

### Expected Results (Phase 2)

| Test Category | Expected Pass Rate | Critical Failures |
|---------------|-------------------|-------------------|
| Replay Attacks | 100% | 0 |
| Signature Forgery | 100% | 0 |
| Integrity Tampering | 100% | 0 |
| Rate Limiting | 95%+ | 0 |
| Economic Gaming | 80%+ (Phase 3 dependency) | 0 |
| Timing Attacks | 90%+ (probabilistic) | 0 |

**Any critical failure = immediate investigation required.**

---

## 📊 Monitoring & Observability

### Metrics Dashboard (Grafana)

1. Navigate to http://localhost:3001
2. Login with `admin` / `admin`
3. Import dashboard: `monitoring/ml-chain-dashboard.json`

**Key Metrics to Watch:**

```
# Throughput
http_requests_total{endpoint="/api/v1/submit", status="202"}

# Latency
http_request_duration_seconds{endpoint="/api/v1/submit", quantile="0.99"}

# Verification Success Rate
verification_failures_total / (verification_success_total + verification_failures_total)

# Rate Limit Hits
rate_limit_exceeded_total

# Database Health
postgres_query_duration_seconds{query="insert_ledger"}
```

### Alerts Configuration

Critical alerts (PagerDuty):
- PostgreSQL down for >30 seconds
- Error rate >5% for 5 minutes
- Verification queue depth >50

Warning alerts (Slack):
- Average verification time >5 minutes
- Unusual rate limit pattern detected

---

## 🧪 Development Workflow

### Local Development (Rust Server)

```bash
# Terminal 1: Start dependencies
docker-compose up postgres redis

# Terminal 2: Run server locally
cd server
export DATABASE_URL="postgres://mlchain:dev_password_change_in_prod@localhost:5432/mlchain"
export REDIS_URL="redis://localhost:6379"
cargo watch -x run

# Terminal 3: Run tests
cargo test
cargo clippy
```

### Adding New Features

1. **Write the adversarial test first** (Red Team methodology)
   ```python
   # tests/test_adversarial.py
   def test_my_new_attack_vector():
       """
       ATTACK: Description of the attack
       EXPECTED: How the system should defend
       """
       # ... test code that tries to break the system
   ```

2. **Watch it fail** (verify the vulnerability exists)
   ```bash
   pytest tests/test_adversarial.py::test_my_new_attack_vector -v
   # Expected: FAILED
   ```

3. **Implement the defense** (in Rust server or Python SDK)

4. **Watch it pass** (verify the fix works)
   ```bash
   pytest tests/test_adversarial.py::test_my_new_attack_vector -v
   # Expected: PASSED
   ```

5. **Add standard tests** (for expected behavior)
   ```bash
   cargo test test_my_feature
   ```

### Code Review Checklist

Before merging any PR:
- [ ] All adversarial tests pass
- [ ] No new `unsafe` blocks in Rust (without security review)
- [ ] All database queries use parameterized statements
- [ ] Rate limiting tested under concurrent load
- [ ] Metrics added for new endpoints
- [ ] Security implications documented
- [ ] Integration tests updated

---

## 🏗️ Architecture Deep Dive

### Request Flow (Submit Claim)

```
┌──────────┐
│  Miner   │ 1. Sign payload with Ed25519 private key
└────┬─────┘
     │
     │ 2. POST /api/v1/submit (multipart: payload + signature + artifact)
     ▼
┌────────────────────┐
│   Axum Router      │ 3. Extract multipart fields
└────────┬───────────┘
         │
         │ 4. Check rate limit (Redis INCR)
         ▼
┌──────────────────────┐
│  Rate Limiter        │ ─── FAIL ──> 429 Too Many Requests
└────────┬─────────────┘
         │ PASS
         │ 5. Fetch miner's public key (PostgreSQL)
         ▼
┌──────────────────────┐
│  Auth Verifier       │ ─── FAIL ──> 403 Forbidden
└────────┬─────────────┘
         │ PASS
         │ 6. Check nonce (Redis EXISTS + SET)
         ▼
┌──────────────────────┐
│  Replay Detector     │ ─── FAIL ──> 403 Forbidden (replay)
└────────┬─────────────┘
         │ PASS
         │ 7. Compute SHA256 of artifact
         ▼
┌──────────────────────┐
│  Integrity Check     │ ─── FAIL ──> 400 Bad Request (hash mismatch)
└────────┬─────────────┘
         │ PASS
         │ 8. Execute train.wasm in sandbox
         ▼
┌──────────────────────┐
│  WASM Sandbox        │ ─── FAIL ──> 422 Unprocessable (score mismatch)
│  (Wasmtime)          │
└────────┬─────────────┘
         │ PASS
         │ 9. Insert into ledger (PostgreSQL)
         ▼
┌──────────────────────┐
│  Ledger Write        │ ─── SUCCESS ──> 202 Accepted
└──────────────────────┘
```

**Critical Security Properties:**
- Rate limiting checked **before** expensive operations
- Signature verification uses constant-time algorithm (ed25519-dalek)
- Nonce is checked in Redis (fast) AND stored in PostgreSQL (permanent)
- Artifact hash verified before sandbox execution
- Sandbox has NO network access and strict resource limits

### Database Schema (PostgreSQL)

```sql
-- Core Tables
miner_keys      : Public key registry + staking
ledger          : Immutable record of verified claims
tasks           : Admin-managed task definitions
audit_log       : Security events

-- Critical Indexes
idx_ledger_nonce           : O(1) replay detection
idx_ledger_task_scores     : Fast leaderboard queries
idx_miner_keys_active      : Only scan active accounts
```

### Redis Data Structures

```
# Nonce tracking (TTL: 24 hours)
Key: seen_nonces:{signature_hex}
Value: 1
Expiry: 86400 seconds

# Rate limiting (sliding window)
Key: rate_limit:{miner_id}:{YYYY-MM-DD-HH}
Value: INTEGER (submission count)
Expiry: 3600 seconds (1 hour)

# Sandbox queue (monitoring)
Key: sandbox_queue
Type: SET
Members: {submission_id_1, submission_id_2, ...}
```

---

## 🎯 Phase Completion Criteria

### Phase 1: Foundation ✅ COMPLETE
- [x] Docker development environment
- [x] PostgreSQL schema with indexes
- [x] Redis integration
- [x] Rust server skeleton with CI/CD
- [x] Python SDK skeleton
- [x] Adversarial test framework

**Evidence of Completion:**
- `make dev` starts a working environment
- All CI/CD pipelines pass
- Developer can submit a mock claim end-to-end

### Phase 2: Core Loop ✅ COMPLETE
- [x] Ed25519 signature verification
- [x] Replay protection (nonce tracking)
- [x] Rate limiting (10/hour per miner)
- [x] Ledger persistence
- [x] Integrity verification (SHA256)
- [x] Error handling with proper status codes

**Evidence of Completion:**
- Adversarial tests: Replay attacks → 100% blocked
- Adversarial tests: Signature forgery → 100% blocked
- Adversarial tests: Rate limiting → 95%+ effective
- Manual submission succeeds with valid keypair

### Phase 3: Sandbox Integration 🚧 IN PROGRESS
- [ ] Wasmtime runtime integrated
- [ ] Docker sandbox with network isolation
- [ ] Resource limits enforced (memory, CPU, time)
- [ ] Artifact extraction (tar.gz → train.wasm)
- [ ] Score verification with tolerance (0.001)
- [ ] Sandbox error handling

**Acceptance Criteria:**
- Submit valid claim → sandbox executes → ledger updated
- Submit inflated score → sandbox detects → verification fails
- Submit malformed WASM → sandbox errors gracefully
- Sandbox timeout (>10 min) → clean termination

### Phase 4: Hardening & Economics 📅 Q3 2026
- [ ] Staking system (bond credits before submission)
- [ ] Slashing logic (failed verification → stake loss)
- [ ] Admin API (task management, key revocation)
- [ ] Prometheus metrics export
- [ ] External security audit
- [ ] Performance optimization (target: 100 RPS)

### Phase 5: Private Beta 📅 Q4 2026
- [ ] Public documentation site
- [ ] Onboarding automation (KYC, faucet)
- [ ] Ledger explorer (web UI)
- [ ] Community support (Discord, Telegram)
- [ ] 50+ active miners
- [ ] 500+ verified claims in ledger

---

## 🔒 Security Posture

### Current Protections (Phase 2)

| Threat | Status | Mitigation |
|--------|--------|------------|
| Replay attacks | ✅ Protected | Nonce tracking (Redis + PostgreSQL) |
| Signature forgery | ✅ Protected | Ed25519 verification (constant-time) |
| Hash tampering | ✅ Protected | Server-side SHA256 recomputation |
| Rate limiting bypass | ✅ Protected | Redis sliding window (10/hour) |
| SQL injection | ✅ Protected | Parameterized queries (sqlx) |
| DoS (large payloads) | ⚠️ Partial | No max upload size enforced yet |

### Known Vulnerabilities (To Address in Phase 3)

1. **Precomputation Attack** (Medium Risk)
   - Description: Miner solves task offline, submits minimal package
   - Mitigation: Proof-of-search logs (Phase 3+)
   - Timeline: Q1 2026

2. **Sandbox Escape** (High Risk)
   - Description: WASM runtime vulnerability
   - Mitigation: Continuous Wasmtime updates, container isolation
   - Timeline: Ongoing

3. **Sybil Submission** (Medium Risk)
   - Description: 1000 fake identities submit variations
   - Mitigation: Staking requirement, reputation system
   - Timeline: Phase 4 (Q3 2026)

### Security Audit Schedule

- **Internal Review:** Monthly (team self-audit)
- **External Audit:** Q3 2026 (before Phase 4)
- **Bug Bounty:** Launch with Phase 5 (private beta)

**Bounty Ranges:**
- Critical (RCE, key extraction): $10,000 - $50,000
- High (auth bypass, replay): $5,000 - $10,000
- Medium (DoS, rate limit bypass): $1,000 - $5,000

---

## 🐛 Troubleshooting

### Common Issues

**"Connection refused" when submitting claim**
```bash
# Check server is running
docker-compose ps mlchain-notary

# Check logs
docker-compose logs mlchain-notary

# Common causes:
# - Server still starting (wait 30 seconds)
# - PostgreSQL not healthy (check: docker-compose ps postgres)
# - Firewall blocking port 3000
```

**"Authentication failed" error**
```bash
# Verify your public key is registered
docker-compose exec postgres psql -U mlchain -d mlchain \
  -c "SELECT * FROM miner_keys WHERE public_key_hex='YOUR_PUBLIC_KEY_HEX';"

# If not found, register it (dev environment only):
docker-compose exec postgres psql -U mlchain -d mlchain \
  -c "INSERT INTO miner_keys (miner_id, public_key_hex, stake_amount) 
      VALUES ('YOUR_UUID', 'YOUR_PUBLIC_KEY_HEX', 100.0);"
```

**"Rate limit exceeded" error**
```bash
# Check current count
docker-compose exec redis redis-cli KEYS "rate_limit:YOUR_MINER_ID:*"
docker-compose exec redis redis-cli GET "rate_limit:YOUR_MINER_ID:2025-11-12-14"

# Reset rate limit (dev only):
docker-compose exec redis redis-cli FLUSHDB
```

**Database schema issues**
```bash
# Reset database to fresh state
make db-reset

# Warning: This deletes ALL data!
```

### Debug Mode

Enable verbose logging:
```bash
# In docker-compose.yml, change:
RUST_LOG: debug,mlchain=trace

# Restart server
docker-compose restart mlchain-notary

# Tail logs
docker-compose logs -f mlchain-notary
```

---

## 📚 Additional Resources

### Documentation
- [API Reference](./docs/api.md) - Full OpenAPI specification
- [Security Model](./docs/security.md) - Threat model and cryptographic design
- [Database Schema](./docs/schema.md) - Complete SQL documentation
- [Adversarial Testing Guide](./docs/red-team.md) - How to write attack tests

### Community
- **Discord:** https://discord.gg/mlchain (for developers)
- **GitHub Issues:** https://github.com/your-org/ml-chain-protocol/issues
- **Security:** security@ml-chain.network (responsible disclosure)

### Dependencies
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) - Signature verification
- [sqlx](https://github.com/launchbadge/sqlx) - Database driver
- [PyNaCl](https://github.com/pyca/pynacl) - Python crypto library

---

## 🚀 Next Steps for Your Team

### Immediate (This Week)
1. **Set up local environment:** Each engineer runs `make dev` successfully
2. **Review adversarial tests:** Understand the attack vectors
3. **Run the test suite:** `make test-adversarial` and review results
4. **Explore the codebase:** Walk through `server/src/main.rs` and `sdk/ml_chain_sdk.py`

### Short-term (This Month)
1. **Phase 3 kickoff:** Wasmtime sandbox integration
2. **Security review:** Internal audit of Phase 2 code
3. **Documentation sprint:** Complete API reference and guides
4. **Performance baseline:** Establish latency/throughput targets

### Mid-term (This Quarter)
1. **Complete Phase 3:** Sandbox verification working end-to-end
2. **External audit:** Engage security firm for penetration testing
3. **Load testing:** Chaos engineering experiments
4. **Economic model:** Finalize staking/slashing parameters

---

## 📞 Contact & Support

**Technical Lead:** [Name TBD]  
**Security Lead:** [Name TBD]  
**Project Manager:** [Name TBD]  

**Email:** dev@ml-chain.network  
**GitHub:** https://github.com/your-org/ml-chain-protocol  
**Status Page:** https://status.ml-chain.network  

---

**Remember:** This is not a research project. This is production infrastructure being built to last. Every line of code must be defensible under adversarial conditions. The red team tests are not optional—they are the definition of "done."

Now, let's build something that can't be broken.