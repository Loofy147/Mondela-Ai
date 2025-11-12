# ML-Chain Protocol v6.0: Hardened Production Blueprint

**Document Version:** 6.0.0  
**Status:** Production Mandate  
**Classification:** Engineering Specification  
**Last Updated:** 2025-11-11  

---

## Executive Summary

This document specifies the ML-Chain Protocol: a cryptographically-secured system for verifiable machine learning computation. Unlike traditional federated learning or model registries, ML-Chain requires participants to submit **reproducible training packages** that can be independently verified in a sandboxed environment. The system is designed with the assumption that all actors are economically rational and potentially adversarial.

**What This Is Not:**
- A research prototype
- A centralized model hub
- A trust-based federation
- A consensus protocol (yet)

**What This Is:**
- A hardened verification pipeline for ML work
- A cryptographically auditable ledger of proven computations
- A practical hybrid of trusted infrastructure and verifiable outputs
- The foundation for a future decentralized compute network

---

## 1. Guiding Principles (Non-Negotiable Axioms)

### 1.1 Verifiability Over Trust
The Notary Server is a trusted operator, but **its actions produce cryptographically verifiable outputs**. Every claim must be independently verifiable by any third party with access to the ledger and artifacts.

### 1.2 The Right Tool for the Right Job
- **Rust:** Notary Server (security-critical, high-performance)
- **Python:** Miner SDK (ML ecosystem compatibility, developer accessibility)
- **WASM:** Execution sandbox (portable, sandboxable, reproducible)

There are no exceptions. Do not compromise on this architectural decision.

### 1.3 Reproducibility is the Proof-of-Work
A claim without reproducibility is worthless. The fundamental unit of contribution is not a model file—it's a **complete, sandboxed training environment** that produces deterministic results.

### 1.4 Secure by Default
- All network communication over TLS 1.3+
- Ed25519 signatures for all claims
- Replay attack protection via nonce tracking
- Rate limiting at multiple layers
- Principle of least privilege for all services

### 1.5 Economically Rational Design
Assume every participant will attempt to maximize reward while minimizing effort. The protocol must make cheating more expensive than honest participation.

---

## 2. System Architecture

### 2.1 Component Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                         EXTERNAL ZONE                            │
│  ┌──────────────────┐                                            │
│  │  Python Miner    │  (Untrusted, arbitrary code)               │
│  │  SDK (PyNaCl,    │────────HTTPS/TLS 1.3──────────┐            │
│  │  Optuna)         │                                │            │
│  └──────────────────┘                                │            │
└──────────────────────────────────────────────────────┼────────────┘
                                                       │
┌──────────────────────────────────────────────────────┼────────────┐
│                      TRUSTED ZONE                    │            │
│                                                      ▼            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              Rust Notary Server (Axum)                     │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │  Auth Layer  │  │  API Gateway │  │  Verification   │  │  │
│  │  │  (Ed25519)   │──│  (Rate Limit)│──│  Orchestrator   │  │  │
│  │  └──────────────┘  └──────────────┘  └─────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│          │                    │                    │              │
│          ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │  PostgreSQL  │    │  Redis Cache │    │  WASM Sandbox    │   │
│  │  (Ledger,    │    │  (Nonces,    │    │  (Wasmtime in    │   │
│  │   Keys)      │    │   Rate       │    │   isolated       │   │
│  │              │    │   Limits)    │    │   container)     │   │
│  └──────────────┘    └──────────────┘    └──────────────────┘   │
│         │                                          │              │
│         ▼                                          ▼              │
│  ┌──────────────┐                        ┌──────────────────┐   │
│  │   Backup &   │                        │  Artifact Store  │   │
│  │   Archive    │                        │  (S3-compatible) │   │
│  └──────────────┘                        └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

#### Python Miner SDK
**Purpose:** Enable ML engineers to participate without blockchain or cryptography expertise.

**Core Functions:**
- Task fetching with automatic retry and backoff
- Optuna integration for hyperparameter optimization
- Reproducibility package generation (`train.wasm` + metadata)
- Ed25519 key generation and secure storage
- Payload signing and claim submission
- Automatic nonce generation (UUID v4)

**Security Boundary:** This is untrusted code running on untrusted hardware. It can be malicious.

#### Rust Notary Server
**Purpose:** The security-critical gatekeeper to the ledger.

**Core Functions:**
- Task distribution via `/api/v1/task`
- Claim ingestion via `/api/v1/submit`
- Cryptographic signature verification
- Replay attack prevention (nonce checking)
- Integrity verification (SHA256 hash validation)
- Sandbox orchestration (WASM execution)
- Ledger persistence (PostgreSQL writes)
- Observability (structured logging, metrics export)

**Security Guarantees:**
- Memory-safe (Rust)
- No unsafe blocks in API handlers
- All database queries use parameterized statements (sqlx)
- TLS termination with strong cipher suites only
- Rate limiting enforced before signature verification

#### PostgreSQL Database
**Schema:**
```sql
-- Public keys registered for claim submission
CREATE TABLE miner_keys (
    miner_id UUID PRIMARY KEY,
    public_key_hex TEXT NOT NULL UNIQUE,
    stake_amount DECIMAL(18,8) NOT NULL DEFAULT 0,
    registration_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    revocation_timestamp TIMESTAMPTZ,
    INDEX idx_active_keys (is_active) WHERE is_active = TRUE
);

-- The immutable ledger of verified claims
CREATE TABLE ledger (
    id BIGSERIAL PRIMARY KEY,
    submission_id UUID NOT NULL UNIQUE,
    miner_id UUID NOT NULL REFERENCES miner_keys(miner_id),
    task_id TEXT NOT NULL,
    claimed_score DECIMAL(10,8) NOT NULL,
    verified_score DECIMAL(10,8) NOT NULL,
    artifact_hash TEXT NOT NULL,
    artifact_uri TEXT NOT NULL,
    signature_hex TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    verification_duration_ms INTEGER NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    INDEX idx_task_scores (task_id, verified_score DESC),
    INDEX idx_miner_submissions (miner_id, timestamp DESC)
);

-- Task definitions (admin-managed)
CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    performance_threshold DECIMAL(10,8) NOT NULL,
    dataset_hash TEXT NOT NULL,
    optuna_storage_url TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### Redis Cache
**Data Structures:**
```
# Replay protection (TTL: 24 hours)
SET seen_nonces:{signature_hex} 1 EX 86400

# Rate limiting (sliding window)
INCR rate_limit:{miner_id}:{window_timestamp}
EXPIRE rate_limit:{miner_id}:{window_timestamp} 3600

# Active sandbox jobs (for monitoring)
SADD sandbox_queue {submission_id}
```

#### WASM Sandbox
**Isolation Model:**
- Runs inside Docker container with:
  - No network access (`--network=none`)
  - Read-only filesystem except `/tmp`
  - Memory limit (4GB)
  - CPU time limit (10 minutes)
  - No access to host device files

**Execution Flow:**
1. Receive artifact package from Notary Server
2. Extract `train.wasm` and `hyperparameters.json`
3. Instantiate WASM module with Wasmtime
4. Inject hyperparameters via WASI environment
5. Execute training function
6. Capture final performance score
7. Compare to claimed score (tolerance: 0.001)
8. Report PASS/FAIL to Notary Server
9. Clean up all temporary files

---

## 3. The Core Workflow: End-to-End Verification

### 3.1 Happy Path (Success)

```
┌──────┐                ┌────────┐                ┌──────────┐
│Miner │                │ Server │                │ Sandbox  │
└───┬──┘                └───┬────┘                └────┬─────┘
    │                       │                          │
    │  GET /api/v1/task     │                          │
    │──────────────────────>│                          │
    │                       │                          │
    │  200 OK (task_spec)   │                          │
    │<──────────────────────│                          │
    │                       │                          │
    │ [LOCAL WORK]          │                          │
    │ - Run Optuna study    │                          │
    │ - Find best params    │                          │
    │ - Build WASM package  │                          │
    │ - Sign payload        │                          │
    │                       │                          │
    │ POST /api/v1/submit   │                          │
    │ (signed payload +     │                          │
    │  artifact package)    │                          │
    │──────────────────────>│                          │
    │                       │                          │
    │                       │ [VERIFICATION]           │
    │                       │ 1. Verify signature      │
    │                       │ 2. Check nonce (Redis)   │
    │                       │ 3. Verify hash           │
    │                       │                          │
    │                       │  Execute train.wasm      │
    │                       │─────────────────────────>│
    │                       │                          │
    │                       │                          │ [RUN]
    │                       │                          │ - Load WASM
    │                       │                          │ - Train model
    │                       │                          │ - Return score
    │                       │                          │
    │                       │  Score: 0.937 (PASS)     │
    │                       │<─────────────────────────│
    │                       │                          │
    │                       │ 4. Write to ledger (PG)  │
    │                       │ 5. Store artifact (S3)   │
    │                       │                          │
    │  202 Accepted         │                          │
    │<──────────────────────│                          │
    │                       │                          │
```

### 3.2 Failure Modes (Rejection)

**Authentication Failure:**
```
- Signature verification fails
- Public key not found in miner_keys table
- Miner account is revoked (is_active=FALSE)
→ 403 Forbidden: {"error": "authentication_failed"}
```

**Replay Attack:**
```
- Nonce already exists in seen_nonces Redis set
→ 403 Forbidden: {"error": "replay_detected", "nonce": "..."}
```

**Rate Limit Exceeded:**
```
- Miner exceeds 10 submissions per hour
→ 429 Too Many Requests: {"retry_after": 3600}
```

**Integrity Failure:**
```
- Computed SHA256 != claimed hash in payload
→ 400 Bad Request: {"error": "hash_mismatch"}
```

**Verification Failure:**
```
- Sandbox reports score: 0.845 (below threshold of 0.925)
- OR: Sandbox score: 0.930 but claimed score: 0.960 (delta > 0.001)
- OR: Sandbox execution timeout (>10 minutes)
- OR: Sandbox error (OOM, crash, invalid WASM)
→ 422 Unprocessable Entity: {"error": "verification_failed", "details": "..."}
→ Stake slashing triggered for miner_id
```

---

## 4. API Specification (Version 1)

### 4.1 Authentication Model

All `/api/v1/submit` requests must include:
- **Header:** `X-Signature: <hex_encoded_ed25519_signature>`
- **Body (multipart):** JSON payload + artifact file

The signature is computed over the **entire JSON payload string** (canonicalized, no whitespace variations).

### 4.2 Endpoints

#### `GET /api/v1/task`

**Purpose:** Fetch the current active task specification.

**Request:**
```http
GET /api/v1/task HTTP/1.1
Host: notary.ml-chain.network
```

**Response (200 OK):**
```json
{
  "task_id": "image-classification-cifar10-v2",
  "performance_threshold": 0.925,
  "metric": "test_accuracy",
  "dataset_hash": "sha256:a3f2c8b...",
  "optuna_storage_url": "postgresql://public:***@db.ml-chain.network:5432/optuna",
  "wasm_template_url": "https://artifacts.ml-chain.network/templates/train_template_v2.wasm",
  "max_training_time_seconds": 600,
  "expires_at": "2025-12-01T00:00:00Z"
}
```

**Caching:** This endpoint is heavily cached (Redis, 5-minute TTL). Tasks change infrequently.

---

#### `POST /api/v1/submit`

**Purpose:** Submit a signed claim for verification.

**Request:**
```http
POST /api/v1/submit HTTP/1.1
Host: notary.ml-chain.network
Content-Type: multipart/form-data; boundary=----Boundary123
X-Signature: 8f3a2c1b... (hex-encoded Ed25519 signature)

------Boundary123
Content-Disposition: form-data; name="payload"

{
  "miner_id": "550e8400-e29b-41d4-a716-446655440000",
  "task_id": "image-classification-cifar10-v2",
  "claimed_score": 0.9372,
  "artifact_hash": "sha256:b7f4c2a...",
  "timestamp": "2025-11-11T14:32:10Z",
  "nonce": "7c9e6679-7425-40de-944b-e07fc1f90ae7"
}
------Boundary123
Content-Disposition: form-data; name="artifact"; filename="submission.tar.gz"
Content-Type: application/gzip

[binary data]
------Boundary123--
```

**Signature Generation (Python SDK):**
```python
import json
import nacl.signing
import nacl.encoding

# Canonicalize payload (no whitespace variation)
payload = {
    "miner_id": str(miner_id),
    "task_id": task_id,
    "claimed_score": float(score),
    "artifact_hash": f"sha256:{hash_hex}",
    "timestamp": timestamp_iso,
    "nonce": str(uuid.uuid4())
}
payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

# Sign with private key
signing_key = nacl.signing.SigningKey(private_key_bytes)
signed = signing_key.sign(payload_bytes)
signature_hex = signed.signature.hex()
```

**Success Response (202 Accepted):**
```json
{
  "status": "pending_verification",
  "submission_id": "a7b3c9d2-...",
  "estimated_verification_time_seconds": 180
}
```

**Error Responses:**
- `400 Bad Request`: Malformed payload, hash mismatch
- `403 Forbidden`: Authentication failure, replay detected
- `422 Unprocessable Entity`: Verification failed (score mismatch, execution error)
- `429 Too Many Requests`: Rate limit exceeded
- `503 Service Unavailable`: Sandbox queue full

---

## 5. Threat Model & Attack Vectors

### 5.1 Threat Actor Profiles

#### T1: Opportunistic Spammer
- **Motivation:** Extract rewards with minimal effort
- **Capabilities:** Script automation, basic knowledge
- **Attack Vector:** Submit random hyperparameters or copied work
- **Mitigation:** Performance threshold, reproducibility verification

#### T2: Sophisticated Cheater
- **Motivation:** Maximize rewards through gaming the system
- **Capabilities:** Reverse engineering, cryptography knowledge
- **Attack Vector:** Replay attacks, signature forgery attempts, sandbox escape research
- **Mitigation:** Nonce tracking, Ed25519 (not forgeable), WASM isolation

#### T3: Malicious Insider
- **Motivation:** Disrupt the network or steal data
- **Capabilities:** Deep technical knowledge, potential access to infrastructure
- **Attack Vector:** Key extraction, ledger manipulation, DoS attacks
- **Mitigation:** Hardware security modules (future), audit logging, rate limiting

#### T4: Nation-State Actor
- **Motivation:** Intelligence gathering, sabotage
- **Capabilities:** Zero-day exploits, supply chain attacks
- **Attack Vector:** Wasmtime vulnerabilities, TLS downgrade, side-channel attacks
- **Mitigation:** Defense in depth, continuous security audits, bug bounty program

### 5.2 Attack Surface Analysis

| Component | Attack Vector | Likelihood | Impact | Mitigation Status |
|-----------|---------------|------------|--------|-------------------|
| TLS Layer | Downgrade attack, weak ciphers | Low | High | ✅ TLS 1.3 only, strong ciphers enforced |
| Ed25519 Verification | Side-channel timing attack | Low | Medium | ✅ Constant-time verification (ed25519-dalek) |
| PostgreSQL | SQL injection | Low | Critical | ✅ Parameterized queries (sqlx) |
| Redis | Command injection | Low | Medium | ✅ Typed client library (redis-rs) |
| WASM Sandbox | Escape via Wasmtime bug | Medium | Critical | 🔄 Continuous updates, container isolation |
| API Gateway | DDoS flood | High | Medium | ✅ Rate limiting, connection limits |
| Artifact Storage | Path traversal | Medium | High | ✅ UUID-based keys, no user-controlled paths |
| Nonce System | Replay after Redis TTL | Low | Medium | ✅ 24-hour TTL, ledger has permanent nonce records |

### 5.3 Specific Attack Scenarios

#### A1: The "Copy-Paste" Attack
**Attack:** Miner downloads a previously verified artifact, re-signs it with their own key, and resubmits.

**Detection:**
- The artifact_hash will match an existing ledger entry
- The signature will be different (different miner_id)

**Mitigation:**
- **Phase 1:** Accept but flag duplicate hashes (they still did valid work to discover it)
- **Phase 2:** Reduce rewards for duplicate discoveries (first-finder bonus)
- **Phase 3:** Require proof-of-search logs (Optuna trial history with signatures)

#### A2: The "Precomputation" Attack
**Attack:** Miner solves the task offline (or with insider knowledge), then submits a minimal-but-valid package without doing the "intended work."

**Detection:**
- Difficult to detect in Phase 1-2
- Requires proof-of-process, not just proof-of-result

**Mitigation:**
- **Phase 3+:** Require signed Optuna database dump showing trial history
- Verify timestamps and trial progression make sense
- Statistical analysis of submission patterns (too fast = suspicious)

#### A3: The "Sybil Submission" Attack
**Attack:** Create 1000 fake miner identities, submit 1000 variations of the same work.

**Detection:**
- All submissions from new identities with zero stake
- Similar artifact hashes or identical WASM blobs

**Mitigation:**
- **Staking requirement:** Must bond tokens before submitting
- **Reputation system:** New identities earn reduced rewards
- **Statistical clustering:** Detect coordinated multi-account behavior

#### A4: The "Sandbox Denial-of-Service" Attack
**Attack:** Submit WASM blobs with infinite loops or memory bombs to exhaust verification resources.

**Detection:**
- Sandbox timeout (>10 minutes)
- Memory limit exceeded
- CPU throttling detection

**Mitigation:**
- **Resource limits:** Hard timeout, memory cap, CPU quota
- **Progressive slashing:** First timeout = warning, repeated = stake slashed
- **Priority queue:** Staked miners get priority in verification queue

#### A5: The "Nonce Exhaustion" Attack
**Attack:** Pre-generate millions of valid signed payloads, then rapid-fire submit to exhaust nonce storage.

**Detection:**
- Rate limiting triggers before significant damage
- Redis memory usage spikes

**Mitigation:**
- **Rate limiting:** 10 submissions/hour per miner
- **TTL enforcement:** Nonces expire after 24 hours
- **Economic cost:** Each submission costs stake, making flood attacks expensive

---

## 6. Economic Model & Game Theory

### 6.1 Incentive Structure (Phase 3+)

**Staking Requirements:**
- Minimum stake to register: **100 credits** (≈ $100 USD equivalent)
- Stake locked during verification period
- Stake returned upon successful verification
- Stake slashed upon failed verification

**Slashing Schedule:**
```
Failed Verification Reason           → Slash Amount
────────────────────────────────────────────────────
Hash mismatch (integrity failure)    → 100% (fraud)
Score below threshold                → 50% (low effort)
Sandbox timeout/error                → 25% (bad package)
Replay attack detected               → 100% (malicious)
```

**Reward Distribution:**
```
Verified Score    Stake Amount    Task Pool    → Reward
──────────────────────────────────────────────────────
0.925-0.940       100 credits     1000 credits → 50 credits
0.941-0.960       100 credits     1000 credits → 100 credits
0.961-0.980       100 credits     1000 credits → 200 credits
0.981+            100 credits     1000 credits → 400 credits
```

**First-Finder Bonus:**
- First miner to discover a unique solution (artifact_hash): **+50% reward**
- Subsequent miners with same hash: Standard reward
- Encourages diversity of exploration

### 6.2 Game-Theoretic Analysis

**Honest Strategy:**
- Invest compute time in genuine Optuna study
- Submit high-quality, reproducible package
- Expected value: `P(verify) × reward - stake_risk`
- For skilled miners: `0.95 × 100 - 0.05 × 50 = 92.5 credits net`

**Spam Strategy:**
- Submit random/minimal effort work
- Expected value: `P(verify) × reward - stake_risk`
- For spammers: `0.10 × 50 - 0.90 × 50 = -40 credits net`

**Nash Equilibrium:**
- Honest participation is the dominant strategy
- Spam is economically irrational
- Reputation effects amplify this (repeat participants earn trust bonuses)

---

## 7. Implementation Roadmap

### Phase 1: Foundation (Months 1-2)
**Goal:** Establish development infrastructure.

**Deliverables:**
- [ ] Git repository with CI/CD (GitHub Actions or GitLab CI)
- [ ] `docker-compose.yml` for local dev environment
  - PostgreSQL 15
  - Redis 7
  - Rust server skeleton
  - Python SDK skeleton
- [ ] Automated testing framework
  - Rust: `cargo test` + `cargo clippy`
  - Python: `pytest` + `mypy`
- [ ] Security linting
  - `cargo audit` for Rust dependencies
  - `bandit` for Python code
  - Dependency vulnerability scanning

**Success Criteria:**
- Developer can run `make dev` and have a working local environment
- All tests pass on every commit (CI enforced)

---

### Phase 2: Core Loop (Months 3-4)
**Goal:** Implement the minimal viable verification pipeline.

**Deliverables:**
- [ ] Rust server with functional endpoints
  - `GET /api/v1/task` (serves hardcoded task)
  - `POST /api/v1/submit` (accepts payloads, no verification yet)
- [ ] PostgreSQL schema deployed
  - `miner_keys`, `ledger`, `tasks` tables
  - Indexes and constraints enforced
- [ ] Python SDK with core functions
  - `fetch_task()`
  - `create_package(hyperparameters, wasm_blob)`
  - `sign_payload(payload, private_key)`
  - `submit_claim(payload, artifact, signature)`
- [ ] Ed25519 signature verification working end-to-end
- [ ] Redis integration for nonce tracking

**Success Criteria:**
- A developer can run the Python SDK locally
- Submit a signed claim
- Server verifies signature and persists to ledger
- Re-submitting the same signature fails (replay protection works)

---

### Phase 3: Sandbox Integration (Months 5-6)
**Goal:** Add the WASM verification layer.

**Deliverables:**
- [ ] Wasmtime integration in Rust server
  - Spawn isolated sandbox process
  - Execute `train.wasm` with resource limits
  - Capture stdout/stderr and exit code
- [ ] Docker container for sandbox
  - `--network=none`, read-only rootfs
  - Memory limit: 4GB, CPU limit: 10 minutes
- [ ] Artifact storage (S3-compatible)
  - MinIO for dev, AWS S3 for production
  - Signed URL generation for artifact access
- [ ] Full verification pipeline
  - Signature → Nonce → Hash → Sandbox → Ledger
  - Detailed error reporting at each stage

**Success Criteria:**
- Submit a valid claim with a WASM artifact
- Server verifies reproducibility in the sandbox
- Ledger entry shows `verified_score` matching `claimed_score`
- Submit an invalid claim (wrong score), verification fails, ledger is unchanged

---

### Phase 4: Hardening & Economics (Months 7-9)
**Goal:** Make the system production-ready.

**Deliverables:**
- [ ] Staking system
  - Miner registration requires bonded stake
  - Slashing logic implemented
  - Stake return after successful verification
- [ ] Rate limiting with tiered quotas
  - Authenticated users: 10/hour
  - Premium users: 50/hour
  - Admin users: unlimited
- [ ] Observability infrastructure
  - Prometheus metrics export
  - Grafana dashboards (latency, throughput, error rates)
  - Structured logging (JSON, ELK stack)
  - Distributed tracing (Jaeger or Tempo)
- [ ] Admin API for governance
  - `POST /admin/tasks` (create new tasks)
  - `POST /admin/revoke_key` (revoke compromised keys)
  - `GET /admin/ledger` (audit trail export)
- [ ] Security audit (external)
  - Penetration testing
  - Code review by third-party firm
  - Cryptographic validation

**Success Criteria:**
- System handles 100 concurrent submissions without degradation
- A malicious miner submitting invalid claims loses their stake
- Admins can manage tasks and revoke keys via secure API
- External audit report shows no critical vulnerabilities

---

### Phase 5: Private Beta (Months 10-12)
**Goal:** Onboard real miners and collect feedback.

**Deliverables:**
- [ ] Public documentation site
  - API reference (OpenAPI/Swagger)
  - Python SDK tutorial
  - Example Optuna integration
  - Troubleshooting guide
- [ ] Monitoring and alerting
  - PagerDuty integration for critical errors
  - Slack notifications for suspicious activity
- [ ] Governance framework
  - Multisig admin wallet for key decisions
  - Transparent task selection process
  - Public ledger explorer (read-only web UI)
- [ ] Onboarding pipeline
  - KYC for initial beta miners (anti-Sybil)
  - Faucet for test stakes
  - Community Discord/Telegram

**Success Criteria:**
- 50+ active miners successfully submit verified claims
- Ledger contains 500+ verified entries
- No security incidents or system downtime
- Positive feedback from beta participants

---

## 8. Testing & Validation Strategy

### 8.1 Unit Tests (Rust Server)
**Coverage Target:** 80%+ for critical paths.

**Key Test Cases:**
```rust
#[cfg(test)]
mod tests {
    // Signature verification
    #[test]
    fn test_valid_signature_accepts() { ... }
    
    #[test]
    fn test_invalid_signature_rejects() { ... }
    
    #[test]
    fn test_replay_attack_rejects() { ... }
    
    // Hash verification
    #[test]
    fn test_hash_mismatch_rejects() { ... }
    
    // Rate limiting
    #[test]
    fn test_rate_limit_enforced() { ... }
    
    // Database interactions
    #[test]
    fn test_ledger_write_atomic() { ... }
}
```

### 8.2 Integration Tests (Python SDK + Server)
**Test Environment:** Docker Compose with all services.

**Test Scenarios:**
```python
def test_happy_path_submission():
    """Complete flow: fetch task → train → submit → verify"""
    pass

def test_replay_attack_blocked():
    """Submit same signature twice, second attempt fails"""
    pass

def test_hash_tampering_detected():
    """Modify artifact after signing, server rejects"""
    pass

def test_low_score_rejected():
    """Submit score below threshold, verification fails"""
    pass
```

### 8.3 Chaos Engineering (Production)
**Tool:** LitmusChaos or Chaos Mesh

**Experiments:**
- Kill random PostgreSQL connections during submission
- Introduce 50% packet loss to Redis
- Terminate sandbox containers mid-execution
- Spike traffic to 10x normal load

**Success Criteria:**
- System degrades gracefully (no data corruption)
- Circuit breakers prevent cascade failures
- Recovery is automatic (no manual intervention)

### 8.4 Security Testing
**Continuous:**
- `cargo audit` on every build
- Dependabot for dependency updates
- OWASP ZAP for web vulnerability scanning

**Pre-Release:**
- Manual penetration testing
- Fuzzing of API endpoints (AFL or libFuzzer)
- Cryptographic validation (incorrect signature attempts)

---

## 9. Observability & Operations

### 9.1 Metrics (Prometheus)
```
# API
http_requests_total{endpoint="/api/v1/submit", status="202"}
http_request_duration_seconds{endpoint="/api/v1/submit", quantile="0.99"}

# Verification
verification_duration_seconds{outcome="success"}
verification_failures_total{reason="hash_mismatch"}
sandbox_executions_total{result="pass"}

# Database
postgres_query_duration_seconds{query="insert_ledger"}
redis_command_duration_seconds{command="get"}

# Business
ledger_entries_total
unique_miners_active
average_claimed_score
```

### 9.2 Logging (Structured JSON)
```json
{
  "timestamp": "2025-11-11T14:32:10.123Z",
  "level": "INFO",
  "message": "Claim verified successfully",
  "miner_id": "550e8400-...",
  "submission_id": "a7b3c9d2-...",
  "claimed_score": 0.9372,
  "verified_score": 0.9371,
  "verification_duration_ms": 8234
}
```

**Log Levels:**
- ERROR: Authentication failures, verification failures, database errors
- WARN: Rate limit hits, nonce collisions, slow queries
- INFO: Successful verifications, ledger writes
- DEBUG: Request payloads, signature details (dev only)

### 9.3 Alerts
**Critical (Page Immediately):**
- Postgres down for >30 seconds
- Redis down for >30 seconds
- Error rate >5% for 5 minutes
- Ledger write failure

**Warning (Slack Notification):**
- Verification queue depth >50
- Average verification time >5 minutes
- Unusual rate limit hits (potential DDoS)
- Suspicious pattern detected (same IP, many identities)

---

## 10. Future Work & Open Questions

### 10.1 Decentralization Path
**Question:** How do we eliminate the single trusted Notary Server?

**Potential Approaches:**
1. **Notary Federation:** Multiple independent operators run replicas, require 2/3 consensus
2. **Blockchain Integration:** Migrate ledger to smart contract (Ethereum, Solana, Cosmos)
3. **zkSNARK Verification:** Replace WASM sandbox with zero-knowledge proofs of computation

**Trade-offs:**
- Federation: Simpler, but still semi-centralized
- Blockchain: True decentralization, but high gas costs and latency
- zkSNARKs: Cryptographically perfect, but requires GPU for proof generation

### 10.2 Proof-of-Process
**Question:** How do we verify the *method* of discovery, not just the result?

**Proposal:**
- Require miners to submit signed Optuna database dump
- Each trial in the study is signed with a timestamp
- Server verifies trial progression is chronologically valid
- Random audits: Run a subset of trials to ensure reproducibility

**Challenges:**
- Increases artifact size significantly
- Adds complexity to verification pipeline
- Miners could still "cherry-pick" trials post-hoc

### 10.3 Confidential Computing
**Question:** Can we verify proprietary models without exposing the model itself?

**Potential Approaches:**
- Intel SGX or AMD SEV for encrypted sandbox execution
- Homomorphic encryption (impractical for ML training currently)
- Federated verification with trusted enclaves

---

## 11. Conclusion

This blueprint represents a hardened, production-oriented approach to verifiable machine learning computation. It is not a research prototype; it is a system designed to be built by a professional engineering team and deployed to real users.

**What We Have:**
- A clear architectural vision (Rust + Python + WASM)
- Cryptographic security model (Ed25519, SHA256)
- Economic incentive structure (staking/slashing)
- Detailed threat model and mitigations
- Phased implementation roadmap

**What We Need:**
- A committed engineering team (2 Rust engineers, 1 Python engineer, 1 DevOps/SRE, 1 security specialist)
- 12 months of focused execution
- External security audit before production launch
- Community engagement and governance framework

**The Mission:**
To build the first production-grade system for verifiable ML computation, where trust is replaced by cryptographic proof, and where any claim can be independently validated by anyone.

The blueprint is complete. The path is clear. Now, we build.

---

**Document Approval:**
- [ ] Technical Architecture Review
- [ ] Security Review
- [ ] Economic Model Validation
- [ ] Executive Sponsor Sign-Off

**Next Steps:**
1. Assemble the engineering team
2. Set up development infrastructure (Phase 1)
3. Begin weekly sprint planning
4. Target Phase 2 completion by end of Q1 2026

**Contact:**
- Technical Lead: [TBD]
- Security Lead: [TBD]
- Project Manager: [TBD]