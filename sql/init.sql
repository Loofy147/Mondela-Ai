-- ML-Chain Database Schema
-- Automatically executed when PostgreSQL container starts

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- MINER KEYS (Public Key Registry)
-- ============================================================================
CREATE TABLE IF NOT EXISTS miner_keys (
    miner_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    public_key_hex TEXT NOT NULL UNIQUE,
    stake_amount DECIMAL(18, 8) NOT NULL DEFAULT 0.0,
    registration_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    revocation_timestamp TIMESTAMPTZ,
    revocation_reason TEXT,

    -- Constraints
    CONSTRAINT stake_non_negative CHECK (stake_amount >= 0),
    CONSTRAINT revoked_has_timestamp CHECK (
        (is_active = TRUE AND revocation_timestamp IS NULL) OR
        (is_active = FALSE AND revocation_timestamp IS NOT NULL)
    )
);

-- Indexes
CREATE INDEX idx_miner_keys_active ON miner_keys(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_miner_keys_public_key ON miner_keys(public_key_hex);

-- ============================================================================
-- LEDGER (Immutable Record of Verified Claims)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ledger (
    id BIGSERIAL PRIMARY KEY,
    submission_id UUID NOT NULL UNIQUE,
    miner_id UUID NOT NULL REFERENCES miner_keys(miner_id),
    task_id TEXT NOT NULL,
    claimed_score DECIMAL(10, 8) NOT NULL,
    verified_score DECIMAL(10, 8) NOT NULL,
    artifact_hash TEXT NOT NULL,
    artifact_uri TEXT NOT NULL,
    signature_hex TEXT NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verification_duration_ms INTEGER NOT NULL,
    nonce TEXT NOT NULL UNIQUE,

    -- Constraints
    CONSTRAINT score_range CHECK (
        claimed_score >= 0.0 AND claimed_score <= 1.0 AND
        verified_score >= 0.0 AND verified_score <= 1.0
    ),
    CONSTRAINT verification_duration_positive CHECK (verification_duration_ms > 0)
);

-- Indexes for common queries
CREATE INDEX idx_ledger_task_scores ON ledger(task_id, verified_score DESC);
CREATE INDEX idx_ledger_miner_submissions ON ledger(miner_id, timestamp DESC);
CREATE INDEX idx_ledger_timestamp ON ledger(timestamp DESC);
CREATE INDEX idx_ledger_nonce ON ledger(nonce);
CREATE INDEX idx_ledger_signature ON ledger(signature_hex);

-- ============================================================================
-- TASKS (Admin-Managed Task Definitions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    performance_threshold DECIMAL(10, 8) NOT NULL,
    metric TEXT NOT NULL,
    dataset_hash TEXT NOT NULL,
    optuna_storage_url TEXT NOT NULL,
    wasm_template_url TEXT NOT NULL,
    max_training_time_seconds INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT threshold_range CHECK (
        performance_threshold >= 0.0 AND performance_threshold <= 1.0
    ),
    CONSTRAINT max_time_positive CHECK (max_training_time_seconds > 0)
);

-- Index
CREATE INDEX idx_tasks_active ON tasks(is_active) WHERE is_active = TRUE;

-- ============================================================================
-- AUDIT LOG (Security Events)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    miner_id UUID,
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_miner ON audit_log(miner_id);

-- ============================================================================
-- INITIAL DATA (Development)
-- ============================================================================

-- Insert a test task
INSERT INTO tasks (
    task_id,
    performance_threshold,
    metric,
    dataset_hash,
    optuna_storage_url,
    wasm_template_url,
    max_training_time_seconds,
    expires_at
) VALUES (
    'image-classification-cifar10-v2',
    0.925,
    'test_accuracy',
    'sha256:a3f2c8b1d4e5f6789012345678901234',
    'postgresql://optuna:password@postgres:5432/optuna',
    'https://artifacts.ml-chain.network/train_v2.wasm',
    600,
    '2025-12-01T00:00:00Z'
) ON CONFLICT (task_id) DO NOTHING;

-- Insert a test miner (for development only)
INSERT INTO miner_keys (
    miner_id,
    public_key_hex,
    stake_amount
) VALUES (
    '550e8400-e29b-41d4-a716-446655440000',
    'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    100.0
) ON CONFLICT (miner_id) DO NOTHING;

-- Log initialization
INSERT INTO audit_log (event_type, details) VALUES (
    'database_initialized',
    ('{"version": "1.0.0", "timestamp": "' || NOW()::TEXT || '"}')::jsonb
);
