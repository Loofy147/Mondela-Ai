// Cargo.toml dependencies:
// [dependencies]
// axum = "0.7"
// tokio = { version = "1", features = ["full"] }
// sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls"] }
// redis = { version = "0.24", features = ["tokio-comp"] }
// ed25519-dalek = "2.1"
// hex = "0.4"
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// tower = "0.4"
// tower-http = { version = "0.5", features = ["cors", "trace"] }
// sha2 = "0.10"
// uuid = { version = "1", features = ["v4", "serde"] }
// chrono = { version = "0.4", features = ["serde"] }
// tracing = "0.1"
// tracing-subscriber = "0.3"

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

// ============================================================================
// CORE DATA STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaskSpec {
    task_id: String,
    performance_threshold: f64,
    metric: String,
    dataset_hash: String,
    optuna_storage_url: String,
    wasm_template_url: String,
    max_training_time_seconds: u64,
    expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaimPayload {
    miner_id: Uuid,
    task_id: String,
    claimed_score: f64,
    artifact_hash: String,
    timestamp: String,
    nonce: String,
}

#[derive(Debug, Serialize)]
struct SubmissionResponse {
    status: String,
    submission_id: Uuid,
    estimated_verification_time_seconds: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

// ============================================================================
// APPLICATION STATE
// ============================================================================

struct AppState {
    db: PgPool,
    redis: redis::Client,
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug)]
enum AppError {
    Database(sqlx::Error),
    Redis(redis::RedisError),
    InvalidSignature,
    ReplayDetected(String),
    HashMismatch,
    RateLimitExceeded,
    MinerNotFound,
    MinerRevoked,
    VerificationFailed(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_msg, details) = match self {
            AppError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error".to_string(),
                Some(e.to_string()),
            ),
            AppError::Redis(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "cache_error".to_string(),
                Some(e.to_string()),
            ),
            AppError::InvalidSignature => (
                StatusCode::FORBIDDEN,
                "authentication_failed".to_string(),
                Some("Invalid signature".to_string()),
            ),
            AppError::ReplayDetected(nonce) => (
                StatusCode::FORBIDDEN,
                "replay_detected".to_string(),
                Some(format!("Nonce already used: {}", nonce)),
            ),
            AppError::HashMismatch => (
                StatusCode::BAD_REQUEST,
                "hash_mismatch".to_string(),
                Some("Artifact hash does not match claimed hash".to_string()),
            ),
            AppError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded".to_string(),
                Some("Maximum 10 submissions per hour".to_string()),
            ),
            AppError::MinerNotFound => (
                StatusCode::FORBIDDEN,
                "authentication_failed".to_string(),
                Some("Miner ID not registered".to_string()),
            ),
            AppError::MinerRevoked => (
                StatusCode::FORBIDDEN,
                "account_revoked".to_string(),
                Some("This miner account has been revoked".to_string()),
            ),
            AppError::VerificationFailed(reason) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "verification_failed".to_string(),
                Some(reason),
            ),
        };

        let body = Json(ErrorResponse {
            error: error_msg,
            details,
        });

        (status, body).into_response()
    }
}

// ============================================================================
// CRYPTOGRAPHIC VERIFICATION
// ============================================================================

fn verify_signature(
    payload_bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), AppError> {
    // Decode hex signature
    let sig_bytes = hex::decode(signature_hex).map_err(|_| AppError::InvalidSignature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;

    // Decode hex public key
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| AppError::InvalidSignature)?;
    let public_key =
        VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| AppError::InvalidSignature)?)
            .map_err(|_| AppError::InvalidSignature)?;

    // Verify signature (constant-time operation)
    public_key
        .verify(payload_bytes, &signature)
        .map_err(|_| AppError::InvalidSignature)?;

    tracing::info!("Signature verification passed");
    Ok(())
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// ============================================================================
// DATABASE OPERATIONS
// ============================================================================

async fn get_miner_public_key(
    db: &PgPool,
    miner_id: Uuid,
) -> Result<(String, bool), AppError> {
    let row = sqlx::query!(
        r#"
        SELECT public_key_hex, is_active
        FROM miner_keys
        WHERE miner_id = $1
        "#,
        miner_id
    )
    .fetch_optional(db)
    .await
    .map_err(AppError::Database)?;

    match row {
        Some(r) => Ok((r.public_key_hex, r.is_active)),
        None => Err(AppError::MinerNotFound),
    }
}

async fn insert_ledger_entry(
    db: &PgPool,
    submission_id: Uuid,
    payload: &ClaimPayload,
    verified_score: f64,
    artifact_hash: &str,
    signature_hex: &str,
    verification_duration_ms: i32,
) -> Result<(), AppError> {
    sqlx::query!(
        r#"
        INSERT INTO ledger (
            submission_id, miner_id, task_id, claimed_score,
            verified_score, artifact_hash, artifact_uri,
            signature_hex, timestamp, verification_duration_ms, nonce
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
        submission_id,
        payload.miner_id,
        payload.task_id,
        payload.claimed_score,
        verified_score,
        artifact_hash,
        format!("s3://ml-chain-artifacts/{}", submission_id),
        signature_hex,
        chrono::Utc::now(),
        verification_duration_ms,
        payload.nonce
    )
    .execute(db)
    .await
    .map_err(AppError::Database)?;

    tracing::info!(
        submission_id = %submission_id,
        miner_id = %payload.miner_id,
        verified_score = verified_score,
        "Ledger entry committed"
    );

    Ok(())
}

// ============================================================================
// REDIS OPERATIONS (Nonce & Rate Limiting)
// ============================================================================

async fn check_and_mark_nonce(
    redis_client: &redis::Client,
    signature_hex: &str,
) -> Result<(), AppError> {
    let mut conn = redis_client
        .get_multiplexed_tokio_connection()
        .await
        .map_err(AppError::Redis)?;

    let key = format!("seen_nonces:{}", signature_hex);

    // Check if nonce exists
    let exists: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .map_err(AppError::Redis)?;

    if exists {
        return Err(AppError::ReplayDetected(signature_hex.to_string()));
    }

    // Mark nonce as seen (24 hour TTL)
    redis::cmd("SET")
        .arg(&key)
        .arg(1)
        .arg("EX")
        .arg(86400) // 24 hours
        .query_async::<_, ()>(&mut conn)
        .await
        .map_err(AppError::Redis)?;

    tracing::debug!("Nonce marked as seen: {}", signature_hex);
    Ok(())
}

async fn check_rate_limit(
    redis_client: &redis::Client,
    miner_id: Uuid,
) -> Result<(), AppError> {
    let mut conn = redis_client
        .get_multiplexed_tokio_connection()
        .await
        .map_err(AppError::Redis)?;

    // Sliding window: current hour
    let window = chrono::Utc::now().format("%Y-%m-%d-%H").to_string();
    let key = format!("rate_limit:{}:{}", miner_id, window);

    let count: i32 = redis::cmd("INCR")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .map_err(AppError::Redis)?;

    // Set expiry on first increment
    if count == 1 {
        redis::cmd("EXPIRE")
            .arg(&key)
            .arg(3600) // 1 hour
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(AppError::Redis)?;
    }

    // Enforce limit: 10 per hour
    if count > 10 {
        tracing::warn!(miner_id = %miner_id, count = count, "Rate limit exceeded");
        return Err(AppError::RateLimitExceeded);
    }

    tracing::debug!(miner_id = %miner_id, count = count, "Rate limit check passed");
    Ok(())
}

// ============================================================================
// SANDBOX VERIFICATION (STUB - Phase 3)
// ============================================================================

async fn verify_in_sandbox(
    _artifact_data: &[u8],
    claimed_score: f64,
) -> Result<f64, AppError> {
    // PHASE 3 TODO: Implement Wasmtime sandbox execution
    // For now, we simulate verification with a tolerance check

    // Simulate sandbox execution time
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // In Phase 3, this will:
    // 1. Extract train.wasm from artifact
    // 2. Spawn isolated Docker container
    // 3. Execute WASM with resource limits
    // 4. Capture performance score
    // 5. Compare with claimed_score

    let simulated_score = claimed_score; // In reality, this comes from sandbox
    let tolerance = 0.001;

    if (simulated_score - claimed_score).abs() > tolerance {
        return Err(AppError::VerificationFailed(format!(
            "Score mismatch: claimed {}, verified {}",
            claimed_score, simulated_score
        )));
    }

    tracing::info!(
        claimed = claimed_score,
        verified = simulated_score,
        "Sandbox verification passed"
    );

    Ok(simulated_score)
}

// ============================================================================
// API HANDLERS
// ============================================================================

async fn get_task(State(_state): State<Arc<AppState>>) -> Json<TaskSpec> {
    // Phase 1: Return hardcoded task
    // Phase 2+: Fetch from database
    Json(TaskSpec {
        task_id: "image-classification-cifar10-v2".to_string(),
        performance_threshold: 0.925,
        metric: "test_accuracy".to_string(),
        dataset_hash: "sha256:a3f2c8b1d4e5f6789012345678901234".to_string(),
        optuna_storage_url: "postgresql://optuna:***@db:5432/optuna".to_string(),
        wasm_template_url: "https://artifacts.ml-chain.network/train_v2.wasm".to_string(),
        max_training_time_seconds: 600,
        expires_at: "2025-12-01T00:00:00Z".to_string(),
    })
}

async fn submit_claim(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<SubmissionResponse>, AppError> {
    let start_time = std::time::Instant::now();
    let submission_id = Uuid::new_v4();

    // Extract multipart fields
    let mut payload_json: Option<String> = None;
    let mut signature_hex: Option<String> = None;
    let mut artifact_data: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        match name.as_str() {
            "payload" => payload_json = Some(field.text().await.unwrap()),
            "signature" => signature_hex = Some(field.text().await.unwrap()),
            "artifact" => artifact_data = Some(field.bytes().await.unwrap().to_vec()),
            _ => {}
        }
    }

    let payload_json = payload_json.ok_or(AppError::InvalidSignature)?;
    let signature_hex = signature_hex.ok_or(AppError::InvalidSignature)?;
    let artifact_data = artifact_data.ok_or(AppError::HashMismatch)?;

    // Parse payload
    let payload: ClaimPayload = serde_json::from_str(&payload_json)
        .map_err(|_| AppError::InvalidSignature)?;

    tracing::info!(
        submission_id = %submission_id,
        miner_id = %payload.miner_id,
        task_id = %payload.task_id,
        claimed_score = payload.claimed_score,
        "Processing submission"
    );

    // VERIFICATION GAUNTLET BEGINS

    // 1. Rate Limiting
    check_rate_limit(&state.redis, payload.miner_id).await?;

    // 2. Authentication
    let (public_key_hex, is_active) = get_miner_public_key(&state.db, payload.miner_id).await?;
    if !is_active {
        return Err(AppError::MinerRevoked);
    }

    verify_signature(payload_json.as_bytes(), &signature_hex, &public_key_hex)?;

    // 3. Replay Protection
    check_and_mark_nonce(&state.redis, &signature_hex).await?;

    // 4. Integrity Check
    let computed_hash = compute_sha256(&artifact_data);
    if computed_hash != payload.artifact_hash {
        tracing::error!(
            claimed = payload.artifact_hash,
            computed = computed_hash,
            "Hash mismatch detected"
        );
        return Err(AppError::HashMismatch);
    }

    // 5. Sandbox Verification
    let verified_score = verify_in_sandbox(&artifact_data, payload.claimed_score).await?;

    // 6. Persist to Ledger
    let duration_ms = start_time.elapsed().as_millis() as i32;
    insert_ledger_entry(
        &state.db,
        submission_id,
        &payload,
        verified_score,
        &computed_hash,
        &signature_hex,
        duration_ms,
    )
    .await?;

    tracing::info!(
        submission_id = %submission_id,
        duration_ms = duration_ms,
        "Submission verified and committed"
    );

    Ok(Json(SubmissionResponse {
        status: "verified".to_string(),
        submission_id,
        estimated_verification_time_seconds: 0,
    }))
}

// ============================================================================
// APPLICATION ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Database connection
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mlchain:password@localhost:5432/mlchain".to_string());
    let db = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    // Redis connection
    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let redis = redis::Client::open(redis_url)
        .expect("Failed to create Redis client");

    let state = Arc::new(AppState { db, redis });

    // Build router
    let app = Router::new()
        .route("/api/v1/task", get(get_task))
        .route("/api/v1/submit", post(submit_claim))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Run server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    tracing::info!("ML-Chain Notary Server listening on port 3000");

    axum::serve(listener, app).await.unwrap();
}
