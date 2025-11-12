"""
ML-Chain Miner SDK
Production-grade client library for submitting verifiable ML claims.

Installation:
    pip install ml-chain-sdk nacl requests optuna

Usage:
    from ml_chain_sdk import MinerClient, create_reproducibility_package
    
    client = MinerClient(private_key_path="~/.ml-chain/key.pem")
    task = client.fetch_task()
    # ... perform training ...
    client.submit_claim(score=0.937, artifact_path="model.tar.gz")
"""

import hashlib
import json
import os
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import nacl.encoding
import nacl.signing
import requests


# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_NOTARY_URL = "https://notary.ml-chain.network"
DEFAULT_KEY_PATH = Path.home() / ".ml-chain" / "key.pem"


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class TaskSpec:
    """Specification for the current active task."""
    task_id: str
    performance_threshold: float
    metric: str
    dataset_hash: str
    optuna_storage_url: str
    wasm_template_url: str
    max_training_time_seconds: int
    expires_at: str


@dataclass
class SubmissionResult:
    """Result of a claim submission."""
    submission_id: str
    status: str
    estimated_verification_time_seconds: int


# ============================================================================
# CRYPTOGRAPHIC UTILITIES
# ============================================================================

def generate_keypair(output_path: Path) -> tuple[str, str]:
    """
    Generate a new Ed25519 keypair and save to disk.
    
    Returns:
        (private_key_hex, public_key_hex)
    """
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    
    # Save private key securely (0600 permissions)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(signing_key.encode())
    os.chmod(output_path, 0o600)
    
    private_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    public_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    
    print(f"✓ Keypair generated and saved to {output_path}")
    print(f"✓ Public key: {public_hex}")
    print(f"⚠ Register this public key with the notary server before submitting")
    
    return private_hex, public_hex


def load_private_key(path: Path) -> nacl.signing.SigningKey:
    """Load Ed25519 private key from disk."""
    if not path.exists():
        raise FileNotFoundError(
            f"Private key not found at {path}. "
            f"Generate one with: ml-chain-sdk generate-key"
        )
    
    with open(path, 'rb') as f:
        return nacl.signing.SigningKey(f.read())


def sign_payload(payload: dict, signing_key: nacl.signing.SigningKey) -> str:
    """
    Sign a payload with Ed25519.
    
    Args:
        payload: Dictionary to sign (will be canonicalized)
        signing_key: Ed25519 signing key
    
    Returns:
        Hex-encoded signature
    """
    # Canonicalize JSON (sorted keys, no whitespace)
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    payload_bytes = canonical_json.encode('utf-8')
    
    # Sign
    signed = signing_key.sign(payload_bytes)
    return signed.signature.hex()


def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


# ============================================================================
# REPRODUCIBILITY PACKAGE BUILDER
# ============================================================================

def create_reproducibility_package(
    hyperparameters: dict,
    wasm_blob_path: Path,
    output_path: Optional[Path] = None
) -> Path:
    """
    Create a reproducibility package (tarball) containing:
    - hyperparameters.json: The discovered hyperparameters
    - train.wasm: The compiled training binary
    
    Args:
        hyperparameters: Dictionary of hyperparameters
        wasm_blob_path: Path to the pre-compiled train.wasm file
        output_path: Where to save the tarball (default: temp file)
    
    Returns:
        Path to the created tarball
    """
    if output_path is None:
        fd, output_path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(fd)
        output_path = Path(output_path)
    
    with tarfile.open(output_path, "w:gz") as tar:
        # Add hyperparameters.json
        hp_json = json.dumps(hyperparameters, indent=2)
        hp_info = tarfile.TarInfo(name="hyperparameters.json")
        hp_info.size = len(hp_json)
        tar.addfile(hp_info, fileobj=tarfile.io.BytesIO(hp_json.encode('utf-8')))
        
        # Add train.wasm
        tar.add(wasm_blob_path, arcname="train.wasm")
    
    print(f"✓ Reproducibility package created: {output_path}")
    return output_path


# ============================================================================
# MINER CLIENT
# ============================================================================

class MinerClient:
    """
    High-level client for interacting with the ML-Chain notary server.
    
    Example:
        client = MinerClient(private_key_path="~/.ml-chain/key.pem")
        task = client.fetch_task()
        
        # ... run Optuna study ...
        
        package = create_reproducibility_package(
            hyperparameters=best_params,
            wasm_blob_path="train.wasm"
        )
        
        result = client.submit_claim(
            task_id=task.task_id,
            claimed_score=0.937,
            artifact_path=package
        )
        
        print(f"Submission ID: {result.submission_id}")
    """
    
    def __init__(
        self,
        private_key_path: Path = DEFAULT_KEY_PATH,
        notary_url: str = DEFAULT_NOTARY_URL,
        miner_id: Optional[str] = None
    ):
        """
        Initialize the miner client.
        
        Args:
            private_key_path: Path to Ed25519 private key
            notary_url: Base URL of the notary server
            miner_id: UUID of the registered miner (if None, derived from public key)
        """
        self.notary_url = notary_url.rstrip('/')
        self.signing_key = load_private_key(Path(private_key_path))
        self.verify_key = self.signing_key.verify_key
        
        # Miner ID is typically registered separately, but we derive a stable ID
        # from the public key for convenience in development
        if miner_id is None:
            pub_hex = self.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
            # Use first 32 chars of public key to seed UUID (reproducible)
            self.miner_id = str(uuid.UUID(pub_hex[:32]))
        else:
            self.miner_id = miner_id
        
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ml-chain-sdk/0.1.0'})
    
    def fetch_task(self) -> TaskSpec:
        """
        Fetch the current active task from the notary server.
        
        Returns:
            TaskSpec object with task details
        
        Raises:
            requests.HTTPError: If the request fails
        """
        response = self.session.get(f"{self.notary_url}/api/v1/task")
        response.raise_for_status()
        data = response.json()
        
        return TaskSpec(
            task_id=data['task_id'],
            performance_threshold=data['performance_threshold'],
            metric=data['metric'],
            dataset_hash=data['dataset_hash'],
            optuna_storage_url=data['optuna_storage_url'],
            wasm_template_url=data['wasm_template_url'],
            max_training_time_seconds=data['max_training_time_seconds'],
            expires_at=data['expires_at']
        )
    
    def submit_claim(
        self,
        task_id: str,
        claimed_score: float,
        artifact_path: Path
    ) -> SubmissionResult:
        """
        Submit a signed claim to the notary server.
        
        Args:
            task_id: ID of the task being solved
            claimed_score: Performance score achieved
            artifact_path: Path to the reproducibility package (.tar.gz)
        
        Returns:
            SubmissionResult with submission details
        
        Raises:
            requests.HTTPError: If submission fails
            ValueError: If claimed_score is invalid
        """
        if not 0.0 <= claimed_score <= 1.0:
            raise ValueError(f"claimed_score must be in [0, 1], got {claimed_score}")
        
        # Compute artifact hash
        artifact_hash = compute_sha256(artifact_path)
        
        # Build payload
        payload = {
            "miner_id": self.miner_id,
            "task_id": task_id,
            "claimed_score": claimed_score,
            "artifact_hash": artifact_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": str(uuid.uuid4())
        }
        
        # Sign payload
        signature_hex = sign_payload(payload, self.signing_key)
        
        # Prepare multipart request
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature_hex),
            'artifact': (artifact_path.name, open(artifact_path, 'rb'), 'application/gzip')
        }
        
        print(f"→ Submitting claim to {self.notary_url}/api/v1/submit")
        print(f"  Miner ID: {self.miner_id}")
        print(f"  Task ID: {task_id}")
        print(f"  Claimed score: {claimed_score}")
        print(f"  Artifact hash: {artifact_hash}")
        
        # Submit
        response = self.session.post(
            f"{self.notary_url}/api/v1/submit",
            files=files
        )
        
        # Handle response
        if response.status_code == 202:
            data = response.json()
            result = SubmissionResult(
                submission_id=data['submission_id'],
                status=data['status'],
                estimated_verification_time_seconds=data['estimated_verification_time_seconds']
            )
            print(f"✓ Submission accepted: {result.submission_id}")
            return result
        else:
            error_data = response.json()
            print(f"✗ Submission failed: {error_data.get('error')}")
            print(f"  Details: {error_data.get('details')}")
            response.raise_for_status()


# ============================================================================
# OPTUNA INTEGRATION HELPER
# ============================================================================

def run_optuna_study(
    task_spec: TaskSpec,
    objective_fn,
    n_trials: int = 100,
    timeout: int = 3600
):
    """
    Helper to run an Optuna study with best practices.
    
    Args:
        task_spec: Task specification from fetch_task()
        objective_fn: Optuna objective function
        n_trials: Number of trials to run
        timeout: Maximum time in seconds
    
    Returns:
        (best_params, best_score)
    """
    import optuna
    
    # Connect to shared Optuna storage
    study = optuna.create_study(
        study_name=f"{task_spec.task_id}-{uuid.uuid4().hex[:8]}",
        storage=task_spec.optuna_storage_url,
        direction='maximize',
        load_if_exists=False
    )
    
    print(f"→ Starting Optuna study: {study.study_name}")
    print(f"  Target threshold: {task_spec.performance_threshold}")
    print(f"  Max trials: {n_trials}")
    
    # Run optimization
    study.optimize(
        objective_fn,
        n_trials=n_trials,
        timeout=timeout,
        show_progress_bar=True
    )
    
    best_params = study.best_params
    best_score = study.best_value
    
    print(f"✓ Study complete!")
    print(f"  Best score: {best_score:.4f}")
    print(f"  Best params: {best_params}")
    
    if best_score < task_spec.performance_threshold:
        print(f"⚠ Warning: Best score below threshold ({task_spec.performance_threshold})")
        print(f"  Submission will likely fail verification")
    
    return best_params, best_score


# ============================================================================
# CLI INTERFACE (if run as script)
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ml_chain_sdk.py generate-key [output_path]")
        print("  python ml_chain_sdk.py fetch-task")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "generate-key":
        output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_KEY_PATH
        generate_keypair(output_path)
    
    elif command == "fetch-task":
        client = MinerClient()
        task = client.fetch_task()
        print(json.dumps(task.__dict__, indent=2))
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
