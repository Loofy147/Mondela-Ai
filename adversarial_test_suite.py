"""
ML-Chain Red Team Test Suite
Adversarial testing framework designed to discover weaknesses.

This suite doesn't test for expected behavior - it actively tries to break the system.

Usage:
    pytest test_adversarial.py -v --html=report.html
    pytest test_adversarial.py -k "replay_attack" -v
"""

import hashlib
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import nacl.signing
import pytest
import requests


# ============================================================================
# TEST INFRASTRUCTURE
# ============================================================================

NOTARY_URL = "http://localhost:3000"


@pytest.fixture
def legitimate_miner():
    """Create a legitimate miner with valid credentials."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    
    # In real tests, this would be registered with the server
    miner_id = str(uuid.uuid4())
    
    return {
        'miner_id': miner_id,
        'signing_key': signing_key,
        'verify_key': verify_key,
        'public_key_hex': verify_key.encode().hex()
    }


@pytest.fixture
def valid_artifact(tmp_path):
    """Create a minimal valid artifact."""
    artifact_path = tmp_path / "artifact.tar.gz"
    
    # Create minimal tarball
    import tarfile
    with tarfile.open(artifact_path, "w:gz") as tar:
        # Add hyperparameters.json
        hp_json = json.dumps({"learning_rate": 0.001, "batch_size": 32})
        hp_info = tarfile.TarInfo(name="hyperparameters.json")
        hp_info.size = len(hp_json)
        tar.addfile(hp_info, fileobj=tarfile.io.BytesIO(hp_json.encode('utf-8')))
        
        # Add dummy train.wasm
        wasm_data = b"\x00asm\x01\x00\x00\x00"  # WASM magic number
        wasm_info = tarfile.TarInfo(name="train.wasm")
        wasm_info.size = len(wasm_data)
        tar.addfile(wasm_info, fileobj=tarfile.io.BytesIO(wasm_data))
    
    return artifact_path


def sign_payload(payload: dict, signing_key) -> str:
    """Sign a payload (helper function)."""
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    signed = signing_key.sign(canonical_json.encode('utf-8'))
    return signed.signature.hex()


def compute_hash(file_path: Path) -> str:
    """Compute SHA256 hash."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        hasher.update(f.read())
    return f"sha256:{hasher.hexdigest()}"


# ============================================================================
# ATTACK VECTOR 1: REPLAY ATTACKS
# ============================================================================

class TestReplayAttacks:
    """Test the system's resistance to replay attacks."""
    
    def test_simple_replay_same_signature(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Submit the same signed payload twice.
        EXPECTED: First succeeds, second is rejected with 403.
        """
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": compute_hash(valid_artifact),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        signature = sign_payload(payload, legitimate_miner['signing_key'])
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature),
            'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
        }
        
        # First submission
        resp1 = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        
        # Rewind file pointer for second attempt
        files['artifact'] = ('artifact.tar.gz', open(valid_artifact, 'rb'))
        
        # Second submission (replay attack)
        resp2 = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        
        # Validate
        assert resp1.status_code in [200, 202], "First submission should succeed"
        assert resp2.status_code == 403, "Replay attack should be blocked"
        assert "replay_detected" in resp2.json().get('error', '')
    
    def test_replay_with_different_nonce_same_signature(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Try to reuse a signature but claim it's for a different nonce.
        EXPECTED: Signature verification should fail because the signature
                  was computed over the original payload with the original nonce.
        """
        # Original payload
        original_payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": compute_hash(valid_artifact),
            "timestamp": time.time(),
            "nonce": "original-nonce-123"
        }
        
        signature = sign_payload(original_payload, legitimate_miner['signing_key'])
        
        # Modified payload (different nonce, but same signature)
        modified_payload = original_payload.copy()
        modified_payload['nonce'] = "malicious-nonce-456"
        
        files = {
            'payload': (None, json.dumps(modified_payload)),
            'signature': (None, signature),  # Reused signature!
            'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        
        # Should fail signature verification
        assert resp.status_code == 403
        assert "authentication_failed" in resp.json().get('error', '')
    
    def test_replay_after_24_hours(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Wait 24 hours for nonce to expire from Redis, then replay.
        EXPECTED: Should still fail because the nonce is also stored in
                  the permanent ledger (PostgreSQL).
        
        NOTE: This test would need time-travel or manual intervention.
              Here we document the expected behavior.
        """
        pytest.skip("Requires time-travel (Redis TTL expiry)")


# ============================================================================
# ATTACK VECTOR 2: SIGNATURE FORGERY
# ============================================================================

class TestSignatureForgery:
    """Test the system's cryptographic integrity."""
    
    def test_unsigned_payload_rejected(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Submit a payload with no signature.
        EXPECTED: Rejected immediately.
        """
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": compute_hash(valid_artifact),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        files = {
            'payload': (None, json.dumps(payload)),
            # No signature field!
            'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        assert resp.status_code in [400, 403]
    
    def test_invalid_signature_rejected(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Submit a valid payload with a random signature.
        EXPECTED: Cryptographic verification fails.
        """
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": compute_hash(valid_artifact),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        # Random signature (64 bytes, hex-encoded)
        fake_signature = "a" * 128  # 64 bytes = 128 hex chars
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, fake_signature),
            'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        assert resp.status_code == 403
        assert "authentication_failed" in resp.json().get('error', '')
    
    def test_signature_from_different_key(self, valid_artifact):
        """
        ATTACK: Sign with one key, claim to be a different miner.
        EXPECTED: Signature verification fails.
        """
        # Attacker's key
        attacker_key = nacl.signing.SigningKey.generate()
        
        # Victim's ID (registered in the system)
        victim_id = str(uuid.uuid4())
        
        payload = {
            "miner_id": victim_id,  # Claim to be the victim
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": compute_hash(valid_artifact),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        # Sign with attacker's key
        signature = sign_payload(payload, attacker_key)
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature),
            'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        assert resp.status_code == 403


# ============================================================================
# ATTACK VECTOR 3: INTEGRITY TAMPERING
# ============================================================================

class TestIntegrityTampering:
    """Test hash verification and artifact integrity checks."""
    
    def test_hash_mismatch_claimed_vs_actual(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Claim one hash, upload different artifact.
        EXPECTED: Server recomputes hash and detects mismatch.
        """
        # Claim a fake hash
        fake_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": fake_hash,
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        signature = sign_payload(payload, legitimate_miner['signing_key'])
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature),
            'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        assert resp.status_code == 400
        assert "hash_mismatch" in resp.json().get('error', '')
    
    def test_corrupt_artifact_detected(self, legitimate_miner, tmp_path):
        """
        ATTACK: Upload a corrupted/invalid tarball.
        EXPECTED: Server detects during extraction or verification.
        """
        # Create a corrupt "tarball"
        corrupt_artifact = tmp_path / "corrupt.tar.gz"
        with open(corrupt_artifact, 'wb') as f:
            f.write(b"THIS IS NOT A VALID TARBALL")
        
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": compute_hash(corrupt_artifact),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        signature = sign_payload(payload, legitimate_miner['signing_key'])
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature),
            'artifact': ('artifact.tar.gz', open(corrupt_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        # Should fail during sandbox verification
        assert resp.status_code in [400, 422]


# ============================================================================
# ATTACK VECTOR 4: RATE LIMITING & DOS
# ============================================================================

class TestRateLimiting:
    """Test the system's resistance to denial-of-service attacks."""
    
    def test_single_miner_rate_limit_enforced(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Submit 100 claims rapidly from one miner.
        EXPECTED: After 10 submissions, rate limit kicks in.
        """
        successful = 0
        rate_limited = 0
        
        for i in range(20):  # Try 20 submissions
            payload = {
                "miner_id": legitimate_miner['miner_id'],
                "task_id": "test-task",
                "claimed_score": 0.95,
                "artifact_hash": compute_hash(valid_artifact),
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4())  # Unique nonce each time
            }
            
            signature = sign_payload(payload, legitimate_miner['signing_key'])
            
            files = {
                'payload': (None, json.dumps(payload)),
                'signature': (None, signature),
                'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
            }
            
            resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
            
            if resp.status_code in [200, 202]:
                successful += 1
            elif resp.status_code == 429:
                rate_limited += 1
        
        # First 10 should succeed, rest should be rate-limited
        assert successful <= 10, "Rate limit should kick in after 10 submissions"
        assert rate_limited >= 5, "Multiple submissions should be rate-limited"
    
    def test_concurrent_submissions_same_miner(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Submit multiple claims concurrently from the same miner.
        EXPECTED: Rate limiting should still work correctly.
        """
        def submit_once():
            payload = {
                "miner_id": legitimate_miner['miner_id'],
                "task_id": "test-task",
                "claimed_score": 0.95,
                "artifact_hash": compute_hash(valid_artifact),
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4())
            }
            
            signature = sign_payload(payload, legitimate_miner['signing_key'])
            
            files = {
                'payload': (None, json.dumps(payload)),
                'signature': (None, signature),
                'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
            }
            
            return requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        
        # Launch 50 concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(submit_once) for _ in range(50)]
            responses = [f.result() for f in futures]
        
        successful = sum(1 for r in responses if r.status_code in [200, 202])
        rate_limited = sum(1 for r in responses if r.status_code == 429)
        
        # Should still enforce the rate limit
        assert successful <= 10
        assert rate_limited >= 30


# ============================================================================
# ATTACK VECTOR 5: ECONOMIC GAMING
# ============================================================================

class TestEconomicAttacks:
    """Test resistance to economic manipulation."""
    
    def test_minimal_effort_spam(self, legitimate_miner, tmp_path):
        """
        ATTACK: Submit random hyperparameters with minimal compute.
        EXPECTED: Verification should fail (score below threshold).
        """
        # Create artifact with random hyperparameters
        artifact_path = tmp_path / "spam.tar.gz"
        import tarfile
        with tarfile.open(artifact_path, "w:gz") as tar:
            hp_json = json.dumps({"learning_rate": 999.0, "batch_size": 1})
            hp_info = tarfile.TarInfo(name="hyperparameters.json")
            hp_info.size = len(hp_json)
            tar.addfile(hp_info, fileobj=tarfile.io.BytesIO(hp_json.encode('utf-8')))
            
            wasm_data = b"\x00asm\x01\x00\x00\x00"
            wasm_info = tarfile.TarInfo(name="train.wasm")
            wasm_info.size = len(wasm_data)
            tar.addfile(wasm_info, fileobj=tarfile.io.BytesIO(wasm_data))
        
        # Claim a high score (but the model will perform poorly)
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,  # Claim high score
            "artifact_hash": compute_hash(artifact_path),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        signature = sign_payload(payload, legitimate_miner['signing_key'])
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature),
            'artifact': ('artifact.tar.gz', open(artifact_path, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        
        # Should fail verification (score mismatch)
        assert resp.status_code == 422
        assert "verification_failed" in resp.json().get('error', '')
    
    def test_score_inflation_detected(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Claim a score of 0.99 when actual score is 0.90.
        EXPECTED: Sandbox verification detects the lie.
        """
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.99,  # Inflated score
            "artifact_hash": compute_hash(valid_artifact),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        signature = sign_payload(payload, legitimate_miner['signing_key'])
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature),
            'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
        
        # Should fail verification
        assert resp.status_code == 422


# ============================================================================
# ATTACK VECTOR 6: TIMING ATTACKS
# ============================================================================

class TestTimingAttacks:
    """Test resistance to timing-based side-channel attacks."""
    
    def test_signature_verification_constant_time(self, legitimate_miner, valid_artifact):
        """
        SECURITY REQUIREMENT: Signature verification should take constant time.
        EXPECTED: Invalid signatures should take approximately the same time
                  as valid signatures to verify (prevents timing oracle).
        
        NOTE: This test is probabilistic and may have false positives.
        """
        import statistics
        
        valid_times = []
        invalid_times = []
        
        for i in range(20):
            payload = {
                "miner_id": legitimate_miner['miner_id'],
                "task_id": "test-task",
                "claimed_score": 0.95,
                "artifact_hash": compute_hash(valid_artifact),
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4())
            }
            
            # Valid signature
            valid_sig = sign_payload(payload, legitimate_miner['signing_key'])
            files = {
                'payload': (None, json.dumps(payload)),
                'signature': (None, valid_sig),
                'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
            }
            
            start = time.perf_counter()
            requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
            elapsed = time.perf_counter() - start
            valid_times.append(elapsed)
            
            # Invalid signature (random)
            invalid_sig = "f" * 128
            files['signature'] = (None, invalid_sig)
            files['artifact'] = ('artifact.tar.gz', open(valid_artifact, 'rb'))
            
            start = time.perf_counter()
            requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
            elapsed = time.perf_counter() - start
            invalid_times.append(elapsed)
        
        valid_mean = statistics.mean(valid_times)
        invalid_mean = statistics.mean(invalid_times)
        
        # Timing difference should be minimal (< 10% relative difference)
        relative_diff = abs(valid_mean - invalid_mean) / valid_mean
        
        assert relative_diff < 0.10, \
            f"Timing leak detected: valid={valid_mean:.4f}s, invalid={invalid_mean:.4f}s"


# ============================================================================
# STRESS TESTING
# ============================================================================

class TestStressConditions:
    """Test system behavior under extreme conditions."""
    
    def test_maximum_artifact_size(self, legitimate_miner, tmp_path):
        """
        ATTACK: Upload a 100MB artifact to exhaust resources.
        EXPECTED: Server rejects or handles gracefully.
        """
        # Create a large artifact
        large_artifact = tmp_path / "large.tar.gz"
        with open(large_artifact, 'wb') as f:
            f.write(b'\x00' * (100 * 1024 * 1024))  # 100 MB
        
        payload = {
            "miner_id": legitimate_miner['miner_id'],
            "task_id": "test-task",
            "claimed_score": 0.95,
            "artifact_hash": compute_hash(large_artifact),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        signature = sign_payload(payload, legitimate_miner['signing_key'])
        
        files = {
            'payload': (None, json.dumps(payload)),
            'signature': (None, signature),
            'artifact': ('artifact.tar.gz', open(large_artifact, 'rb'))
        }
        
        resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files, timeout=30)
        
        # Should either accept (if under limit) or reject cleanly
        assert resp.status_code in [200, 202, 400, 413]  # 413 = Payload Too Large
    
    def test_malformed_json_payload(self, legitimate_miner, valid_artifact):
        """
        ATTACK: Send malformed JSON to test parser robustness.
        EXPECTED: Graceful rejection with clear error.
        """
        malformed_payloads = [
            "",  # Empty
            "not json at all",
            '{"miner_id": "incomplete"',  # Unterminated
            '{"miner_id": null}',  # Missing required fields
            '[]',  # Array instead of object
        ]
        
        for bad_payload in malformed_payloads:
            files = {
                'payload': (None, bad_payload),
                'signature': (None, "fake_signature"),
                'artifact': ('artifact.tar.gz', open(valid_artifact, 'rb'))
            }
            
            resp = requests.post(f"{NOTARY_URL}/api/v1/submit", files=files)
            assert resp.status_code in [400, 403], \
                f"Server should reject malformed JSON: {bad_payload[:50]}"


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--html=adversarial_report.html"])
