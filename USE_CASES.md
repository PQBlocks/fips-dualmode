# Use Cases: pqblocks-fips-dualmode

Practical architectural scenarios illustrating deployment patterns for dual-mode cryptographic operations.

## Scenario 1: Regulated Enterprise Post-Quantum Migration Pipeline

### Context
A financial services institution operates transaction pipelines subject to federal compliance mandates. Current compliance requires FIPS 140-3 approved classical encryption. Simultaneously, engineering leadership has mandated readiness for CNSA 2.0 post-quantum migration without requiring dual codebases or architectural rewrites.

### Implementation
The application parameterizes the envelope mode from environment configuration:

```python
import os
from pqblocks_fips_dualmode import CryptoEnvelope

# Read mode from deployment environment: "fips" or "pq"
CRYPTO_MODE = os.getenv("CRYPTO_ENV_MODE", "fips")

def process_transaction(payload: bytes, peer_key_bytes: bytes) -> bytes:
    # Initialize envelope under current policy mode
    env = CryptoEnvelope(mode=CRYPTO_MODE)
    
    if env.mode == "fips":
        # Classical mode: ECDH P-256 agreement + AES-256-GCM encryption
        key = env.generate_key()
        envelope = env.encrypt(key, payload, associated_data=b"tenant-fintech")
        return envelope.ciphertext
    else:
        # Post-quantum mode: ML-KEM-768 key encapsulation
        shared_secret, kem_ciphertext = env.encapsulate(peer_key_bytes)
        # Shared secret is now established for symmetric channel derivation
        return kem_ciphertext

# Expected output when tested under FIPS mode:
# Returns AES-256-GCM ciphertext || 16-byte authentication tag
```

## Scenario 2: Zero-Trust Document Signing with ML-DSA-65

### Context
A healthcare provider exchanges electronic health records (EHR) across distributed hospital networks. To protect records against long-term "harvest now, decrypt later" adversary campaigns, medical signatures must utilize quantum-resistant digital signatures.

### Implementation
Using `CryptoEnvelope(mode="pq")` with ML-DSA-65 signatures:

```python
from pqblocks_fips_dualmode import CryptoEnvelope

# Initialize post-quantum envelope
pq_env = CryptoEnvelope(mode="pq")

# Author generates an ML-DSA-65 signature keypair
signer_key = pq_env.generate_key()

# Medical record payload to authenticate
medical_record = b"Patient ID: 948102; Diagnosis: Normal; Authorization: Approved"
domain_context = b"EHR-SIGNING-V1"

# Generate signature with explicit domain separation context
sig_envelope = pq_env.sign(signer_key, medical_record, context=domain_context)

# Recipient verifies the document signature
result = pq_env.verify(signer_key, sig_envelope, medical_record, context=domain_context)

if result.valid:
    print("Record signature verified under FIPS 204 ML-DSA-65: OK")
else:
    print("Signature verification failed:", result.reason)

# Expected output:
# Record signature verified under FIPS 204 ML-DSA-65: OK
```

## Scenario 3: Secure Session Key Agreement and Symmetric AEAD Channel

### Context
A secure IoT gateway establishes point-to-point authenticated channels with edge gateways. In edge environments with limited crypto hardware accelerators, ECDH P-256 key agreement combined with AES-256-GCM provides sub-millisecond setup latencies.

### Implementation
Using `CryptoEnvelope(mode="fips")` for authenticated session establishment:

```python
from pqblocks_fips_dualmode import CryptoEnvelope
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Gateway A and Gateway B initialize FIPS envelopes
env_a = CryptoEnvelope(mode="fips")
env_b = CryptoEnvelope(mode="fips")

key_a = env_a.generate_key()
key_b = env_b.generate_key()

# Perform mutual ECDH key agreement over SECP256R1
shared_secret_a = env_a.agree(key_a, key_b.public)
shared_secret_b = env_b.agree(key_b, key_a.public)

assert shared_secret_a == shared_secret_b

# Encrypt session telemetry using agreed shared key
aesgcm = AESGCM(shared_secret_a)
nonce = b"\x01" * 12
ciphertext = aesgcm.encrypt(nonce, b"Telemetry Status: Operational", b"session-42")
plaintext = aesgcm.decrypt(nonce, ciphertext, b"session-42")

print("Session plaintext recovered:", plaintext.decode())
# Expected output:
# Session plaintext recovered: Telemetry Status: Operational
```

## When to Use Something Else

While `pqblocks-fips-dualmode` provides a streamlined abstraction for dual-mode applications, other tools are recommended for specific specialized requirements:

1. **Stateful Hash-Based Signatures**: If your organization requires LMS or XMSS stateful hash-based signatures for firmware signing (NIST SP 800-208), use a specialized SP 800-208 library; stateful hash algorithms are out of scope for this package.
2. **Unsupported Signature Schemes (FIPS 205 and FIPS 206 are not supported)**: If you require SPHINCS+ / SLH-DSA (FIPS 205) or Falcon / FN-DSA (FIPS 206) signature primitives, these are not supported in this package; use upstream libraries instead.
3. **Pure Symmetric Workloads**: If your application performs only standard data-at-rest bulk encryption with pre-shared keys and does not require asymmetric key agreement or PQC migration paths, utilize standard `cryptography.hazmat.primitives.ciphers.aead.AESGCM` directly.
4. **Hardware Security Modules (HSM)**: If your compliance environment requires physical tamper-reactive boundary validation (FIPS 140-3 Level 3 or Level 4), deploy an enterprise HSM appliance rather than a software library.
