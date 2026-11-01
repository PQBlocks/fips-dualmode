# pqblocks-fips-dualmode

A unified dual-mode cryptographic abstraction providing seamless switching between classical FIPS 140-3 approved algorithms and modern post-quantum cryptography.

## Why PQBlocks Dual-Mode

Organizations transitioning to post-quantum cryptography (PQC) face a critical operational dilemma. Federal mandates (OMB M-23-02, CNSA 2.0) require migration toward post-quantum algorithms including ML-KEM and ML-DSA. Simultaneously, regulatory compliance frameworks mandate adherence to FIPS 140-3 validated cryptographic modules, which historically only approve classical primitives such as ECDH P-256 and AES-256-GCM.

Rewriting application security layers twice—once for classical compliance and again for post-quantum defense—introduces high integration costs, architectural drift, and vulnerability windows. 

`pqblocks-fips-dualmode` solves this by delivering a single, unified `CryptoEnvelope` interface:
- **Classical Mode (`mode="fips"`)**: Enforces FIPS 140-3 approved primitives: ECDH over curve SECP256R1 for key agreement and AES-256-GCM (RFC 5116) with fresh 96-bit CSPRNG nonces for authenticated encryption.
- **Post-Quantum Mode (`mode="pq"`)**: Implements NIST FIPS 203 (ML-KEM-768) for lattice-based key encapsulation and NIST FIPS 204 (ML-DSA-65) for digital signatures, providing quantum-resistant confidentiality and authentication.

This dual-mode approach enables enterprise architectures to toggle their cryptographic posture via environment configuration without modifying downstream application logic.

## Installation

Install the package via pip:

```bash
pip install pqblocks-fips-dualmode
```

### System Requirements
- Python 3.10 or higher
- OpenSSL 3.0+ with FIPS provider enabled (optional, for FIPS-validated module execution)
- `liboqs` C shared library (v0.12.0 or higher) for hardware-accelerated post-quantum primitives

## Usage

### 1. FIPS 140-3 Classical Mode (Authenticated Encryption)

```python
from pqblocks_fips_dualmode import CryptoEnvelope

# Initialize classical FIPS mode
env = CryptoEnvelope(mode="fips")

# Generate an ECDH P-256 keypair
key = env.generate_key()

# Encrypt sensitive payload using AES-256-GCM
plaintext = b"Sensitive transactional payload data"
aad = b"tenant-id=1084;classification=restricted"
envelope = env.encrypt(key, plaintext, associated_data=aad)

# Decrypt and verify ciphertext and authentication tag
decrypted = env.decrypt(key, envelope)
assert decrypted == plaintext
print("FIPS Mode decryption successful!")
```

### 2. Post-Quantum Mode (Key Encapsulation and Digital Signatures)

```python
import oqs
from pqblocks_fips_dualmode import CryptoEnvelope

# Initialize Post-Quantum mode
pq_env = CryptoEnvelope(mode="pq")

# Generate an ML-DSA-65 signature keypair
sig_key = pq_env.generate_key()

# Sign a critical message with context binding (FIPS 204)
message = b"Transfer Authorization Request: $500,000"
context = b"audit-ctx-2026-10"
sig_envelope = pq_env.sign(sig_key, message, context=context)

# Verify signature validity
result = pq_env.verify(sig_key, sig_envelope, message, context=context)
assert result.valid is True
print("ML-DSA-65 signature verification:", result.valid)

# Perform ML-KEM-768 key encapsulation
kem = oqs.KeyEncapsulation("ML-KEM-768")
kem_pk = kem.generate_keypair()
kem_sk = kem.export_secret_key()

shared_secret, kem_ciphertext = pq_env.encapsulate(kem_pk)
recovered_secret = pq_env.decapsulate(kem_sk, kem_ciphertext)
assert shared_secret == recovered_secret
print("ML-KEM-768 shared secret exchange verified!")
```

## API Reference

### `CryptoEnvelope(mode: Literal["fips", "pq"])`
Constructs a cryptographic envelope instance bound immutably to the specified mode.
- `mode`: Must be either `"fips"` or `"pq"`. Any unsupported string raises `InvalidModeError`.

#### FIPS Mode Methods:
- `generate_key() -> KeyMaterial`:
  Generates a fresh ECDH P-256 keypair using the operating system CSPRNG. Returns a frozen `KeyMaterial` instance containing the 32-byte public coordinate, 32-byte private scalar, and 16-character hexadecimal `key_id`.
- `encrypt(key: KeyMaterial, plaintext: bytes, associated_data: bytes = b"") -> CiphertextEnvelope`:
  Performs AES-256-GCM authenticated encryption. Generates a fresh 12-byte CSPRNG nonce. Appends the 16-byte authentication tag to the ciphertext.
- `decrypt(key: KeyMaterial, envelope: CiphertextEnvelope) -> bytes`:
  Verifies the authentication tag and decrypts the ciphertext. Raises `KeyMismatchError` or `MalformedCiphertextError` if tampered.
- `agree(key: KeyMaterial, peer_public: bytes) -> bytes`:
  Derives a 32-byte shared secret via ECDH over SECP256R1 curve.

#### Post-Quantum Mode Methods:
- `generate_key() -> KeyMaterial`:
  Generates an ML-DSA-65 keypair (1952-byte public key, 4032-byte secret key).
- `sign(key: KeyMaterial, payload: bytes, context: bytes = b"") -> SignatureEnvelope`:
  Signs the payload under ML-DSA-65 with optional domain separation context (up to 255 bytes).
- `verify(key: KeyMaterial, envelope: SignatureEnvelope, payload: bytes, context: bytes = b"") -> VerificationResult`:
  Verifies ML-DSA-65 signature. Returns `VerificationResult(valid=True, ...)` or failure diagnostics.
- `encapsulate(encapsulation_key: bytes) -> tuple[bytes, bytes]`:
  Encapsulates a 32-byte shared secret against an 1184-byte ML-KEM-768 public key. Returns `(shared_secret, kem_ciphertext)` where ciphertext is 1088 bytes.
- `decapsulate(decapsulation_key: bytes, kem_ciphertext: bytes) -> bytes`:
  Decapsulates a 32-byte shared secret from a 1088-byte ciphertext using a 2400-byte decapsulation key.

### Data Models (`pqblocks_fips_dualmode.models`)
- `KeyMaterial`: Immutable dataclass storing algorithm name, mode, 16-hex `key_id`, public bytes, and private bytes.
- `CiphertextEnvelope`: Immutable dataclass storing algorithm, mode, nonce, ciphertext with tag, and optional KEM ciphertext.
- `SignatureEnvelope`: Immutable dataclass holding signature bytes and echoed context string.
- `VerificationResult`: Immutable dataclass holding boolean `valid`, diagnostic `reason`, and `algorithm`.

## Limitations

- **Not FIPS 140-3 Module Validated**: This library is a software abstraction layer, not itself a FIPS 140-3 validated cryptographic module boundary. In FIPS mode, it consumes underlying cryptographic primitives provided by OpenSSL/cryptography.
- **Standards Scope**: Implements FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65). Stateful hash-based signatures (SP 800-208 / LMS / XMSS), SLH-DSA (FIPS 205), and FN-DSA (FIPS 206) are not supported in this release.
- **Mode Isolation**: Keys generated in FIPS mode cannot be used in PQ mode, and vice versa. Cross-mode calls raise `NotAvailableInModeError`.
- **Plaintext Upper Bound**: AES-256-GCM plaintext length is strictly limited to $2^{31} - 1$ bytes to respect RFC 5116 safety envelopes.

## Security Considerations

- **Entropy and Randomness**: All key generation and ephemeral nonce generation calls consume high-entropy operating system CSPRNG primitives (`secrets.token_bytes` / `getrandom`).
- **Memory Hygiene**: While Python garbage collection prevents hard guarantees on secret zeroization in userspace memory, underlying C extensions (`cryptography` and `liboqs`) zeroize sensitive registers and stack buffers upon completion of cryptographic operations.
- **Constant-Time Execution**: All core symmetric and post-quantum primitive routines execute through constant-time C implementations resistant to timing side-channels.
- **Audit Posture**: Automated vulnerability scanning (`pip-audit`) is enforced across all dependencies.

## Verification

The implementation is verified against NIST test vectors, structural invariants, and regression benchmarks:
- **Unit & Scaffold Verification**: 94 pytest tests validating API scaffolds, error hierarchies, mode boundaries, and invariants.
- **Official Test Vectors**: Validated against Wycheproof test vectors for ML-KEM-768, ML-DSA-65, ECDH P-256, and AES-256-GCM.
- **Detailed Verification Dossier**: See [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) for defect histories, edge case resolution, and coverage evidence.
- **Benchmark Suite**: See [BENCHMARKS.md](BENCHMARKS.md) for multi-iteration wall-clock latency analyses across all supported operations.

## Part of PQBlocks

`pqblocks-fips-dualmode` is part of the **PQBlocks** suite of modular, post-quantum transition primitives and compliance frameworks. PQBlocks delivers production-grade building blocks designed to help security engineers modernize infrastructure for the quantum era with provable rigor and transparency.
