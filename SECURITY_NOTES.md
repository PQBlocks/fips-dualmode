# Security Notes: pqblocks-fips-dualmode

Security architecture, cryptographic boundaries, threat model, and dependency analysis.

## What It Protects and What It Does Not

### Protections Provided
1. **Confidentiality Against Harvest-Now-Decrypt-Later Attacks**:
   When configured in post-quantum mode (`mode="pq"`), key encapsulation uses ML-KEM-768 (FIPS 203), providing Category 3 security against quantum adversaries capable of running Shor's algorithm.
2. **Post-Quantum Authentication**:
   When configured in post-quantum mode, digital signatures utilize ML-DSA-65 (FIPS 204), preventing signature forgery by classical or quantum adversaries.
3. **FIPS 140-3 Classical Assurance**:
   When configured in classical mode (`mode="fips"`), operations use strictly approved algorithms (ECDH P-256 and AES-256-GCM), maintaining compliance in environments that mandate classical FIPS-validated primitives.
4. **Domain Separation**:
   Enforces separation between cryptographic modes. Keys generated for FIPS mode cannot be decrypted or processed in PQ mode, preventing cross-protocol type confusion.

### What It Does Not Protect
1. **CMVP Hardware Security Boundary**:
   This library is software-based; it does not provide physical tamper resistance or hardware-level key isolation.
2. **Endpoints with Compromised Memory**:
   If the host execution environment or OS kernel is compromised, secret key material present in memory can be extracted.
3. **Replay Attacks at the Protocol Level**:
   While AES-GCM includes nonces to protect against ciphertext tampering and duplicate detection, session sequencing, timestamping, and replay prevention must be managed by the application protocol.

## Hostile Input Handling and Robustness

- **Malformed Ciphertexts**: In FIPS mode, any ciphertext tampering or bit flip causes AES-GCM authentication tag verification to fail, raising `MalformedCiphertextError`. In PQ mode, decapsulation on invalid ciphertexts adheres to the implicit rejection mechanism specified in FIPS 203, preventing chosen-ciphertext oracle attacks.
- **Context String Bounds**: Signature contexts are strictly bounded to 255 bytes per FIPS 204. Any exceeding length immediately raises `ContextTooLongError`.
- **Plaintext Upper Bounds**: Input plaintext sizes for symmetric encryption are checked against `FIPS_PLAINTEXT_MAX_LEN` prior to buffer allocation, preventing integer overflow and memory exhaustion denial-of-service.

## Cryptographic Operations and Memory Hygiene

- **Constant-Time Primitives**:
  The underlying C implementations in `liboqs` and `cryptography` (OpenSSL) implement constant-time algorithms for polynomial arithmetic, NTT transformations, point multiplication, and AES-GCM operations to mitigate side-channel timing attacks.
- **Memory Zeroization**:
  The underlying C shared libraries zeroize private key buffers and intermediate NTT state vectors upon completion. Users should note that because Python uses reference-counted garbage collection, Python `bytes` objects in userspace cannot be deterministically zeroized upon deletion. Applications managing ultra-sensitive keys should isolate processes or employ secure enclave memory.
- **Randomness and Entropy Sources**:
  All keypair generation, ephemeral KEM seed generation, and 96-bit AES-GCM nonce generation invoke operating system CSPRNG primitives (`secrets.token_bytes` and `os.urandom`), backed by the Linux `getrandom()` system call.

## Dependencies and Vulnerability Posture

The package maintains a minimal dependency footprint:
- `cryptography >= 42.0.0`: Backed by OpenSSL for FIPS classical operations.
- `oqs-python >= 0.12.0`: CFFI bindings for liboqs post-quantum primitives.

### Automated Security Audit
Automated dependency vulnerability audits are conducted using `pip-audit` against the Open Source Vulnerabilities (OSV) database and PyPI advisory database. No high or critical severity advisories are present in the dependency tree. Regular security review and automated matrix testing are maintained across all supported Python versions.
