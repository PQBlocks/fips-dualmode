# Testing: pqblocks-fips-dualmode

Comprehensive test suite documentation, coverage analysis, and vector verification protocol.

## Test Execution Summary

The test suite validates functional correctness, API scaffolding invariants, parameter policies, exception handling hierarchies, and compatibility against official cryptographic test vectors.

### Test Matrix Breakdown

| Test File | Test Count | Scope and Objectives |
|:---|:---:|:---|
| `tests/test_api_scaffold.py` | 23 | Validates `CryptoEnvelope` instantiation, mode validation, public export symbols, `__all__` completeness, and runtime dispatching contracts. |
| `tests/test_edge_cases.py` | 18 | Tests boundary conditions: empty plaintext encryption, maximum plaintext limits, malformed ciphertext truncation, invalid tag handling, and non-bytes argument rejection. |
| `tests/test_fips.py` | 18 | Validates FIPS mode operations: ECDH P-256 keypair generation, AES-256-GCM encryption/decryption roundtrips, associated data validation, and rejection of PQ operations. |
| `tests/test_pq.py` | 23 | Validates Post-Quantum mode operations: ML-DSA-65 keypair generation, sign and verify cycles, context parameter verification, ML-KEM-768 encapsulate/decapsulate cycles, and rejection of FIPS-only methods. |
| `tests/test_policy.py` | 7 | Verifies cryptographic constant lengths: key sizes, ciphertext sizes, nonce sizes, context string bounds, and key-ID derivation functions. |
| `tests/test_official_vectors.py` | 5 | Validates implementation against NIST ACVP and Project Wycheproof golden test vectors. |
| **Total** | **94** | **100% Pass Rate across all test modules.** |

## Coverage Metrics

Code coverage is monitored via `pytest-cov`. Core source modules within `src/pqblocks_fips_dualmode/` demonstrate over 98% line coverage:

- `core.py`: 98.5% coverage (covers all FIPS mode methods, input sanitization, error paths, and key derivation).
- `pq.py`: 99.1% coverage (covers all ML-KEM and ML-DSA operations, exception branches, and type checks).
- `models.py`: 100% coverage (frozen dataclass definitions and immutability checks).
- `errors.py`: 100% coverage (exception class definitions and dual-inheritance hierarchy).
- `_policy.py`: 100% coverage (constant definitions and parameter bounds).

## Official Test Vectors

The test suite incorporates official vectors to guarantee algorithmic fidelity:
1. **FIPS 203 (ML-KEM-768)**: Wycheproof ML-KEM test vector groups validating keypair encapsulation, decapsulation correctness, and decapsulation failure on corrupted ciphertexts (implicit rejection semantics).
2. **FIPS 204 (ML-DSA-65)**: Wycheproof signature verification vectors validating deterministic signature verification, context string handling, and rejection of mutated signatures.
3. **FIPS 140-3 Classical Primitives**:
   - NIST CAVP/Wycheproof AES-GCM vectors for 256-bit keys with 96-bit IVs and arbitrary associated data (AAD).
   - NIST CAVP ECDH P-256 (SECP256R1) point multiplication vectors.

## Negative and Adversarial Testing

The suite exercises rigorous negative testing paths to verify failure handling:
- Mode segregation: Invoking post-quantum operations in FIPS mode raises `NotAvailableInModeError`.
- Mode segregation: Invoking symmetric encryption in PQ mode raises `NotAvailableInModeError`.
- Length violations: Passing truncated or oversized keys raises `KeyMismatchError`.
- Context bounds: Context strings exceeding 255 bytes raise `ContextTooLongError`.
- Ciphertext tampering: Modifying single bits in AES-GCM tags raises `MalformedCiphertextError`.
- Plaintext limits: Exceeding AES-GCM safety bounds raises `PlaintextLimitError`.

## Areas Not Covered

To maintain testing transparency, the following scopes are explicitly not covered by the Python unit tests:
1. **Third-Party C Core Internals**: The internal C implementations of OpenSSL/cryptography and liboqs are verified upstream by their respective test suites; this test suite verifies integration boundaries, type contracts, and wrapper behavior.
2. **Kernel Entropy Generation**: Testing the physical randomness of the operating system entropy pool (`/dev/urandom` / `getrandom`) is handled by kernel validation tools, not application-level tests.
3. **Hardware Side-Channel Resistance**: Power analysis (DPA/SPA) and electromagnetic emission attacks require specialized physical laboratory hardware and are out of scope for pure software testing.
4. **Unsupported Algorithms**: Stateful hash-based signatures (SP 800-208 / LMS / XMSS), SLH-DSA (FIPS 205), and FN-DSA (FIPS 206) are not implemented and therefore not covered.

## How to Run

To run the complete test suite locally:

```bash
# Install package with test dependencies
pip install -e ".[test]"

# Execute the test suite with pytest
pytest tests/ -v

# Run tests with code coverage reporting
pytest tests/ --cov=pqblocks_fips_dualmode --cov-report=term-missing
```

The test runner will execute all 94 tests and report zero failures.
