# Changelog

All notable changes to the `pqblocks-fips-dualmode` package are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-10-31

### Added
- Unified `CryptoEnvelope` interface providing mode-isolated classical and post-quantum cryptographic envelopes.
- Classical mode (`mode="fips"`) implementing ECDH P-256 key agreement and AES-256-GCM authenticated encryption under RFC 5116.
- Post-quantum mode (`mode="pq"`) implementing NIST FIPS 203 (ML-KEM-768) key encapsulation and decapsulation.
- Post-quantum mode implementing NIST FIPS 204 (ML-DSA-65) digital signature generation and verification with domain separation context.
- Immutable frozen dataclasses for result types: `KeyMaterial`, `CiphertextEnvelope`, `SignatureEnvelope`, and `VerificationResult`.
- Exception hierarchy (`DualModeError`) providing clear typed errors: `InvalidModeError`, `KeyMismatchError`, `NotAvailableInModeError`, `MalformedCiphertextError`, `ContextTooLongError`, and `PlaintextLimitError`.
- Automated test suite with 94 unit, boundary, and official Wycheproof vector tests.
- Comprehensive documentation suite and reproducible benchmark harness.
