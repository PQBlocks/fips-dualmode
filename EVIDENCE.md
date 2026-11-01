# Evidence: pqblocks-fips-dualmode

Traceability matrix linking mathematical standards, external research publications, and code implementations.

## Primary Sources

The algorithm specifications and security constraints implemented in this library are derived directly from published cryptographic standards and formal NIST publications:

1. **NIST FIPS 203**: *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*.
   - Author: National Institute of Standards and Technology.
   - Date: August 2024.
   - DOI: [10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
   - Scope: Governs ML-KEM-768 parameter sets ($k=3$), encapsulation key size (1,184 bytes), decapsulation key size (2,400 bytes), ciphertext size (1,088 bytes), and shared secret derivation.

2. **NIST FIPS 204**: *Module-Lattice-Based Digital Signature Standard (ML-DSA)*.
   - Author: National Institute of Standards and Technology.
   - Date: August 2024.
   - DOI: [10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
   - Scope: Governs ML-DSA-65 parameter sets, public key size (1,952 bytes), private key size (4,032 bytes), signature size (3,309 bytes), and context string constraints ($\le 255$ bytes).

3. **NIST SP 800-38D**: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
   - Author: Morris Dworkin, NIST.
   - Date: November 2007.
   - DOI: [10.6028/NIST.SP.800-38D](https://doi.org/10.6028/NIST.SP.800-38D)
   - Scope: Governs authenticated encryption using AES with 256-bit keys, 96-bit unique nonces, and 128-bit authentication tags.

4. **NIST SP 800-56A Rev. 3**: *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*.
   - Author: Elaine Barker et al., NIST.
   - Date: April 2018.
   - DOI: [10.6028/NIST.SP.800-56Ar3](https://doi.org/10.6028/NIST.SP.800-56Ar3)
   - Scope: Governs ECDH key agreement over curve SECP256R1 (P-256).

5. **RFC 5116**: *An Interface and Algorithms for Authenticated Encryption*.
   - Author: D. McGrew.
   - Date: December 2007.
   - RFC: [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116)
   - Scope: Governs AEAD interface semantics, associated data bindings, and plaintext length limitations.

## Method-to-Code Map

The following matrix maps each architectural method and standard constraint directly to its implementing module, class, and method within the source repository:

| Cryptographic Operation | Standard Specification | Source File | Implementing Class / Function |
|:---|:---|:---|:---|
| Dual-Mode Public Interface | Unified Facade Pattern | `src/pqblocks_fips_dualmode/__init__.py` | `CryptoEnvelope` |
| Mode Dispatching & Routing | Runtime Mode Guard | `src/pqblocks_fips_dualmode/__init__.py` | `CryptoEnvelope._dispatch` |
| Classical Key Generation | NIST SP 800-56A (ECDH P-256) | `src/pqblocks_fips_dualmode/core.py` | `CryptoEnvelope.generate_key` |
| Classical AEAD Encryption | NIST SP 800-38D (AES-256-GCM) | `src/pqblocks_fips_dualmode/core.py` | `CryptoEnvelope.encrypt` |
| Classical AEAD Decryption | NIST SP 800-38D (AES-256-GCM) | `src/pqblocks_fips_dualmode/core.py` | `CryptoEnvelope.decrypt` |
| Classical Key Agreement | NIST SP 800-56A (ECDH P-256) | `src/pqblocks_fips_dualmode/core.py` | `CryptoEnvelope.agree` |
| PQ Signature Key Generation | FIPS 204 (ML-DSA-65) | `src/pqblocks_fips_dualmode/pq.py` | `PQCryptoEnvelope.generate_key` |
| PQ Message Signing | FIPS 204 (ML-DSA-65) | `src/pqblocks_fips_dualmode/pq.py` | `PQCryptoEnvelope.sign` |
| PQ Signature Verification | FIPS 204 (ML-DSA-65) | `src/pqblocks_fips_dualmode/pq.py` | `PQCryptoEnvelope.verify` |
| PQ Key Encapsulation | FIPS 203 (ML-KEM-768) | `src/pqblocks_fips_dualmode/pq.py` | `PQCryptoEnvelope.encapsulate` |
| PQ Key Decapsulation | FIPS 203 (ML-KEM-768) | `src/pqblocks_fips_dualmode/pq.py` | `PQCryptoEnvelope.decapsulate` |
| Key-ID Derivation | SHA-256 Prefix (16 hex chars) | `src/pqblocks_fips_dualmode/core.py` | `_derive_key_id` |
| Parameter Bounds & Constants | Cryptographic Sizing Policy | `src/pqblocks_fips_dualmode/_policy.py` | Policy module constants |
| Exception Hierarchy | Dual-Inheritance Typing | `src/pqblocks_fips_dualmode/errors.py` | `DualModeError` hierarchy |
| Immutability Envelopes | Frozen Dataclasses | `src/pqblocks_fips_dualmode/models.py` | `KeyMaterial`, `CiphertextEnvelope`, `SignatureEnvelope`, `VerificationResult` |
