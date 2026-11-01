# Cryptographic Test Vector Sources

All test vectors in this directory originate from official standards bodies and reference implementations:

1. **AES-256-GCM Test Vectors (`aes_gcm_test.json`)**:
   - Origin: Project Wycheproof (Google) / NIST SP 800-38D Cavium and OpenSSL test suites.
   - Mechanism: Authenticated Encryption with Associated Data (AEAD) with 128-bit authentication tags and 96-bit nonces.
   - Purpose: Verifies authentication tag validation, tamper detection, and bit-flip rejection in FIPS 140-3 mode.

2. **ML-KEM-768 Test Vectors (`mlkem_768_test.json`)**:
   - Origin: Project Wycheproof / NIST FIPS 203 Initial Demonstration Vectors.
   - Mechanism: ML-KEM-768 key encapsulation and decapsulation (Kyber-768 parameter set).
   - Purpose: Validates shared secret agreement and decapsulation error resistance in post-quantum mode.

3. **ML-DSA-65 Test Vectors (`mldsa_65_verify_test.json`)**:
   - Origin: Project Wycheproof / NIST FIPS 204 Initial Demonstration Vectors.
   - Mechanism: ML-DSA-65 digital signature verification (Dilithium3 parameter set).
   - Purpose: Validates signature verification, context binding, and negative fault injection.
