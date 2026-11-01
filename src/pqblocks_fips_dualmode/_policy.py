"""pqblocks_fips_dualmode/_policy.py — algorithm constants and mode policy.

Centralises all magic numbers from FIPS 203 / FIPS 204 / FIPS 140-3
so no hard-coded sizes leak into core logic. All sizes are transcribed
from the standards' tables and cross-checked against the research brief.

This module is intentionally pure: no I/O, no randomness, no external
dependencies. It is the single source of truth for algorithm sizes.
"""

# ML-KEM-768 sizes (FIPS 203 Table 2 / Table 3)
# NIST FIPS 203 Table 3: ML-KEM-768 sizes in bytes
PQ_KEM_PUBLIC_KEY_LEN = 1184   # encapsulation key (pk)
PQ_KEM_PRIVATE_KEY_LEN = 2400  # decapsulation key (sk) - expanded form
PQ_KEM_CIPHERTEXT_LEN = 1088   # KEM ciphertext (ct)
PQ_KEM_SHARED_SECRET_LEN = 32  # shared secret (ss)

# ML-DSA-65 sizes (FIPS 204 Table 2)
PQ_SIG_PUBLIC_KEY_LEN = 1952   # verification key (pk)
PQ_SIG_PRIVATE_KEY_LEN = 4032  # signing key (sk) - expanded form
PQ_SIG_SIGNATURE_LEN = 3309    # signature length

# FIPS 140-3 / AES-GCM sizes
FIPS_EC_P256_PRIVATE_KEY_LEN = 32  # scalar, 32 bytes
FIPS_EC_P256_PUBLIC_KEY_LEN = 32   # compressed X-coordinate, 32 bytes
FIPS_AES_GCM_KEY_LEN = 32          # AES-256 key, 32 bytes
FIPS_AES_GCM_NONCE_LEN = 12        # 96-bit nonce for GCM
FIPS_AES_GCM_TAG_LEN = 16          # 128-bit tag

# Context bounds
PQ_SIG_MAX_CONTEXT_LEN = 255  # FIPS 204 §4.2: context string max 255 bytes

# Key ID derivation: sha256(mode||algorithm||public_bytes)[:16] -> 16 hex chars
KEY_ID_HEX_LEN = 16

# Practical plaintext limit for AES-GCM (2^36 - 256 bytes per RFC 5116 / NIST SP 800-38D)
# We use a conservative 2^24 bytes = 16 MiB as the documented limit
FIPS_PLAINTEXT_MAX_LEN = 16 * 1024 * 1024  # 16 MiB

# Mode-to-primitive mapping
MODE_PRIMITIVES = {
    "fips": {
        "key_agreement": "ECDH-P256",
        "symmetric_encryption": "AES-256-GCM",
        "signature": None,
        "kem": None,
    },
    "pq": {
        "key_agreement": None,  # handled via KEM encapsulation
        "symmetric_encryption": "AES-256-GCM",
        "signature": "ML-DSA-65",
        "kem": "ML-KEM-768",
    },
}

# Which operations are available in which mode
MODE_OPERATIONS = {
    "fips": {"generate_key", "encrypt", "decrypt", "agree"},
    "pq": {"generate_key", "encrypt", "decrypt", "sign", "verify", "encapsulate", "decapsulate"},
}


def operations_for_mode(mode: str) -> set[str]:
    """Return the set of operations available in the given mode."""
    return MODE_OPERATIONS.get(mode, set())


def is_available(mode: str, operation: str) -> bool:
    """Check if an operation is available in the given mode."""
    return operation in MODE_OPERATIONS.get(mode, set())


def algorithm_name(mode: str, operation: str) -> str:
    """Return the algorithm name for a mode+operation pair."""
    primitives = MODE_PRIMITIVES.get(mode, {})
    return primitives.get(operation, "unknown")


# Policy constants exported for tests
__all__ = [
    "PQ_KEM_PUBLIC_KEY_LEN",
    "PQ_KEM_PRIVATE_KEY_LEN",
    "PQ_KEM_CIPHERTEXT_LEN",
    "PQ_KEM_SHARED_SECRET_LEN",
    "PQ_SIG_PUBLIC_KEY_LEN",
    "PQ_SIG_PRIVATE_KEY_LEN",
    "PQ_SIG_SIGNATURE_LEN",
    "FIPS_EC_P256_PRIVATE_KEY_LEN",
    "FIPS_EC_P256_PUBLIC_KEY_LEN",
    "FIPS_AES_GCM_KEY_LEN",
    "FIPS_AES_GCM_NONCE_LEN",
    "FIPS_AES_GCM_TAG_LEN",
    "PQ_SIG_MAX_CONTEXT_LEN",
    "KEY_ID_HEX_LEN",
    "FIPS_PLAINTEXT_MAX_LEN",
    "MODE_PRIMITIVES",
    "MODE_OPERATIONS",
    "operations_for_mode",
    "is_available",
    "algorithm_name",
]