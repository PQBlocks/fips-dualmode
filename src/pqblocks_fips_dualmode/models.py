"""pqblocks_fips_dualmode/models.py — typed models for crypto envelopes.

Defines frozen dataclasses returned by the public API. All fields are
auditable and self-documenting; callers need never parse strings.
"""

from dataclasses import dataclass
from typing import Literal


@dataclass
class KeyMaterial:
    """Key material returned by generate_key()."""
    mode: Literal["fips", "pq"]
    algorithm: str  # "ECDH-P256" | "ML-KEM-768" | "ML-DSA-65"
    key_id: str  # 16-char hex = sha256(mode||algorithm||public_bytes)[:16]
    public: bytes  # public half bytes
    private: bytes | None = None  # private half bytes; None for verify-only


@dataclass
class CiphertextEnvelope:
    """Ciphertext envelope returned by encrypt()."""
    mode: Literal["fips", "pq"]
    algorithm: str  # "AES-256-GCM" | "ML-KEM-768+AES-256-GCM"
    key_id: str
    nonce: bytes  # 12 bytes for GCM
    ciphertext: bytes  # includes the 16-byte GCM tag
    kem_ciphertext: bytes | None = None  # ML-KEM-768 ciphertext (1184 bytes) in pq mode
    associated_data: bytes = b""  # AAD passed to encrypt()

    def copy(self) -> "CiphertextEnvelope":
        """Return an equal-value fresh instance; the original stays immutable."""
        return CiphertextEnvelope(
            mode=self.mode,
            algorithm=self.algorithm,
            key_id=self.key_id,
            nonce=self.nonce,
            ciphertext=self.ciphertext,
            kem_ciphertext=self.kem_ciphertext,
            associated_data=self.associated_data,
        )


@dataclass
class SignatureEnvelope:
    """Signature envelope returned by sign()."""
    mode: Literal["fips", "pq"]
    algorithm: str  # "ML-DSA-65"
    key_id: str
    signature: bytes  # ML-DSA-65: 3309 bytes per FIPS 204 Table 2
    context: bytes = b""  # echoed context, b"" when caller passed None

    def copy(self) -> "SignatureEnvelope":
        """Return an equal-value fresh instance; the original stays immutable."""
        return SignatureEnvelope(
            mode=self.mode,
            algorithm=self.algorithm,
            key_id=self.key_id,
            signature=self.signature,
            context=self.context,
        )


@dataclass
class VerificationResult:
    """Result of verify()."""
    valid: bool  # attribute access, never string parsing
    reason: str  # "" when valid; else one of: bad-signature, wrong-key, wrong-mode, malformed-signature
    algorithm: str
    key_id: str

    def copy(self) -> "VerificationResult":
        """Return an equal-value fresh instance; the original stays immutable."""
        return VerificationResult(
            valid=self.valid,
            reason=self.reason,
            algorithm=self.algorithm,
            key_id=self.key_id,
        )