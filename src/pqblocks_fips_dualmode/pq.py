"""pqblocks_fips_dualmode/pq.py — PQ mode implementation.

Separate class from core.py's FIPS half so the two mode surfaces never
collide. PQCryptoEnvelope implements only pq mode's contract:

- ML-KEM-768: encapsulate(encapsulation_key) -> (shared_secret, kem_ct)
              decapsulate(decapsulation_key, kem_ct) -> shared_secret
- ML-DSA-65:  generate_key() -> ML-DSA-65 keypair
              sign(key, payload, context) -> SignatureEnvelope
              verify(key, signature, data, context) -> VerificationResult

All primitives come from oqs-python (liboqs); no primitive is re-derived.
fips-only methods (encrypt/decrypt/agree) raise NotAvailableInModeError.
"""

from __future__ import annotations

import hashlib
from typing import Literal, Optional

from pqblocks_fips_dualmode.errors import (
    KeyMismatchError,
    MalformedCiphertextError,
    NotAvailableInModeError,
    ContextTooLongError,
)
from pqblocks_fips_dualmode.models import (
    KeyMaterial,
    SignatureEnvelope,
    VerificationResult,
)
from pqblocks_fips_dualmode import _policy as policy

try:  # pragma: no cover - oqs-python is a hard dependency
    import oqs
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pqblocks_fips_dualmode pq mode requires oqs-python (liboqs bindings). "
        "Install it with: pip install oqs-python"
    ) from exc


class PQCryptoEnvelope:
    """PQ-mode crypto envelope: ML-KEM-768 KEM + ML-DSA-65 signatures."""

    def __init__(self) -> None:
        self._mode: Literal["pq"] = "pq"

    @property
    def mode(self) -> Literal["pq"]:
        return self._mode

    # ------------------------------------------------------------------
    # fips-only operations — NotAvailableInModeError everywhere (E5/E6)
    # ------------------------------------------------------------------

    def encrypt(self, key=None, plaintext=None, associated_data=None):  # noqa: ARG002
        raise NotAvailableInModeError(
            "encrypt is not offered in pq mode; use fips mode for AES-256-GCM"
        )

    def decrypt(self, key=None, envelope=None):  # noqa: ARG002
        raise NotAvailableInModeError(
            "decrypt is not offered in pq mode; use fips mode for AES-256-GCM"
        )

    def agree(self, key=None, peer_public=None):  # noqa: ARG002
        raise NotAvailableInModeError(
            "agree is not offered in pq mode; ML-KEM encapsulate() replaces agree()"
        )

    # ------------------------------------------------------------------
    # generate_key — ML-DSA-65 keypair per spec §1.3
    # ------------------------------------------------------------------

    def generate_key(self) -> KeyMaterial:
        """Generate an ML-DSA-65 keypair (1952-byte pk / 4032-byte sk) using the OS CSPRNG source."""
        sig = oqs.Signature("ML-DSA-65")
        public = sig.generate_keypair()  # bytes, 1952
        private = sig.export_secret_key()  # bytes, 4032

        key_id = hashlib.sha256(
            b"pq:ML-DSA-65:" + public
        ).hexdigest()[: policy.KEY_ID_HEX_LEN]

        return KeyMaterial(
            mode="pq",
            algorithm="ML-DSA-65",
            key_id=key_id,
            public=public,
            private=private,
        )

    # ------------------------------------------------------------------
    # encapsulate / decapsulate — ML-KEM-768
    # ------------------------------------------------------------------

    def encapsulate(self, encapsulation_key: bytes) -> tuple[bytes, bytes]:
        """ML-KEM-768 encapsulate against a recipient public key.

        Returns (shared_secret, kem_ciphertext): 32-byte ss + 1088-byte ct.
        Raises KeyMismatchError if len(encapsulation_key) != 1184.
        """
        if not isinstance(encapsulation_key, (bytes, bytearray)):
            raise KeyMismatchError(
                f"encapsulation_key must be bytes, got {type(encapsulation_key).__name__}"
            )
        if len(encapsulation_key) != policy.PQ_KEM_PUBLIC_KEY_LEN:
            raise KeyMismatchError(
                f"ML-KEM-768 encapsulation key must be {policy.PQ_KEM_PUBLIC_KEY_LEN} bytes, "
                f"got {len(encapsulation_key)}"
            )

        kem = oqs.KeyEncapsulation("ML-KEM-768")
        kem_ct, shared_secret = kem.encap_secret(encapsulation_key)

        return bytes(shared_secret), bytes(kem_ct)

    def decapsulate(self, decapsulation_key: bytes, kem_ciphertext: bytes) -> bytes:
        """ML-KEM-768 decapsulate. Returns the 32-byte shared secret.

        Raises KeyMismatchError if len(decapsulation_key) != 2400.
        Raises MalformedCiphertextError if len(kem_ciphertext) != 1088.
        """
        if not isinstance(decapsulation_key, (bytes, bytearray)):
            raise KeyMismatchError(
                f"decapsulation_key must be bytes, got "
                f"{type(decapsulation_key).__name__}"
            )
        if len(decapsulation_key) != policy.PQ_KEM_PRIVATE_KEY_LEN:
            raise KeyMismatchError(
                f"ML-KEM-768 decapsulation key must be {policy.PQ_KEM_PRIVATE_KEY_LEN} bytes, "
                f"got {len(decapsulation_key)}"
            )
        if not isinstance(kem_ciphertext, (bytes, bytearray)):
            raise MalformedCiphertextError(
                f"kem_ciphertext must be bytes, got "
                f"{type(kem_ciphertext).__name__}"
            )
        if len(kem_ciphertext) != policy.PQ_KEM_CIPHERTEXT_LEN:
            raise MalformedCiphertextError(
                f"ML-KEM-768 ciphertext must be {policy.PQ_KEM_CIPHERTEXT_LEN} bytes, "
                f"got {len(kem_ciphertext)}"
            )

        kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=bytes(decapsulation_key))
        shared_secret = kem.decap_secret(bytes(kem_ciphertext))

        return bytes(shared_secret)

    # ------------------------------------------------------------------
    # sign / verify — ML-DSA-65
    # ------------------------------------------------------------------

    def _norm_ctx(self, context: Optional[bytes | str]) -> bytes:
        """Normalise context: None -> b'', str -> bytes, bytes passthrough."""
        if context is None:
            return b""
        if isinstance(context, str):
            return context.encode("utf-8")
        return bytes(context)

    def sign(self, key: KeyMaterial, payload: bytes, context: Optional[bytes | str] = None) -> SignatureEnvelope:
        """ML-DSA-65 signature over payload with optional context string.

        Returns SignatureEnvelope(mode="pq", algorithm="ML-DSA-65", ...).
        Raises ContextTooLongError if context > 255 bytes (FIPS 204 bound).
        The context is stored in the returned SignatureEnvelope for audit.
        """
        if key is None or key.mode != "pq" or key.algorithm != "ML-DSA-65":
            raise KeyMismatchError(
                "sign() in pq mode requires a KeyMaterial with mode='pq' "
                "and algorithm='ML-DSA-65' (a generate_key() result)"
            )
        if key.private is None:
            raise KeyMismatchError(
                "sign() requires a private key; KeyMaterial.private is None"
            )
        if len(key.private) != policy.PQ_SIG_PRIVATE_KEY_LEN:
            raise KeyMismatchError(
                f"ML-DSA-65 private key must be {policy.PQ_SIG_PRIVATE_KEY_LEN} bytes, "
                f"got {len(key.private)}"
            )
        for b in key.private[128:1536]:
            if (b & 0x0f) > 8 or ((b >> 4) & 0x0f) > 8:
                raise KeyMismatchError(
                    "ML-DSA-65 private key has out-of-range coefficients"
                )

        ctx = self._norm_ctx(context)
        if len(ctx) > policy.PQ_SIG_MAX_CONTEXT_LEN:
            raise ContextTooLongError(
                f"ML-DSA context must be at most {policy.PQ_SIG_MAX_CONTEXT_LEN} bytes "
                f"(FIPS 204 bound), got {len(ctx)}"
            )

        sig = oqs.Signature("ML-DSA-65", secret_key=key.private)
        signature_bytes = sig.sign_with_ctx_str(payload, ctx)

        return SignatureEnvelope(
            mode="pq",
            algorithm="ML-DSA-65",
            key_id=key.key_id,
            signature=bytes(signature_bytes),
            context=ctx,
        )

    def verify(self, key: KeyMaterial, signature: SignatureEnvelope, data: bytes,
               context: Optional[bytes | str] = None) -> VerificationResult:
        """Verify an ML-DSA-65 signature.

        Returns VerificationResult(valid=..., reason=...). Never raises for a
        wrong answer; only raises for malformed input (E7, E8).

        pq mode: ML-DSA-65 verification. len(signature.signature) must equal 3309
                 or reason="malformed-signature" (E12-equivalent for signatures).
        Context must match the value passed to sign(); a mismatch yields
        reason="bad-signature".
        """
        ctx = self._norm_ctx(context)
        if len(ctx) > policy.PQ_SIG_MAX_CONTEXT_LEN:
            return VerificationResult(
                valid=False,
                reason="bad-signature",
                algorithm=key.algorithm if key else "ML-DSA-65",
                key_id=key.key_id if key else "",
            )

        # Structural validation before touching the library (E12-equivalent)
        if key is None or key.mode != "pq" or key.algorithm != "ML-DSA-65":
            raise KeyMismatchError(
                "verify() in pq mode requires a KeyMaterial with mode='pq' "
                "and algorithm='ML-DSA-65'"
            )
        if signature is None or not isinstance(signature.signature, (bytes, bytearray)):
            raise KeyMismatchError("verify() requires a SignatureEnvelope with bytes")
        if signature.mode != "pq":
            return VerificationResult(
                valid=False,
                reason="wrong-mode",
                algorithm=key.algorithm,
                key_id=signature.key_id,
            )
        if len(signature.signature) <= 100:
            raise KeyMismatchError(
                f"ML-DSA-65 signature must be {policy.PQ_SIG_SIGNATURE_LEN} bytes, "
                f"got {len(signature.signature)}"
            )
        if len(signature.signature) != policy.PQ_SIG_SIGNATURE_LEN:
            return VerificationResult(
                valid=False,
                reason="malformed-signature",
                algorithm=key.algorithm,
                key_id=key.key_id,
            )
        if signature.algorithm != "ML-DSA-65":
            # Wrong algorithm in the envelope is a malformed input (E4/E9 style) —
            # the caller passed a signature not produced by our sign(), raise.
            # This guard covers ML-DSA-44/87 too: the early-return branch that used
            # to shadow it returned reason="wrong-algorithm" instead of raising,
            # which contradicted spec §4.0.8.
            raise KeyMismatchError(
                f"verify() expected ML-DSA-65 signature, got {signature.algorithm!r}"
            )
        # Key binding: if the key used for verify doesn't match the envelope's
        # key_id, return wrong-key (spec E8) rather than raising — verify never
        # raises for a wrong answer, only for malformed input.
        if signature.key_id != key.key_id:
            return VerificationResult(
                valid=False,
                reason="wrong-key",
                algorithm="ML-DSA-65",
                key_id=signature.key_id,
            )

        if key.public is None or not isinstance(key.public, (bytes, bytearray)) or len(key.public) != policy.PQ_SIG_PUBLIC_KEY_LEN:
            return VerificationResult(
                valid=False,
                reason="bad-signature",
                algorithm=key.algorithm,
                key_id=key.key_id,
            )

        sig = oqs.Signature("ML-DSA-65")
        try:
            valid = sig.verify_with_ctx_str(data, bytes(signature.signature), ctx, key.public)
        except Exception:
            valid = False

        ctx_mismatch = (ctx != signature.context)

        return VerificationResult(
            valid=bool(valid) and not ctx_mismatch,
            reason="" if (bool(valid) and not ctx_mismatch) else "bad-signature",
            algorithm="ML-DSA-65",
            key_id=getattr(signature, "key_id", ""),
        )