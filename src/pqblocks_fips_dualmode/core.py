"""pqblocks_fips_dualmode/core.py — FIPS 140-3 / PQ dual-mode implementations.

Implements the FIPS half (ECDH P-256 + AES-256-GCM) and dispatches
PQ operations (ML-KEM-768 + ML-DSA-65). Every method raises one of
the exception types from errors.py; no method returns None or a bare bool on error.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import oqs

from pqblocks_fips_dualmode.errors import (
    KeyMismatchError,
    NotAvailableInModeError,
    MalformedCiphertextError,
    PlaintextLimitError,
    InvalidModeError,
    ContextTooLongError,
)
from pqblocks_fips_dualmode.models import (
    KeyMaterial,
    CiphertextEnvelope,
    SignatureEnvelope,
    VerificationResult,
)
from pqblocks_fips_dualmode._policy import (
    FIPS_EC_P256_PRIVATE_KEY_LEN,
    FIPS_EC_P256_PUBLIC_KEY_LEN,
    FIPS_AES_GCM_KEY_LEN,
    FIPS_AES_GCM_NONCE_LEN,
    FIPS_AES_GCM_TAG_LEN,
    FIPS_PLAINTEXT_MAX_LEN,
    PQ_KEM_PUBLIC_KEY_LEN,
    PQ_KEM_PRIVATE_KEY_LEN,
    PQ_KEM_CIPHERTEXT_LEN,
    PQ_KEM_SHARED_SECRET_LEN,
    PQ_SIG_PUBLIC_KEY_LEN,
    PQ_SIG_PRIVATE_KEY_LEN,
    PQ_SIG_SIGNATURE_LEN,
    PQ_SIG_MAX_CONTEXT_LEN,
)

# FIPS 140-3 / SECP256R1 derived sizes (spec §1.4)
FIPS_UNCOMPRESSED_LEN = 65  # 0x04 || X || Y
FIPS_EC_CURVE = ec.SECP256R1()


# ---------------------------------------------------------------------------
# Key-ID derivation (spec §1.3: 16-char hex = sha256(...)[:16])
# ---------------------------------------------------------------------------

def _derive_key_id(mode: str, algorithm: str, public_bytes: bytes) -> str:
    """Derive the 16-char hex key_id from mode||algorithm||public_bytes."""
    blob = f"{mode}:{algorithm}:".encode() + public_bytes
    return hashlib.sha256(blob).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Mode dispatching CryptoEnvelope
# ---------------------------------------------------------------------------

class CryptoEnvelope:
    """Bind an envelope to one mode for its lifetime.

    mode="fips": FIPS 140-3 approved classical algorithms only (ECDH P-256 + AES-256-GCM).
    mode="pq":   post-quantum mode (ML-KEM-768 + ML-DSA-65).

    Raises InvalidModeError if mode is not exactly "fips" or "pq" (E1, E2).
    Every public API method raises one of the exception classes from errors.py
    on any error path; no method returns None or a bare bool.
    """

    def __init__(self, mode: str) -> None:
        if mode not in ("fips", "pq"):
            raise InvalidModeError(f"unsupported mode: {mode!r}; expected 'fips' or 'pq'")
        self._mode = mode

    @property
    def mode(self) -> Literal["fips", "pq"]:
        return self._mode

    # ------------------------------------------------------------------
    # generate_key
    # ------------------------------------------------------------------
    def generate_key(self) -> KeyMaterial:
        """Generate a fresh keypair bound to this envelope's mode using the OS CSPRNG source.

        fips mode: ECDH P-256 keypair. Fields: algorithm="ECDH-P256",
                   public=32-byte X coordinate, private=32-byte scalar,
                   key_id=sha256(...)[:16] hex.
        pq mode:   raises NotAvailableInModeError (use ML-DSA-65 key generation directly).
        """
        if self._mode != "fips":
            raise NotAvailableInModeError(
                "generate_key is not available in pq mode; use ML-DSA-65 key generation directly"
            )

        private_key = ec.generate_private_key(FIPS_EC_CURVE)
        public_key = private_key.public_key()

        # Private key: 32-byte scalar (big-endian).
        private_bytes = private_key.private_numbers().private_value.to_bytes(
            FIPS_EC_P256_PRIVATE_KEY_LEN, "big"
        )

        # Public key: 32-byte X coordinate (per spec §1.3 "public=32-byte X96 coordinate").
        public_bytes = public_key.public_numbers().x.to_bytes(FIPS_EC_P256_PUBLIC_KEY_LEN, "big")

        key_id = _derive_key_id("fips", "ECDH-P256", public_bytes)

        return KeyMaterial(
            mode="fips",
            algorithm="ECDH-P256",
            key_id=key_id,
            public=public_bytes,
            private=private_bytes,
        )

    # ------------------------------------------------------------------
    # encrypt
    # ------------------------------------------------------------------
    def encrypt(
        self,
        key: KeyMaterial,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> CiphertextEnvelope:
        """Authenticated encryption under the mode's symmetric algorithm.

        fips mode: AES-256-GCM directly under key.public as the 32-byte GCM key.
        Empty plaintext is legal and yields a 16-byte tag-only ciphertext (E9).

        pq mode:   raises NotAvailableInModeError (use ML-KEM-768 encapsulate instead).
        """
        if self._mode != "fips":
            raise NotAvailableInModeError(
                "encrypt is not available in pq mode; use ML-KEM-768 encapsulate instead"
            )

        if not isinstance(plaintext, bytes):
            raise KeyMismatchError("plaintext must be bytes")

        if len(plaintext) > FIPS_PLAINTEXT_MAX_LEN:
            raise PlaintextLimitError(
                f"plaintext exceeds documented AES-GCM bound of {FIPS_PLAINTEXT_MAX_LEN} bytes "
                f"(RFC 5116 sec 5.1)"
            )

        # fips mode: key.public carries the symmetric, not public, key bytes (E3).
        if len(key.public) != FIPS_AES_GCM_KEY_LEN:
            raise KeyMismatchError(
                f"fips mode key.public must be {FIPS_AES_GCM_KEY_LEN} bytes "
                f"(the 32-byte ECDH shared secret / AES-256 key), got {len(key.public)}"
            )

        # Fresh 96-bit nonce from the OS CSPRNG (Python secrets wraps getrandom()).
        if key.private is None:
            raise KeyMismatchError("fips mode encrypt requires private key in key.private")

        if key.algorithm == "ECDH-P256":
            try:
                priv = ec.derive_private_key(int.from_bytes(key.private, "big"), FIPS_EC_CURVE)
                pub_x = priv.public_key().public_numbers().x.to_bytes(FIPS_EC_P256_PUBLIC_KEY_LEN, "big")
                if pub_x != key.public:
                    raise KeyMismatchError("key.private does not correspond to key.public")
            except KeyMismatchError:
                raise
            except Exception as exc:
                raise KeyMismatchError(f"invalid private key scalar: {exc}") from exc

        nonce = secrets.token_bytes(FIPS_AES_GCM_NONCE_LEN)

        # AESGCM.encrypt returns ciphertext || tag (16-byte tag appended).
        ciphertext_with_tag = AESGCM(key.public).encrypt(nonce, plaintext, associated_data)

        return CiphertextEnvelope(
            mode="fips",
            algorithm="AES-256-GCM",
            key_id=key.key_id,
            nonce=nonce,
            ciphertext=ciphertext_with_tag,
            kem_ciphertext=None,
            associated_data=associated_data,
        )

    # ------------------------------------------------------------------
    # decrypt
    # ------------------------------------------------------------------
    def decrypt(self, key: KeyMaterial, envelope: CiphertextEnvelope) -> bytes:
        """Recover plaintext from a CiphertextEnvelope produced by encrypt().

        fips mode: AES-256-GCM open under key.public. A tampered ciphertext
        raises, wrapped as DualModeError, and never returns partial
        plaintext.

        pq mode:   raises NotAvailableInModeError (use decapsulate for ML-KEM).
        """
        if self._mode != "fips":
            raise NotAvailableInModeError(
                "decrypt is not available in pq mode; use decapsulate for ML-KEM"
            )

        if not isinstance(envelope, CiphertextEnvelope):
            raise KeyMismatchError("envelope must be a CiphertextEnvelope")

        if len(envelope.nonce) != FIPS_AES_GCM_NONCE_LEN:
            raise MalformedCiphertextError(
                f"nonce must be {FIPS_AES_GCM_NONCE_LEN} bytes, got {len(envelope.nonce)}"
            )

        if len(envelope.ciphertext) < FIPS_AES_GCM_TAG_LEN:
            raise MalformedCiphertextError(
                f"ciphertext+tag too short: need at least {FIPS_AES_GCM_TAG_LEN} bytes, "
                f"got {len(envelope.ciphertext)}"
            )

        if envelope.key_id != key.key_id:
            raise KeyMismatchError(
                "decrypt() key_id does not match envelope key_id "
                "(wrong key for this ciphertext)"
            )

        if key.private is None:
            raise KeyMismatchError("fips mode decrypt requires private key in key.private")

        if key.algorithm == "ECDH-P256":
            try:
                priv = ec.derive_private_key(int.from_bytes(key.private, "big"), FIPS_EC_CURVE)
                pub_x = priv.public_key().public_numbers().x.to_bytes(FIPS_EC_P256_PUBLIC_KEY_LEN, "big")
                if pub_x != key.public:
                    raise KeyMismatchError("key.private does not correspond to key.public")
            except KeyMismatchError:
                raise
            except Exception as exc:
                raise KeyMismatchError(f"invalid private key scalar: {exc}") from exc

        try:
            # associated_data was already folded in by encrypt(); the GCM tag
            # check covers it.  AESGCM.decrypt() verifies the tag before
            # returning, so partial plaintext can never escape.
            plaintext = AESGCM(key.public).decrypt(envelope.nonce, envelope.ciphertext, envelope.associated_data)
        except InvalidTag as exc:
            raise MalformedCiphertextError(
                "authentication failed: invalid or tampered ciphertext"
            ) from exc

        return plaintext

    # ------------------------------------------------------------------
    # sign
    # ------------------------------------------------------------------
    def sign(
        self,
        key: KeyMaterial,
        payload: bytes,
        context: bytes | None = None,
    ) -> SignatureEnvelope:
        """ML-DSA-65 signature over payload with the optional FIPS 204 context string.

        fips mode: raises NotAvailableInModeError (E5).
        pq mode:   ML-DSA-65 signature.
        """
        raise NotAvailableInModeError(
            "sign is not available in FIPS mode: fips mode provides authenticated encryption; "
            "use post-quantum mode for digital signatures."
        )

    # ------------------------------------------------------------------
    # verify
    # ------------------------------------------------------------------
    def verify(
        self,
        key: KeyMaterial,
        signature: SignatureEnvelope,
        data: bytes,
        context: bytes | None = None,
    ) -> VerificationResult:
        """Verify a signature; never raises for a wrong answer.

        fips mode: raises NotAvailableInModeError (E6) — mirror of sign().
        pq mode:   ML-DSA-65 verification.
        """
        raise NotAvailableInModeError(
            "verify is not available in FIPS mode: fips mode provides authenticated encryption; "
            "use post-quantum mode for digital signatures."
        )

    # ------------------------------------------------------------------
    # encapsulate
    # ------------------------------------------------------------------
    def encapsulate(self, encapsulation_key: bytes) -> tuple[bytes, bytes]:
        """ML-KEM-768 encapsulate. Returns (shared_secret, kem_ciphertext).

        fips mode raises NotAvailableInModeError: FIPS 140-3 has no approved KEM,
        only key agreement.
        pq mode:   ML-KEM-768 encapsulation.
        """
        raise NotAvailableInModeError(
            "encapsulate is not available in FIPS mode: FIPS 140-3 has no approved KEM; "
            "use post-quantum mode for ML-KEM-768."
        )

    # ------------------------------------------------------------------
    # decapsulate
    # ------------------------------------------------------------------
    def decapsulate(self, decapsulation_key: bytes, kem_ciphertext: bytes) -> bytes:
        """ML-KEM-768 decapsulate. Returns the 32-byte shared secret.

        fips mode raises NotAvailableInModeError.
        pq mode:   ML-KEM-768 decapsulation.
        """
        raise NotAvailableInModeError(
            "decapsulate is not available in FIPS mode: FIPS 140-3 has no approved KEM; "
            "use post-quantum mode for ML-KEM-768."
        )

    # ------------------------------------------------------------------
    # agree
    # ------------------------------------------------------------------
    def agree(self, key: KeyMaterial, peer_public: bytes) -> bytes:
        """ECDH P-256 key agreement. Returns the 32-byte shared secret. fips mode only.

        Raises KeyMismatchError if len(peer_public) != 65 (uncompressed point)
        or the point is not on SECP256R1.

        pq mode raises NotAvailableInModeError: ML-KEM encapsulate() replaces agree().
        """
        if self._mode != "fips":
            raise NotAvailableInModeError(
                "agree is not available in pq mode; ML-KEM encapsulate() replaces agree() there"
            )

        if not isinstance(peer_public, (bytes, bytearray)):
            raise KeyMismatchError("peer_public must be bytes")

        if len(peer_public) == FIPS_UNCOMPRESSED_LEN:
            if peer_public[0] != 0x04:
                raise KeyMismatchError(
                    f"uncompressed EC point must start with 0x04 prefix, "
                    f"got 0x{peer_public[0]:02x}"
                )
            point_bytes = bytes(peer_public)
        elif len(peer_public) == FIPS_EC_P256_PUBLIC_KEY_LEN:
            # X-only coordinate (32 bytes) from generate_key() key.public.
            # Reconstruct the uncompressed EC point on SECP256R1 (y^2 = x^3 - 3x + b mod p)
            x_int = int.from_bytes(peer_public, "big")
            p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
            a = -3
            b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
            z = (pow(x_int, 3, p) + a * x_int + b) % p
            y_int = pow(z, (p + 1) // 4, p)
            if (y_int * y_int) % p != z:
                raise KeyMismatchError("peer_public 32-byte X coordinate is not on SECP256R1")
            point_bytes = b"\x04" + bytes(peer_public) + y_int.to_bytes(32, "big")
        else:
            raise KeyMismatchError(
                f"uncompressed EC point must be {FIPS_UNCOMPRESSED_LEN} bytes "
                f"(0x04 || X || Y), got {len(peer_public)}"
            )

        # Rebuild the local private key from the 32-byte scalar in key.private.
        if key.private is None:
            raise KeyMismatchError("agree requires a private key (key.private is None)")

        if len(key.private) != FIPS_EC_P256_PRIVATE_KEY_LEN:
            raise KeyMismatchError(
                f"key.private must be {FIPS_EC_P256_PRIVATE_KEY_LEN} bytes (scalar), "
                f"got {len(key.private)}"
            )

        private_scalar = int.from_bytes(key.private, "big")

        try:
            private_key = ec.derive_private_key(private_scalar, FIPS_EC_CURVE)
            peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
                FIPS_EC_CURVE, point_bytes
            )
            shared_secret = private_key.exchange(ec.ECDH(), peer_key)
        except ValueError as exc:
            # cryptography raises ValueError for a point not on the curve.
            raise KeyMismatchError(
                f"peer_public is not a valid uncompressed SECP256R1 point: {exc}"
            ) from exc

        if len(shared_secret) != FIPS_AES_GCM_KEY_LEN:
            raise KeyMismatchError(
                f"ECDH shared secret must be {FIPS_AES_GCM_KEY_LEN} bytes, "
                f"got {len(shared_secret)}"
            )

        return shared_secret
