"""pqblocks_fips_dualmode — dual-mode FIPS 140-3 / PQ abstraction.

The public surface is exposed through CryptoEnvelope,
which dispatches to the appropriate mode implementation.

Contract: every method named in the specification exists and
raises appropriate errors when called with invalid arguments.

Runtime: when called with the correct method signature,
the façade delegates to the owning mode implementation (core.CryptoEnvelope
for FIPS half, pq.PQCryptoEnvelope for PQ half).
"""

from typing import Literal

# Re-export the error hierarchy and models
from pqblocks_fips_dualmode.errors import (
    DualModeError,
    InvalidModeError,
    KeyMismatchError,
    NotAvailableInModeError,
    MalformedCiphertextError,
    ContextTooLongError,
    KeyFormatError,
    PlaintextLimitError,
)
from pqblocks_fips_dualmode.models import (
    KeyMaterial,
    CiphertextEnvelope,
    SignatureEnvelope,
    VerificationResult,
)
from pqblocks_fips_dualmode import _policy as policy

__all__ = [
    "CryptoEnvelope",
    "DualModeError",
    "InvalidModeError",
    "KeyMismatchError",
    "NotAvailableInModeError",
    "MalformedCiphertextError",
    "ContextTooLongError",
    "KeyFormatError",
    "PlaintextLimitError",
    "KeyMaterial",
    "CiphertextEnvelope",
    "SignatureEnvelope",
    "VerificationResult",
    "policy",
]


class CryptoEnvelope:
    """Bind an envelope to one mode for its lifetime.

    mode="fips": FIPS 140-3 approved classical algorithms only (ECDH P-256 + AES-256-GCM).
    mode="pq":   post-quantum mode (ML-KEM-768 + ML-DSA-65).

    Raises InvalidModeError for any other mode (spec E1/E2).

    Runtime contract: correctly-signed calls are delegated to the owning mode implementation.
    """

    def __init__(self, mode: Literal["fips", "pq"]) -> None:
        if mode not in ("fips", "pq"):
            raise InvalidModeError(
                f"unsupported mode: {mode!r}; expected 'fips' or 'pq'"
            )
        self._mode = mode

    # Policy constants re-exported on the facade (spec section 3 E10 reads
    # env.FIPS_PLAINTEXT_MAX_LEN directly from the public object).
    FIPS_PLAINTEXT_MAX_LEN = policy.FIPS_PLAINTEXT_MAX_LEN
    PQ_SIG_MAX_CONTEXT_LEN = policy.PQ_SIG_MAX_CONTEXT_LEN

    @property
    def mode(self) -> Literal["fips", "pq"]:
        return self._mode

    # ------------------------------------------------------------------
    # runtime dispatcher
    # ------------------------------------------------------------------
    def _dispatch(self, name, args, kwargs):
        """Route a method call to the mode that owns it.

        All calls forward to the owning mode's
        implementation. The implementation raises NotAvailableInModeError
        for methods not supported in its mode (e.g. fips.encapsulate() or
        pq.encrypt()). This keeps the runtime contract intact
        while letting legitimate zero-arg methods such as generate_key()
        work through the public facade.
        """
    # Mode-method validity map: which methods are valid per mode
        valid_methods = {
            "fips": {
                "generate_key", "encrypt", "decrypt", "agree",
            },
            "pq": {
                "generate_key", "encapsulate", "decapsulate", "sign", "verify",
            },
        }

        # If the method is not valid for this mode, raise early with
        # NotAvailableInModeError instead of forwarding to an impl that
        # may raise TypeError for a signature mismatch (E5/E6 contract).
        if name not in valid_methods[self._mode]:
            from pqblocks_fips_dualmode.errors import NotAvailableInModeError

            raise NotAvailableInModeError(
                f"{name}() is not available in {self._mode} mode"
            )

        # import lazily to avoid a circular import of pq at package init
        if self._mode == "fips":
            from pqblocks_fips_dualmode.core import CryptoEnvelope as _FIPS

            impl = _FIPS(mode="fips")
            return getattr(impl, name)(*args, **kwargs)

        from pqblocks_fips_dualmode.pq import PQCryptoEnvelope as _PQ

        impl = _PQ()
        return getattr(impl, name)(*args, **kwargs)

    # ------------------------------------------------------------------
    # scaffold-facing methods (zero-arg => NotImplementedError)
    # ------------------------------------------------------------------

    def generate_key(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        """Generate a fresh keypair using the OS CSPRNG source (os.urandom)."""
        return self._dispatch("generate_key", args, kwargs)

    def encrypt(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return self._dispatch("encrypt", args, kwargs)

    def decrypt(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return self._dispatch("decrypt", args, kwargs)

    def sign(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return self._dispatch("sign", args, kwargs)

    def verify(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return self._dispatch("verify", args, kwargs)

    def encapsulate(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return self._dispatch("encapsulate", args, kwargs)

    def decapsulate(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return self._dispatch("decapsulate", args, kwargs)

    def agree(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return self._dispatch("agree", args, kwargs)
