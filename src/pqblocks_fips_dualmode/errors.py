"""errors.py — error hierarchy for dual-mode cryptography.

Defines DualModeError base class with structured sub-exceptions for
FIPS 140-3 and PQ algorithm-specific error conditions. All public API
methods raise one of these types (never bare ValueError or None).
"""

from dataclasses import dataclass


class DualModeError(Exception):
    """Base class for every error raised by the dual-mode cryptographic envelope."""
    pass


class InvalidModeError(DualModeError, ValueError):
    """mode is not \"fips\" or \"pq\" (E1, E2)."""
    pass


class KeyMismatchError(DualModeError, TypeError, ValueError):
    """Key bytes are absent, wrong-length or wrong-type for the active mode (E3, E4, E11)."""
    pass


class NotAvailableInModeError(DualModeError, NotImplementedError):
    """Operation is not offered by the active mode (E5, E6)."""
    pass


class MalformedCiphertextError(DualModeError, ValueError):
    """Ciphertext is not the exact length the mode's KEM expects (E12)."""
    pass


class ContextTooLongError(DualModeError, ValueError):
    """ML-DSA context string exceeds the FIPS 204 bound of 255 bytes (E15)."""
    pass


class KeyFormatError(DualModeError, ValueError):
    """PEM/JWK blob is unparseable or the wrong key type (gap Check 3 (correctness))."""
    pass


class PlaintextLimitError(DualModeError, ValueError):
    """Plaintext exceeds the documented AES-GCM practical limit (E10)."""
    pass