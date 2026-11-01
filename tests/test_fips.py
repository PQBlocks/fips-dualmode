"""Tests for FIPS mode core (spec section 3, FIPS-mode edge cases).

Contract: these test src/pqblocks_fips_dualmode/core.py directly (the FIPS
implementation), verifying the FIPS mode operations.

Edge cases per spec section 3 ledger (FIPS half):
  E1: plaintext that is not bytes                    -> KeyMismatchError
  E2: tampered ciphertext                             -> MalformedCiphertextError
  E3: decrypt under a wrong key.public                -> KeyMismatchError
  E4: wrong AAD                                       -> MalformedCiphertextError
  E5: plaintext over the documented limit             -> PlaintextLimitError
  E6: empty plaintext (E9 alias)                      -> round-trips fine
  E7: agree with non-bytes peer_public                -> KeyMismatchError
  E8: agree with wrong-length peer_public             -> KeyMismatchError
  E9: agree with valid peer_public -> 32-byte shared secret
  E10: worked-example-A interop: our AES-256-GCM vs cryptography AESGCM
  E11: pq mode: every fips method raises NotAvailableInModeError
  E12: encrypt-then-decrypt returns exact bytes
"""

import pytest

from pqblocks_fips_dualmode.core import CryptoEnvelope
from pqblocks_fips_dualmode.errors import (
    KeyMismatchError,
    MalformedCiphertextError,
    NotAvailableInModeError,
    PlaintextLimitError,
)


def env() -> CryptoEnvelope:
    return CryptoEnvelope(mode="fips")


# ------------------------------------------------------------------
# E1: plaintext that is not bytes -> KeyMismatchError
# ------------------------------------------------------------------
def test_e1_plaintext_not_bytes_rejected():
    e = env()
    key = e.generate_key()
    with pytest.raises(KeyMismatchError):
        e.encrypt(key, "not bytes")  # type: ignore[arg-type]


# ------------------------------------------------------------------
# E2: tampered ciphertext -> MalformedCiphertextError
# ------------------------------------------------------------------
def test_e2_tampered_ciphertext_rejected():
    e = env()
    key = e.generate_key()
    ct = e.encrypt(key, b"secret payload", b"aad")
    tampered = bytearray(ct.ciphertext)
    tampered[0] ^= 0xFF
    bad = ct.__class__(
        mode=ct.mode,
        algorithm=ct.algorithm,
        key_id=ct.key_id,
        nonce=ct.nonce,
        ciphertext=bytes(tampered),
        kem_ciphertext=ct.kem_ciphertext,
        associated_data=ct.associated_data,
    )
    with pytest.raises(MalformedCiphertextError):
        e.decrypt(key, bad)


# ------------------------------------------------------------------
# E3: decrypt under a wrong key.public -> KeyMismatchError
# ------------------------------------------------------------------
def test_e3_wrong_key_decrypt_rejected():
    e = env()
    key1 = e.generate_key()
    key2 = e.generate_key()
    ct = e.encrypt(key1, b"plaintext", b"aad")
    with pytest.raises(KeyMismatchError):
        e.decrypt(key2, ct)


# ------------------------------------------------------------------
# E4: wrong AAD -> MalformedCiphertextError
# ------------------------------------------------------------------
def test_e4_wrong_aad_rejected():
    e = env()
    key = e.generate_key()
    ct = e.encrypt(key, b"payload", b"correct-aad")
    bad_aad = ct.__class__(
        mode=ct.mode,
        algorithm=ct.algorithm,
        key_id=ct.key_id,
        nonce=ct.nonce,
        ciphertext=ct.ciphertext,
        kem_ciphertext=ct.kem_ciphertext,
        associated_data=b"WRONG-AAD",
    )
    with pytest.raises(MalformedCiphertextError):
        e.decrypt(key, bad_aad)


# ------------------------------------------------------------------
# E5: plaintext over the documented limit -> PlaintextLimitError
# ------------------------------------------------------------------
def test_e5_plaintext_over_limit_rejected():
    e = env()
    key = e.generate_key()
    # The documented limit is 16 MiB = 16777216 bytes
    with pytest.raises(PlaintextLimitError):
        e.encrypt(key, b"\x00" * (16_777_216 + 1))  # over 16 MiB


# ------------------------------------------------------------------
# E6: empty plaintext (E9 alias) round-trips fine
# ------------------------------------------------------------------
def test_e6_empty_plaintext_roundtrips():
    e = env()
    key = e.generate_key()
    ct = e.encrypt(key, b"")
    assert len(ct.ciphertext) == 16  # tag only, zero plaintext
    assert e.decrypt(key, ct) == b""


# ------------------------------------------------------------------
# E7: agree with non-bytes peer_public -> KeyMismatchError
# ------------------------------------------------------------------
def test_e7_agree_non_bytes_peer_rejected():
    e = env()
    key = e.generate_key()
    with pytest.raises(KeyMismatchError):
        e.agree(key, "not bytes")  # type: ignore[arg-type]


# ------------------------------------------------------------------
# E8: agree with wrong-length peer_public -> KeyMismatchError
# ------------------------------------------------------------------
def test_e8_agree_wrong_length_peer_rejected():
    e = env()
    key = e.generate_key()
    with pytest.raises(KeyMismatchError):
        e.agree(key, b"\x04" + b"\x00" * 30)  # 31 bytes, not 65


# ------------------------------------------------------------------
# E9: agree with valid peer -> 32-byte shared secret
# ------------------------------------------------------------------
def test_e9_agree_valid_peer_returns_32_bytes():
    e = env()
    key = e.generate_key()
    # build a proper 65-byte uncompressed SECP256R1 point (0x04 || X || Y)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    peer_priv = ec.generate_private_key(ec.SECP256R1())
    peer_pub = peer_priv.public_key()
    peer_pub_bytes = peer_pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert len(peer_pub_bytes) == 65
    assert peer_pub_bytes[0] == 0x04

    ss = e.agree(key, peer_pub_bytes)
    assert len(ss) == 32


# ------------------------------------------------------------------
# E10: worked-example-A interop: our AES-256-GCM vs cryptography AESGCM
# ------------------------------------------------------------------
def test_e10_worked_example_a_interop():
    e = env()
    key = e.generate_key()
    pt = b"worked example A interop"
    aad = b"worked-aad"

    # ours
    ct = e.encrypt(key, pt, aad)

    # cryptography directly
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ct_direct = AESGCM(key.public).encrypt(ct.nonce, pt, aad)
    # AESGCM returns ciphertext || tag
    assert ct.ciphertext == ct_direct
    assert e.decrypt(key, ct) == pt


# ------------------------------------------------------------------
# E11: pq mode: every fips method raises NotAvailableInModeError
# ------------------------------------------------------------------
@pytest.mark.parametrize(
    "method_name",
    ["encrypt", "decrypt", "agree", "sign", "verify", "encapsulate", "decapsulate"],
)
def test_e11_pq_mode_fips_methods_unavailable(method_name):
    e = CryptoEnvelope(mode="pq")
    key = env().generate_key()
    method = getattr(e, method_name)
    try:
        if method_name == "encrypt":
            method(key, b"x")
        elif method_name == "decrypt":
            from pqblocks_fips_dualmode.models import CiphertextEnvelope

            method(
                key,
                CiphertextEnvelope(
                    mode="fips",
                    algorithm="AES-256-GCM",
                    key_id=key.key_id,
                    nonce=b"\x00" * 12,
                    ciphertext=b"\x00" * 16,
                    associated_data=b"",
                ),
            )
        elif method_name == "agree":
            method(key, b"\x04" + b"\x00" * 64)
        elif method_name == "sign":
            method(key, b"x")
        elif method_name == "verify":
            from pqblocks_fips_dualmode.models import SignatureEnvelope

            method(
                key,
                SignatureEnvelope(
                    mode="fips",
                    algorithm="ML-DSA-65",
                    key_id=key.key_id,
                    signature=b"\x00" * 3309,
                    context=b"",
                ),
                b"x",
            )
        elif method_name == "encapsulate":
            method(b"x")
        elif method_name == "decapsulate":
            method(b"x", b"y")
    except NotAvailableInModeError:
        pass  # expected
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{method_name} raised {type(exc).__name__}, expected NotAvailableInModeError")


# ------------------------------------------------------------------
# E12: encrypt-then-decrypt returns exact bytes
# ------------------------------------------------------------------
def test_e12_encrypt_decrypt_exact_bytes():
    e = env()
    key = e.generate_key()
    payload = b"The quick brown fox jumps over the lazy dog" * 100
    ct = e.encrypt(key, payload, b"final-aad")
    assert e.decrypt(key, ct) == payload


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
