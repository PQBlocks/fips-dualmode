"""Slice feature 4 tests — PQ mode (ML-KEM-768 + ML-DSA-65) per spec §5."""

import pytest
from pqblocks_fips_dualmode import CryptoEnvelope
from pqblocks_fips_dualmode.models import KeyMaterial, SignatureEnvelope, CiphertextEnvelope, VerificationResult
from pqblocks_fips_dualmode.errors import NotAvailableInModeError, KeyMismatchError, MalformedCiphertextError, ContextTooLongError, PlaintextLimitError
from pqblocks_fips_dualmode import _policy as policy
import pytest


# ----------------------------------------------------------------------
# PQ mode instantiation & method surface
# ----------------------------------------------------------------------

def test_pq_mode_instantiates():
    env = CryptoEnvelope(mode="pq")
    assert env.mode == "pq"


def test_pq_mode_has_all_pq_methods():
    env = CryptoEnvelope(mode="pq")
    for m in ("generate_key", "encapsulate", "decapsulate", "sign", "verify"):
        assert hasattr(env, m) and callable(getattr(env, m)), f"missing {m}"


def test_pq_mode_fips_methods_raise_not_available():
    env = CryptoEnvelope(mode="pq")
    for m in ("encrypt", "decrypt", "agree"):
        with pytest.raises(NotAvailableInModeError):
            getattr(env, m)()


# ----------------------------------------------------------------------
# generate_key (spec §1.3: pq mode = ML-DSA-65 keypair)
# ----------------------------------------------------------------------

def test_pq_generate_key_returns_keymaterial():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    assert isinstance(km, KeyMaterial)
    assert km.mode == "pq"
    assert km.algorithm == "ML-DSA-65"
    assert len(km.key_id) == policy.KEY_ID_HEX_LEN
    assert len(km.public) == policy.PQ_SIG_PUBLIC_KEY_LEN  # 1952
    assert len(km.private) == policy.PQ_SIG_PRIVATE_KEY_LEN  # 4032


def test_pq_generate_key_len_public_is_1952():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    assert len(km.public) == 1952, f"expected 1952, got {len(km.public)}"


def test_pq_generate_key_len_private_is_4032():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    assert len(km.private) == 4032, f"expected 4032, got {len(km.private)}"


def test_pq_generate_key_key_id_len():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    assert len(km.key_id) == 16, f"expected 16, got {len(km.key_id)}"


# ----------------------------------------------------------------------
# encapsulate / decapsulate (spec §1.3: ML-KEM-768)
# ----------------------------------------------------------------------

def test_pq_encapsulate_returns_tuple_ss_and_kt():
    env = CryptoEnvelope(mode="pq")
    import oqs
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pk = kem.generate_keypair_seed(b"\xaa" * 64)
    ss, ct = env.encapsulate(pk)
    assert isinstance(ss, bytes)
    assert isinstance(ct, bytes)
    assert len(ss) == 32, f"expected 32-byte shared secret, got {len(ss)}"
    assert len(ct) == policy.PQ_KEM_CIPHERTEXT_LEN  # 1088


def test_pq_encapsulate_bad_key_len_raises_key_mismatch():
    env = CryptoEnvelope(mode="pq")
    with pytest.raises(KeyMismatchError):
        env.encapsulate(b"\x00" * 100)  # too short


def test_pq_encapsulate_wrong_len_raises_key_mismatch():
    env = CryptoEnvelope(mode="pq")
    with pytest.raises(KeyMismatchError):
        env.encapsulate(b"\x00" * 2000)  # too long


def test_pq_decapsulate_returns_ss():
    env = CryptoEnvelope(mode="pq")
    import oqs
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pk = kem.generate_keypair_seed(b"\xaa" * 64)
    ct, ss1 = kem.encap_secret(pk)  # generate ciphertext
    ss2 = env.decapsulate(kem.export_secret_key(), ct)
    assert isinstance(ss2, bytes)
    assert len(ss2) == 32
    assert ss1 == ss2  # deterministic


def test_pq_decapsulate_wrong_key_len_raises_key_mismatch():
    env = CryptoEnvelope(mode="pq")
    with pytest.raises(KeyMismatchError):
        env.decapsulate(b"\x00" * 100, b"\x00" * policy.PQ_KEM_CIPHERTEXT_LEN)


def test_pq_decapsulate_empty_ct_raises_malformed_ciphertext():
    env = CryptoEnvelope(mode="pq")
    with pytest.raises(MalformedCiphertextError):
        env.decapsulate(b"\x00" * policy.PQ_KEM_PRIVATE_KEY_LEN, b"")


# ----------------------------------------------------------------------
# sign / verify (spec §1.3: ML-DSA-65)
# ----------------------------------------------------------------------

def test_pq_sign_returns_signature_envelope():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()  # ML-DSA-65 keypair
    sig = env.sign(km, b"test payload", None)
    assert isinstance(sig, SignatureEnvelope)
    assert len(sig.signature) == policy.PQ_SIG_SIGNATURE_LEN  # 3309


def test_pq_sign_len_3309():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    sig = env.sign(km, b"test", None)
    assert len(sig.signature) == 3309


def test_pq_verify_returns_verification_result():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    sig = env.sign(km, b"test payload", None)
    res = env.verify(km, sig, b"test payload", None)
    assert isinstance(res, VerificationResult)
    assert res.valid is True


def test_pq_verify_valid_returns_true():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    sig = env.sign(km, b"hello world", None)
    res = env.verify(km, sig, b"hello world", None)
    assert res.valid is True


def test_pq_verify_wrong_data_fails_gracefully():
    """verify never raises for wrong answer; returns valid=False."""
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    sig = env.sign(km, b"test payload", None)
    res = env.verify(km, sig, b"different data", None)
    assert res.valid is False


def test_pq_verify_bad_sig_len_raises_key_mismatch():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    bad_sig = SignatureEnvelope(mode="pq", algorithm="ML-DSA-65", signature=b"\x00" * 100, key_id="0" * 16)
    with pytest.raises(KeyMismatchError):
        env.verify(km, bad_sig, b"test", None)


def test_pq_verify_tampered_signature_invalid():
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    sig = env.sign(km, b"test", None)
    # Tamper with the signature
    tampered = bytearray(sig.signature)
    tampered[0] ^= 0xFF
    bad_sig = SignatureEnvelope(
        mode="pq", algorithm="ML-DSA-65", signature=bytes(tampered), key_id=sig.key_id
    )
    res = env.verify(km, bad_sig, b"test", None)
    assert res.valid is False


def test_pq_verify_never_raises_for_wrong_answer():
    """E7: verify returns VerificationResult, never raises for wrong signature."""
    env = CryptoEnvelope(mode="pq")
    km = env.generate_key()
    sig = env.sign(km, b"test", None)
    res = env.verify(km, sig, b"different", None)
    assert res.valid is False
    assert isinstance(res, VerificationResult)


def test_fips_mode_rejects_pq_methods():
    env = CryptoEnvelope(mode="fips")
    for m in ("encapsulate", "decapsulate", "sign", "verify"):
        with pytest.raises(NotAvailableInModeError):
            getattr(env, m)()