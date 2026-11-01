from pqblocks_fips_dualmode import CryptoEnvelope
from pqblocks_fips_dualmode._policy import FIPS_PLAINTEXT_MAX_LEN, FIPS_AES_GCM_NONCE_LEN
from pqblocks_fips_dualmode.models import SignatureEnvelope, CiphertextEnvelope
from dataclasses import replace
import pytest
from pqblocks_fips_dualmode.errors import (
    NotAvailableInModeError,
    KeyMismatchError,
    MalformedCiphertextError,
    ContextTooLongError,
    PlaintextLimitError,
)

# ----------------------------------------------------------------------
# Test E1: Empty plaintext - should be allowed (16-byte tag only)
# ----------------------------------------------------------------------
def test_fips_encrypt_empty_plaintext():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    cipher = env.encrypt(key, b"")
    assert isinstance(cipher, type(cipher))
    assert len(cipher.ciphertext) >= 16  # at least 16-byte tag

# ----------------------------------------------------------------------
# Test E2: Oversized plaintext - should raise PlaintextLimitError
# ----------------------------------------------------------------------
def test_fips_encrypt_plaintext_too_large():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    with pytest.raises(PlaintextLimitError):
        env.encrypt(key, b"x" * (env.FIPS_PLAINTEXT_MAX_LEN + 1))

# ----------------------------------------------------------------------
# Test E3: Malformed ciphertext (wrong tag) - should raise MalformedCiphertextError
# ----------------------------------------------------------------------
def test_fips_decrypt_malformed_ciphertext():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    cipher = env.encrypt(key, b"test data")
    # Tamper with ciphertext
    cipher.ciphertext = cipher.ciphertext[:-1]  # remove last byte of tag
    with pytest.raises(MalformedCiphertextError):
        env.decrypt(key, cipher)

# ----------------------------------------------------------------------
# Test E4: Wrong key - should raise KeyMismatchError
# ----------------------------------------------------------------------
def test_fips_decrypt_wrong_key():
    env = CryptoEnvelope(mode="fips")
    key1 = env.generate_key()
    key2 = env.generate_key()
    cipher = env.encrypt(key1, b"test data")
    with pytest.raises(KeyMismatchError):
        env.decrypt(key2, cipher)

# ----------------------------------------------------------------------
# Test E5: Wrong nonce size - should raise MalformedCiphertextError
# ----------------------------------------------------------------------
def test_fips_decrypt_wrong_nonce_size():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    cipher = env.encrypt(key, b"test data")
    # Tamper with nonce size
    bad_cipher = cipher.copy()
    bad_cipher.nonce = b"x" * 10  # wrong size
    with pytest.raises(MalformedCiphertextError):
        env.decrypt(key, bad_cipher)

# ----------------------------------------------------------------------
# Test E6: Tampered ciphertext (invalid tag) - should raise MalformedCiphertextError
# ----------------------------------------------------------------------
def test_fips_decrypt_tampered_ciphertext():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    cipher = env.encrypt(key, b"test data")
    # Tamper with ciphertext
    cipher.ciphertext = cipher.ciphertext[:-1] + b"\x00"
    with pytest.raises(MalformedCiphertextError):
        env.decrypt(key, cipher)

# ----------------------------------------------------------------------
# Test E7: Context too long in sign/verify - should raise ContextTooLongError
# ----------------------------------------------------------------------
def test_pq_sign_context_too_long():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    # 256-byte context should fail (limit is 255)
    with pytest.raises(ContextTooLongError):
        env.sign(key, b"test", "x" * 256)

# ----------------------------------------------------------------------
# Test E8: Empty signature - should raise KeyMismatchError
# ----------------------------------------------------------------------
def test_pq_verify_empty_signature():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    sig = env.sign(key, b"test", None)
    # Empty signature bytes
    bad_sig = sig.copy()
    bad_sig.signature = b""
    with pytest.raises(KeyMismatchError):
        env.verify(key, bad_sig, b"test")

# ----------------------------------------------------------------------
# Test E9: Wrong algorithm in verify - should raise KeyMismatchError
# ----------------------------------------------------------------------
def test_pq_verify_wrong_algorithm():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    sig = env.sign(key, b"test", None)
    # Wrong algorithm
    bad_sig = sig.copy()
    bad_sig.algorithm = "ML-DSA-64"  # doesn't exist
    with pytest.raises(KeyMismatchError):
        env.verify(key, bad_sig, b"test")

# ----------------------------------------------------------------------
# Test E10: Wrong key in verify - should return valid=False, reason="wrong-key"
# ----------------------------------------------------------------------
def test_pq_verify_wrong_key():
    env = CryptoEnvelope(mode="pq")
    key1 = env.generate_key()
    key2 = env.generate_key()
    sig = env.sign(key1, b"test", None)
    res = env.verify(key2, sig, b"test")
    assert res.valid is False
    assert res.reason == "wrong-key"

# ----------------------------------------------------------------------
# Test E11: Tampered signature - should return valid=False, not raise
# ----------------------------------------------------------------------
def test_pq_verify_tampered_signature():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    sig = env.sign(key, b"test", None)
    # Tamper with signature bytes
    tampered_sig = bytearray(sig.signature)
    tampered_sig[0] ^= 0xFF
    bad_sig = sig.copy()
    bad_sig.signature = bytes(tampered_sig)
    res = env.verify(key, bad_sig, b"test")
    assert res.valid is False
    assert res.reason == "bad-signature"

# ----------------------------------------------------------------------
# Test E12: Wrong context in verify - should return valid=False, reason="bad-signature"
# ----------------------------------------------------------------------
def test_pq_verify_context_mismatch():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    sig = env.sign(key, b"test", b"context1")
    res = env.verify(key, sig, b"test", b"context2")  # different context
    assert res.valid is False
    assert res.reason == "bad-signature"

# ----------------------------------------------------------------------
# Test E13: Non-bytes plaintext - should raise KeyMismatchError
# ----------------------------------------------------------------------
def test_fips_encrypt_non_bytes_plaintext():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    with pytest.raises(KeyMismatchError):
        env.encrypt(key, "not bytes")

# ----------------------------------------------------------------------
# Test E14: Non-bytes ciphertext - should raise KeyMismatchError
# ----------------------------------------------------------------------
def test_fips_decrypt_non_ciphertext():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    with pytest.raises(KeyMismatchError):
        env.decrypt(key, "not a CiphertextEnvelope")

# ----------------------------------------------------------------------
# Test E15: Wrong key ID in CiphertextEnvelope - should raise KeyMismatchError
# ----------------------------------------------------------------------
def test_ciphertext_key_mismatch():
    env = CryptoEnvelope(mode="fips")
    key1 = env.generate_key()
    key2 = env.generate_key()
    cipher = env.encrypt(key1, b"test")
    # Wrong key_id in ciphertext
    bad_cipher = cipher.copy()
    bad_cipher.key_id = key2.key_id
    with pytest.raises(KeyMismatchError):
        env.decrypt(key1, bad_cipher)

# ----------------------------------------------------------------------
# DEF-GAP-1: Context binding
# ----------------------------------------------------------------------
def test_pq_sign_context_binding_valid():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    payload = b"test message"
    ctx = b"my context"
    sig = env.sign(key, payload, ctx)
    result = env.verify(key, sig, payload, ctx)
    assert result.valid is True, "Signature with context should be valid (tcId=3)"
    sig_no_ctx = env.sign(key, payload, None)
    result_no_ctx = env.verify(key, sig_no_ctx, payload, ctx)
    assert result_no_ctx.valid is False, "Signature without context should be invalid (tcId=4)"

def test_pq_sign_context_too_long():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    payload = b"test message"
    with pytest.raises(ContextTooLongError):
        env.sign(key, payload, b"x" * 256)  # 256 bytes > 255 limit

# ----------------------------------------------------------------------
# DEF-GAP-3: Malformed signature returns reason not raise
# ----------------------------------------------------------------------
def test_pq_verify_malformed_signature_reason():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    sig = env.sign(key, b"test", None)
    bad_sig = sig.copy()
    bad_sig.signature = sig.signature[:-1]
    result = env.verify(key, bad_sig, b"test", None)
    assert result.valid is False
    assert result.reason == "malformed-signature", f"Expected malformed-signature, got {result.reason}"

# ----------------------------------------------------------------------
# DEF-GAP-2: Private key sub-range validation
# ----------------------------------------------------------------------
def test_pq_sign_rejects_out_of_range_private_key():
    env = CryptoEnvelope(mode="pq")
    key = env.generate_key()
    bad_key = replace(key, private=b"\xff" * 4032)  # out of range coefficients
    with pytest.raises(KeyMismatchError):
        env.sign(bad_key, b"test", None)