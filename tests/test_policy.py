"""Tests for policy constants and mode operations."""

import pytest
from pqblocks_fips_dualmode import _policy as policy
from pqblocks_fips_dualmode.errors import DualModeError


def test_policy_sizes_fips203():
    """Verify PQ_KEM_ENCAP_KEY_LEN == 1184 (FIPS 203 Table 3)."""
    assert policy.PQ_KEM_PUBLIC_KEY_LEN == 1184
    assert policy.PQ_KEM_PRIVATE_KEY_LEN == 2400
    assert policy.PQ_KEM_CIPHERTEXT_LEN == 1088
    assert policy.PQ_KEM_SHARED_SECRET_LEN == 32


def test_policy_sizes_fips204():
    """Verify PQ_SIG_PRIVKEY_LEN == 4032 (FIPS 204 Table 2)."""
    assert policy.PQ_SIG_PRIVATE_KEY_LEN == 4032
    assert policy.PQ_SIG_PUBLIC_KEY_LEN == 1952
    assert policy.PQ_SIG_SIGNATURE_LEN == 3309


def test_fips_sizes():
    """Verify FIPS 140-3 AES-GCM and ECDH P-256 sizes."""
    assert policy.FIPS_AES_GCM_KEY_LEN == 32
    assert policy.FIPS_AES_GCM_NONCE_LEN == 12
    assert policy.FIPS_AES_GCM_TAG_LEN == 16
    assert policy.FIPS_EC_P256_PRIVATE_KEY_LEN == 32
    assert policy.FIPS_EC_P256_PUBLIC_KEY_LEN == 32


def test_mode_operations():
    """Verify mode-operation mapping."""
    fips_ops = policy.operations_for_mode("fips")
    pq_ops = policy.operations_for_mode("pq")
    assert "generate_key" in fips_ops
    assert "encrypt" in fips_ops
    assert "decrypt" in fips_ops
    assert "agree" in fips_ops
    assert "sign" not in fips_ops
    assert "encapsulate" not in fips_ops

    assert "generate_key" in pq_ops
    assert "sign" in pq_ops
    assert "verify" in pq_ops
    assert "encapsulate" in pq_ops
    assert "decapsulate" in pq_ops


def test_mode_available():
    """Verify is_available helper."""
    assert policy.is_available("fips", "encrypt")
    assert not policy.is_available("fips", "sign")
    assert policy.is_available("pq", "sign")
    assert policy.is_available("pq", "encapsulate")
    assert not policy.is_available("pq", "agree")


def test_key_id_length():
    """Key ID hex length must be 16."""
    assert policy.KEY_ID_HEX_LEN == 16


def test_context_limit():
    """ML-DSA context max is 255 bytes."""
    assert policy.PQ_SIG_MAX_CONTEXT_LEN == 255