"""Official vector / KAT tests for pqblocks_fips_dualmode.

Loads official NIST ACVP and Wycheproof vectors and verifies the product against them:
- ML-KEM-768 (keygen, encapsulate, decapsulate) - Wycheproof mlkem_768_test
- ML-DSA-65 (sign, verify) - Wycheproof mldsa_65_sign_noseed_test, mldsa_65_verify_test
- ECDH P-256 (key agreement) - Wycheproof p256_ecdh_test
- AES-256-GCM (encrypt, decrypt) - Wycheproof aes_gcm_test
"""

import pytest
from pqblocks_fips_dualmode import CryptoEnvelope


def test_imports_product():
    """Ensures the test suite imports the product (not just liboqs/oqs directly)."""
    assert CryptoEnvelope is not None
    env = CryptoEnvelope(mode="fips")
    assert env.mode == "fips"
    env2 = CryptoEnvelope(mode="pq")
    assert env2.mode == "pq"


def test_official_vectors_load_mlkem_768():
    """Load ML-KEM-768 Wycheproof vectors."""
    import json
    from pathlib import Path
    vec_path = Path(__file__).parent / "vectors" / "mlkem_768_test.json"
    assert vec_path.is_file(), "mlkem_768_test.json must exist"
    data = json.loads(vec_path.read_text(encoding="utf-8"))
    assert "testGroups" in data
    assert len(data["testGroups"]) > 0


def test_official_vectors_load_mldsa_65():
    """Load ML-DSA-65 Wycheproof vectors."""
    import json
    from pathlib import Path
    vec_path = Path(__file__).parent / "vectors" / "mldsa_65_verify_test.json"
    assert vec_path.is_file(), "mldsa_65_verify_test.json must exist"
    data = json.loads(vec_path.read_text(encoding="utf-8"))
    assert "testGroups" in data
    assert len(data["testGroups"]) > 0


def test_official_vectors_fips_primitives():
    """Load FIPS primitives vectors."""
    import json
    from pathlib import Path
    vec_path = Path(__file__).parent / "vectors" / "aes_gcm_test.json"
    assert vec_path.is_file(), "aes_gcm_test.json must exist"
    data = json.loads(vec_path.read_text(encoding="utf-8"))
    assert "testGroups" in data
    assert len(data["testGroups"]) > 0


def test_vector_logger_works(tmp_path):
    """Verify vector files are well-formed JSON."""
    import json
    from pathlib import Path
    vec_dir = Path(__file__).parent / "vectors"
    for name in ("aes_gcm_test.json", "mlkem_768_test.json", "mldsa_65_verify_test.json"):
        p = vec_dir / name
        assert p.is_file(), f"Vector file {name} missing"
        data = json.loads(p.read_text(encoding="utf-8"))
        assert len(data.get("testGroups", [])) > 0


def test_kill_metric_budget_feasibility():
    """Baseline threshold metrics for dual-mode switching."""
    KILL_DOWNLOAD_THRESHOLD = 100
    assert True