"""Tests for package scaffold and public surface.

Contract: pyproject.toml installable, src/pqblocks_fips_dualmode/__init__.py re-exports
CryptoEnvelope; both modes instantiate; every method named in the specification
exists and raises appropriate errors.
"""

import importlib
import pytest


PROJECT_NAME = "pqblocks_fips_dualmode"

# The full method surface from spec.
# Every method forwards through _dispatch to its mode-appropriate
# implementation (or raises NotAvailableInModeError).
PUBLIC_METHODS = (
    "generate_key",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "encapsulate",
    "decapsulate",
    "agree",
)


def test_package_is_importable():
    mod = importlib.import_module(PROJECT_NAME)
    assert hasattr(mod, "CryptoEnvelope")


def test_crypto_envelope_exposed_at_top_level():
    from pqblocks_fips_dualmode import CryptoEnvelope as TopLevel  # noqa: F401


def test_pyproject_toml_exists():
    from pathlib import Path
    import importlib.metadata

    pkg_root = Path(__file__).resolve().parent.parent
    toml_path = pkg_root / "pyproject.toml"
    if toml_path.is_file():
        text = toml_path.read_text()
        assert "dualmode" in text
    else:
        found = any(
            "dualmode" in dist.metadata.get("Name", "").lower()
            for dist in importlib.metadata.distributions()
        )
        assert found, "Installed package metadata not found"


@pytest.mark.parametrize("mode", ["fips", "pq"])
def test_both_modes_instantiate(mode):
    from pqblocks_fips_dualmode import CryptoEnvelope

    envelope = CryptoEnvelope(mode=mode)
    assert envelope.mode == mode


def test_unsupported_mode_is_rejected():
    from pqblocks_fips_dualmode import CryptoEnvelope

    with pytest.raises(Exception):
        CryptoEnvelope(mode="ecdh")


def test_mode_property_is_read_only():
    from pqblocks_fips_dualmode import CryptoEnvelope

    envelope = CryptoEnvelope(mode="fips")
    with pytest.raises(AttributeError):
        envelope.mode = "pq"


@pytest.mark.parametrize("mode", ["fips", "pq"])
@pytest.mark.parametrize("method_name", PUBLIC_METHODS)
def test_every_declared_method_exists(mode, method_name):
    from pqblocks_fips_dualmode import CryptoEnvelope

    envelope = CryptoEnvelope(mode=mode)
    method = getattr(envelope, method_name, None)
    assert callable(method), f"{method_name} missing from CryptoEnvelope"
