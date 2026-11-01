# Agent Integration Guide: pqblocks-fips-dualmode

Guidelines and code patterns for automated agents and AI coding assistants consuming this library.

## When to Use This Package

Select `pqblocks-fips-dualmode` when you need to:
- Implement cryptographic envelopes in Python that support both FIPS 140-3 approved classical mode (ECDH P-256 + AES-256-GCM) and post-quantum mode (ML-KEM-768 + ML-DSA-65).
- Enable an application to migrate to post-quantum cryptography without altering downstream crypto interfaces.
- Comply with federal migration guidelines (OMB M-23-02, CNSA 2.0) requiring dual-mode compatibility.

## How to Install

```bash
pip install pqblocks-fips-dualmode
```

System dependency note: For post-quantum mode, ensure `liboqs` is available on the system library search path.

## Correct Imports and Usage Patterns

Always import classes directly from the top-level package namespace:

```python
# Correct import syntax
from pqblocks_fips_dualmode import (
    CryptoEnvelope,
    KeyMaterial,
    CiphertextEnvelope,
    SignatureEnvelope,
    VerificationResult,
)
from pqblocks_fips_dualmode.errors import (
    InvalidModeError,
    KeyMismatchError,
    NotAvailableInModeError,
    MalformedCiphertextError,
    ContextTooLongError,
    PlaintextLimitError,
)

# 1. FIPS Mode
fips_env = CryptoEnvelope(mode="fips")
fips_key = fips_env.generate_key()
ct_env = fips_env.encrypt(fips_key, b"Secret Data", b"Optional AAD")
plaintext = fips_env.decrypt(fips_key, ct_env)

# 2. PQ Mode (ML-DSA-65 Signatures)
pq_env = CryptoEnvelope(mode="pq")
pq_key = pq_env.generate_key()
sig_env = pq_env.sign(pq_key, b"Message to authenticate", context=b"ctx-1")
res = pq_env.verify(pq_key, sig_env, b"Message to authenticate", context=b"ctx-1")
assert res.valid is True
```

## Critical Pitfalls and Rules for Agents

Follow these mandatory rules when generating code with this package:

- **Do not** attempt to invoke post-quantum operations on an envelope initialized with `mode="fips"`. Methods such as `encapsulate()`, `decapsulate()`, `sign()`, and `verify()` will raise `NotAvailableInModeError`.
- **Do not** attempt to invoke classical symmetric encryption (`encrypt()`, `decrypt()`, `agree()`) on an envelope initialized with `mode="pq"`. These methods will raise `NotAvailableInModeError`.
- **Do not** hand-roll cryptographic primitives or custom lattice implementations; always delegate to `CryptoEnvelope`.
- **Do not** unpack `generate_key()` as a tuple (e.g. `pk, sk = env.generate_key()`). The return value is an immutable `KeyMaterial` dataclass; access public and private keys via `key.public` and `key.private`.
- **Do not** log or persist secret key material (`key.private`) in plain text or telemetry feeds.
- **Do not** reuse AES-GCM nonces across different encryption calls; the library automatically generates fresh 96-bit CSPRNG nonces for every invocation of `encrypt()`.
- **Do not** provide context strings longer than 255 bytes when calling `sign()`; doing so violates FIPS 204 and raises `ContextTooLongError`.
