"""Example 2: Post-Quantum Mode Signatures using pqblocks_fips_dualmode."""
from pqblocks_fips_dualmode import CryptoEnvelope

def main():
    pq_env = CryptoEnvelope(mode="pq")
    key = pq_env.generate_key()
    
    document = b"Post-quantum authorization manifest"
    context = b"audit-v1"
    
    signature_env = pq_env.sign(key, document, context=context)
    result = pq_env.verify(key, signature_env, document, context=context)
    
    assert result.valid is True, "Signature verification failed"
    print("Post-quantum signature verification: OK")

if __name__ == "__main__":
    main()
