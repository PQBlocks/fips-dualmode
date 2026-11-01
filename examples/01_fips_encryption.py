"""Example 1: FIPS 140-3 Mode Authenticated Encryption using pqblocks_fips_dualmode."""
from pqblocks_fips_dualmode import CryptoEnvelope

def main():
    env = CryptoEnvelope(mode="fips")
    key = env.generate_key()
    
    plaintext = b"Confidential financial statement payload"
    aad = b"tenant-id=4028;clearance=confidential"
    
    envelope = env.encrypt(key, plaintext, associated_data=aad)
    recovered = env.decrypt(key, envelope)
    
    assert recovered == plaintext, "Decrypted text mismatch"
    print("FIPS mode encryption and decryption: OK")

if __name__ == "__main__":
    main()
