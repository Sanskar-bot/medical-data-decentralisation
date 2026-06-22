# test_crypto.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.crypto_utils import generate_rsa_keypair, serialize_private_key, serialize_public_key, aes_gcm_encrypt, rsa_encrypt, rsa_decrypt, aes_gcm_decrypt

# Generate keys
priv, pub = generate_rsa_keypair()
priv_pem = serialize_private_key(priv)
pub_pem = serialize_public_key(pub)

print("Private Key PEM:\n", priv_pem[:100], "...")
print("Public Key PEM:\n", pub_pem[:100], "...")

# AES encrypt some data
data = b"My secret FHIR record"
key, nonce, ct = aes_gcm_encrypt(data)
print("AES encrypted:", ct[:20], "...")

# RSA encrypt AES key
enc_key = rsa_encrypt(pub, key)
dec_key = rsa_decrypt(priv, enc_key)
print("AES key match:", key == dec_key)

# Decrypt AES
plain = aes_gcm_decrypt(dec_key, nonce, ct)
print("Decrypted:", plain)
