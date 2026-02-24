# common/crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode

# ---------- AES-GCM (data encryption) ----------
def generate_aes_key() -> bytes:
    """Return a 32-byte AES key (AES-256)."""
    return os.urandom(32)

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> dict:
    """
    Encrypt plaintext with AES-GCM.
    Returns dict with base64-encoded nonce, ciphertext, tag will be part of AESGCM output.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit recommended
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return {
        "nonce": b64encode(nonce).decode(),
        "ciphertext": b64encode(ct).decode()  # ct contains ciphertext||tag in AESGCM implementation
    }

def aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str, aad: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = b64decode(nonce_b64)
    ct = b64decode(ct_b64)
    return aesgcm.decrypt(nonce, ct, aad)

# ---------- RSA keys and key-wrapping ----------
def generate_rsa_keypair(key_size: int = 2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    return priv, pub

def rsa_serialize_private(priv, password: bytes = None) -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )

def rsa_serialize_public(pub) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def rsa_load_private(pem_bytes: bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)

def rsa_load_public(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

def rsa_wrap_key(pub, key_bytes: bytes) -> str:
    """
    Wrap (encrypt) a symmetric key with recipient's RSA public key using OAEP.
    Returns base64 string of ciphertext.
    """
    ct = pub.encrypt(
        key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        )
    )
    return b64encode(ct).decode()

def rsa_unwrap_key(priv, ct_b64: str) -> bytes:
    ct = b64decode(ct_b64)
    return priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        )
    )

# ---------- Sign / verify (RSA-PSS with SHA256) ----------
def rsa_sign(priv, data: bytes) -> str:
    sig = priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return b64encode(sig).decode()

def rsa_verify(pub, data: bytes, sig_b64: str) -> bool:
    sig = b64decode(sig_b64)
    try:
        pub.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------- Password-based wrapping for local storage ----------
def derive_kek_from_password(password: str, salt: bytes = None, iterations: int = 200_000):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    )
    kek = kdf.derive(password.encode())
    return kek, salt

def wrap_key_with_kek(kek: bytes, key_to_wrap: bytes) -> str:
    # Use AESGCM with random nonce to encrypt the key_to_wrap (return base64)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, key_to_wrap, None)
    return b64encode(nonce + ct).decode()

def unwrap_key_with_kek(kek: bytes, wrapped_b64: str) -> bytes:
    raw = b64decode(wrapped_b64)
    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ct, None)
