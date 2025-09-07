# signing.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_keypair(algo: str):
    """Generates a private key based on the specified algorithm."""
    if algo == "RSA":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    elif algo == "ECDSA":
        return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    elif algo == "Ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError("Unsupported algorithm")

def load_private_key(key_path: str, password: bytes):
    """Loads a private key from a PEM file with password protection."""
    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password
        )
    return private_key

def sign_digest(private_key, algo: str, digest: bytes, hash_algo: str = "sha3_256") -> bytes:
    """Signs a digest using the provided private key and algorithm."""
    hash_class = hashes.SHA3_256 if hash_algo == "sha3_256" else hashes.SHA3_512
    if algo == "RSA":
        return private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hash_class()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_class()
        )
    elif algo == "ECDSA":
        return private_key.sign(digest, ec.ECDSA(hash_class()))
    elif algo == "Ed25519":
        return private_key.sign(digest)
    raise ValueError("Unsupported algorithm")

def verify_signature(public_key, algo: str, digest: bytes, signature: bytes, hash_algo: str = "sha3_256") -> bool:
    """Verifies a signature against a digest using the public key."""
    hash_class = hashes.SHA3_256 if hash_algo == "sha3_256" else hashes.SHA3_512
    try:
        if algo == "RSA":
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hash_class()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_class()
            )
        elif algo == "ECDSA":
            public_key.verify(signature, digest, ec.ECDSA(hash_class()))
        elif algo == "Ed25519":
            public_key.verify(signature, digest)
        return True
    except Exception:
        return False
