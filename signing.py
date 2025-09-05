# signing.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.backends import default_backend

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

def sign_digest(private_key, algo: str, digest: bytes) -> bytes:
    """Signs a digest using the provided private key and algorithm."""
    if algo == "RSA":
        return private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA3_256()
        )
    elif algo == "ECDSA":
        return private_key.sign(digest, ec.ECDSA(hashes.SHA3_256()))
    elif algo == "Ed25519":
        return private_key.sign(digest)
    raise ValueError("Unsupported algorithm")

def verify_signature(public_key, algo: str, digest: bytes, signature: bytes) -> bool:
    """Verifies a signature against a digest using the public key."""
    try:
        if algo == "RSA":
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA3_256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA3_256()
            )
        elif algo == "ECDSA":
            public_key.verify(signature, digest, ec.ECDSA(hashes.SHA3_256()))
        elif algo == "Ed25519":
            public_key.verify(signature, digest)
        return True
    except Exception:
        return False