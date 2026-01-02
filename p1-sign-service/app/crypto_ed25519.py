from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .crypto_backend import CryptoBackend, KeyPair, AlgName, derive_kid


class Ed25519Backend(CryptoBackend):
    """
    Development-only crypto backend using Ed25519.

    This lets us build and test the P1 service end-to-end before
    plugging in the real Dilithium (ml-dsa-44 / ml-dsa-65) backend.
    """

    SUPPORTED: set[AlgName] = {"ed25519-dev"}

    def generate_keypair(self, alg: AlgName) -> KeyPair:
        if alg not in self.SUPPORTED:
            raise ValueError(f"Ed25519Backend only supports: {self.SUPPORTED}, got {alg}")

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()

        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        kid = derive_kid(pub_bytes)

        return KeyPair(
            alg=alg,
            kid=kid,
            public_key=pub_bytes,
            private_key=priv_bytes,
        )

    def sign(self, alg: AlgName, private_key: bytes, data: bytes) -> bytes:
        if alg not in self.SUPPORTED:
            raise ValueError(f"Unsupported alg for Ed25519Backend: {alg}")

        priv = Ed25519PrivateKey.from_private_bytes(private_key)
        return priv.sign(data)

    def verify(self, alg: AlgName, public_key: bytes, data: bytes, signature: bytes) -> bool:
        if alg not in self.SUPPORTED:
            raise ValueError(f"Unsupported alg for Ed25519Backend: {alg}")

        pub = Ed25519PublicKey.from_public_bytes(public_key)
        try:
            pub.verify(signature, data)
            return True
        except Exception:
            return False
