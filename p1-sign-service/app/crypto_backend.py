from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal
import hashlib
import base64

# We support these algorithm names in the service
AlgName = Literal["ml-dsa-44", "ml-dsa-65", "ed25519-dev"]


@dataclass
class KeyPair:
    """
    Generic key pair representation for our service.
    """
    alg: AlgName
    kid: str
    public_key: bytes
    private_key: bytes


class CryptoBackend(ABC):
    """
    Abstract base class for any signing backend (Ed25519 dev, Dilithium, etc.).
    """

    @abstractmethod
    def generate_keypair(self, alg: AlgName) -> KeyPair:
        """
        Generate a new keypair for the given algorithm.
        """
        raise NotImplementedError

    @abstractmethod
    def sign(self, alg: AlgName, private_key: bytes, data: bytes) -> bytes:
        """
        Sign the given data using the private key.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, alg: AlgName, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """
        Verify the signature for the given data and public key.
        """
        raise NotImplementedError


def derive_kid(public_key: bytes) -> str:
    """
    Deterministic kid = base64url(SHA-256(pub_key)[:16])

    This matches your proposal: kid based on public key, stable across restarts.
    """
    digest = hashlib.sha256(public_key).digest()
    first_16 = digest[:16]
    return base64.urlsafe_b64encode(first_16).rstrip(b"=").decode("ascii")
