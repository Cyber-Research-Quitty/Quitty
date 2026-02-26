from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal
import hashlib
import base64

AlgName = Literal["ml-dsa-44", "ml-dsa-65", "ed25519-dev"]


@dataclass
class KeyPair:
    alg: AlgName
    kid: str
    public_key: bytes
    private_key: bytes


class CryptoBackend(ABC):
    @abstractmethod
    def generate_keypair(self, alg: AlgName) -> KeyPair:
        raise NotImplementedError

    @abstractmethod
    def sign(self, alg: AlgName, private_key: bytes, data: bytes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def verify(self, alg: AlgName, public_key: bytes, data: bytes, signature: bytes) -> bool:
        raise NotImplementedError


def derive_kid(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).digest()
    first_16 = digest[:16]
    return base64.urlsafe_b64encode(first_16).rstrip(b"=").decode("ascii")
