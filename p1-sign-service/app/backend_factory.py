from __future__ import annotations

from .crypto_backend import AlgName, CryptoBackend
from .crypto_mldsa import MLDSABackend


def get_backend(alg: AlgName) -> CryptoBackend:
    if alg == "ml-dsa-44":
        return MLDSABackend()

    raise NotImplementedError(f"Unsupported alg: {alg}")
