from __future__ import annotations

from .crypto_backend import AlgName, CryptoBackend
from .crypto_ed25519 import Ed25519Backend
from .crypto_mldsa import MLDSABackend


def get_backend(alg: AlgName) -> CryptoBackend:
    if alg == "ed25519-dev":
        return Ed25519Backend()

    if alg in ("ml-dsa-44", "ml-dsa-65"):
        return MLDSABackend()

    raise NotImplementedError(f"Unsupported alg: {alg}")
