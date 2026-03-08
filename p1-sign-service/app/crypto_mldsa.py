from __future__ import annotations

from .crypto_backend import CryptoBackend, KeyPair, AlgName, derive_kid
from pqcrypto.sign import ml_dsa_44


class MLDSABackend(CryptoBackend):
    SUPPORTED: set[AlgName] = {"ml-dsa-44"}

    def _mod(self, alg: AlgName):
        if alg == "ml-dsa-44":
            return ml_dsa_44
        raise ValueError(f"Unsupported alg for MLDSABackend: {alg}")

    def generate_keypair(self, alg: AlgName) -> KeyPair:
        if alg not in self.SUPPORTED:
            raise ValueError(f"MLDSABackend only supports {self.SUPPORTED}, got {alg}")

        mod = self._mod(alg)

        # pqcrypto typically returns (public_key, secret_key)
        a, b = mod.generate_keypair()

        # Ensure which one is secret by attempting sign with CORRECT order
        msg = b"p1-selftest"

        # correct: sign(secret_key, message)
        try:
            _ = mod.sign(b, msg)
            pub, sec = a, b
        except Exception:
            # maybe reversed in this build
            _ = mod.sign(a, msg)
            pub, sec = b, a

        kid = derive_kid(pub)
        return KeyPair(alg=alg, kid=kid, public_key=pub, private_key=sec)

    def sign(self, alg: AlgName, private_key: bytes, data: bytes) -> bytes:
        mod = self._mod(alg)

        # IMPORTANT: pqcrypto ML-DSA uses sign(secret_key, message)
        return mod.sign(private_key, data)

    def verify(self, alg: AlgName, public_key: bytes, data: bytes, signature: bytes) -> bool:
        mod = self._mod(alg)
        try:
            # Common pqcrypto order: verify(public_key, message, signature)
            return bool(mod.verify(public_key, data, signature))
        except Exception:
            # Some builds differ; try fallback:
            try:
                return bool(mod.verify(data, signature, public_key))
            except Exception:
                return False
