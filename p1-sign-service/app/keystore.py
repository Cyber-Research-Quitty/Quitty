from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from .config import settings
from .crypto_backend import KeyPair, AlgName
from .crypto_ed25519 import Ed25519Backend


class JsonKeyStore:
    """
    Very simple JSON file-based keystore for P1.

    For now:
      - Stores private + public keys in a local JSON file.
      - On first use, generates one Ed25519 keypair and reuses it.
      - Later we can extend this for multiple keys, rotation, Dilithium, etc.
    """

    def __init__(self, path: str | Path, default_alg: AlgName = "ed25519-dev"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self._default_alg: AlgName = default_alg
        self._backend = Ed25519Backend()
        self._cache: Dict[str, KeyPair] = {}

        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return

        data = json.loads(self.path.read_text())
        for kid, record in data.items():
            kp = KeyPair(
                alg=record["alg"],
                kid=record["kid"],
                public_key=bytes.fromhex(record["public_key"]),
                private_key=bytes.fromhex(record["private_key"]),
            )
            self._cache[kid] = kp

    def _flush(self) -> None:
        data = {
            kid: {
                "alg": kp.alg,
                "kid": kp.kid,
                "public_key": kp.public_key.hex(),
                "private_key": kp.private_key.hex(),
            }
            for kid, kp in self._cache.items()
        }
        self.path.write_text(json.dumps(data, indent=2))

    def get(self, kid: str) -> KeyPair | None:
        return self._cache.get(kid)

    def put(self, kp: KeyPair) -> None:
        self._cache[kp.kid] = kp
        self._flush()

    def get_active_key(self) -> KeyPair:
        """
        For v0: just return the first key if it exists, otherwise generate one.
        Later we can add real 'active' key logic + rotation.
        """
        if self._cache:
            # return first key in dict
            return next(iter(self._cache.values()))

        kp = self._backend.generate_keypair(self._default_alg)
        self.put(kp)
        return kp


# Single global keystore instance used by the P1 service
keystore = JsonKeyStore(settings.keystore_path)
