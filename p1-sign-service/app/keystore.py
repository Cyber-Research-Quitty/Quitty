from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from .crypto_backend import KeyPair, AlgName
from .backend_factory import get_backend
from .config import settings


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class KeyStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"active": {}, "keys": {}}

        with self.path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # Backward compatibility old format
        if "keys" not in data:
            return {"active": {}, "keys": data}

        if "active" not in data:
            data["active"] = {}

        return data

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.replace(self.path)

    def _kp_to_record(self, kp: KeyPair) -> dict[str, Any]:
        return {
            "alg": kp.alg,
            "kid": kp.kid,
            "public_key": kp.public_key.hex(),
            "private_key": kp.private_key.hex(),
            "createdAt": _now_iso(),
        }

    def _record_to_kp(self, rec: dict[str, Any]) -> KeyPair:
        return KeyPair(
            alg=rec["alg"],
            kid=rec["kid"],
            public_key=bytes.fromhex(rec["public_key"]),
            private_key=bytes.fromhex(rec["private_key"]),
        )

    def get(self, kid: str) -> KeyPair | None:
        data = self._load()
        rec = data["keys"].get(kid)
        if not rec:
            return None
        return self._record_to_kp(rec)

    def get_active_kid(self, alg: AlgName) -> str | None:
        data = self._load()
        return data.get("active", {}).get(alg)

    def get_active_key(self, alg: AlgName) -> KeyPair:
        data = self._load()

        active_kid = data["active"].get(alg)
        if active_kid:
            kp = self.get(active_kid)
            if kp and kp.alg == alg:
                return kp

        backend = get_backend(alg)
        kp = backend.generate_keypair(alg)

        data["keys"][kp.kid] = self._kp_to_record(kp)
        data["active"][alg] = kp.kid
        self._save(data)

        return kp

    def rotate(self, alg: AlgName) -> KeyPair:
        """
        Generate a new keypair for alg and switch active pointer.
        Old keys remain stored so verification of older tokens still works.
        """
        data = self._load()

        backend = get_backend(alg)
        kp = backend.generate_keypair(alg)

        data["keys"][kp.kid] = self._kp_to_record(kp)
        data["active"][alg] = kp.kid
        self._save(data)

        return kp

    def list_public(self, alg: AlgName | None = None, include_all: bool = True) -> dict[str, Any]:
        """
        Export public-only view for P2 / debugging. Never returns private keys.
        """
        data = self._load()
        active = data.get("active", {})
        keys = data.get("keys", {})

        if include_all:
            items = keys.items()
        else:
            active_kids = set(active.values())
            items = ((kid, rec) for kid, rec in keys.items() if kid in active_kids)

        out = []
        for kid, rec in items:
            if alg is not None and rec.get("alg") != alg:
                continue
            pub = bytes.fromhex(rec["public_key"])
            out.append(
                {
                    "kid": kid,
                    "alg": rec["alg"],
                    "public_key_hex": rec["public_key"],
                    "public_key_len": len(pub),
                    "createdAt": rec.get("createdAt"),
                    "is_active": active.get(rec["alg"]) == kid,
                }
            )

        return {"active": active, "keys": out}


keystore = KeyStore(Path(settings.keystore_path))
