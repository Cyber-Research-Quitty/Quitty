from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from .crypto_backend import KeyPair, AlgName
from .backend_factory import get_backend
from .config import settings


SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class KeyStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _default_data(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "updatedAt": _now_iso(),
            "active": {},
            "keys": {},
        }

    def _load(self) -> dict[str, Any]:
        # If file doesn't exist -> create empty schema v1 structure (not writing yet)
        if not self.path.exists():
            return self._default_data()

        with self.path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # Backward compatibility: very old format where entire JSON is keys map
        if "keys" not in data:
            data = {"active": {}, "keys": data}

        # Ensure active exists
        if "active" not in data or not isinstance(data["active"], dict):
            data["active"] = {}

        # ---- schema versioning / migration ----
        if "schema_version" not in data:
            # v0 -> v1 migration (non-breaking)
            data["schema_version"] = SCHEMA_VERSION
            data["updatedAt"] = _now_iso()
            self._apply_status_fields(data)
            self._save(data)  # persist migration immediately
        else:
            if data["schema_version"] != SCHEMA_VERSION:
                raise ValueError(f"Unsupported keystore schema_version: {data['schema_version']}")

            if "updatedAt" not in data:
                data["updatedAt"] = _now_iso()

            self._apply_status_fields(data)

        # self-heal: if active[alg] points to missing key, remove pointer
        keys = data.get("keys", {})
        active = data.get("active", {})
        changed = False
        for alg, kid in list(active.items()):
            if kid not in keys:
                active.pop(alg, None)
                changed = True
        if changed:
            data["updatedAt"] = _now_iso()
            self._save(data)

        return data

    def _save(self, data: dict[str, Any]) -> None:
        data["updatedAt"] = _now_iso()

        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.replace(self.path)

    def _apply_status_fields(self, data: dict[str, Any]) -> None:
        """
        Add record status ("active"/"inactive") based on the active pointer.
        This does NOT change your signing/verifying logic, only improves clarity/stability.
        """
        keys = data.get("keys", {})
        active = data.get("active", {})

        # Set all to inactive first
        for _, rec in keys.items():
            if isinstance(rec, dict):
                rec["status"] = "inactive"

        # Mark active ones
        for _, active_kid in active.items():
            rec = keys.get(active_kid)
            if isinstance(rec, dict):
                rec["status"] = "active"

    def _kp_to_record(self, kp: KeyPair, status: str = "inactive") -> dict[str, Any]:
        return {
            "alg": kp.alg,
            "kid": kp.kid,
            "public_key": kp.public_key.hex(),
            "private_key": kp.private_key.hex(),
            "createdAt": _now_iso(),
            "status": status,
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
        keys = data["keys"]
        active = data["active"]

        active_kid = active.get(alg)
        if active_kid:
            kp = self.get(active_kid)
            if kp and kp.alg == alg:
                return kp

        # If no active key (or broken pointer), generate one and set active
        backend = get_backend(alg)
        kp = backend.generate_keypair(alg)

        # mark old active inactive (if any, just in case)
        prev_active = active.get(alg)
        if prev_active and prev_active in keys:
            keys[prev_active]["status"] = "inactive"

        keys[kp.kid] = self._kp_to_record(kp, status="active")
        active[alg] = kp.kid
        self._save(data)

        return kp

    def rotate(self, alg: AlgName) -> KeyPair:
        """
        Generate a new keypair for alg and switch active pointer.
        Old keys remain stored so verification of older tokens still works.
        """
        data = self._load()
        keys = data["keys"]
        active = data["active"]

        backend = get_backend(alg)
        kp = backend.generate_keypair(alg)

        # mark previous active as inactive
        prev_active = active.get(alg)
        if prev_active and prev_active in keys:
            keys[prev_active]["status"] = "inactive"

        keys[kp.kid] = self._kp_to_record(kp, status="active")
        active[alg] = kp.kid
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
                    "public_key_b64u": _b64url(pub),
                    "public_key_len": len(pub),
                    "createdAt": rec.get("createdAt"),
                    "status": rec.get("status"),
                    "is_active": active.get(rec["alg"]) == kid,
                }
            )

        return {
            "schema_version": data.get("schema_version"),
            "updatedAt": data.get("updatedAt"),
            "active": active,
            "keys": out,
        }

    def jwks(self, alg: AlgName | None = None, include_all: bool = False) -> dict[str, Any]:
        """
        JWKS-like output for integration.
        - include_all=False by default: returns only active keys
        - PQC keys use custom fields (kty="PQC", pk is public key base64url)
        """
        data = self._load()
        active = data.get("active", {})
        keys = data.get("keys", {})

        if include_all:
            items = keys.items()
        else:
            active_kids = set(active.values())
            items = ((kid, rec) for kid, rec in keys.items() if kid in active_kids)

        jwk_list = []
        for kid, rec in items:
            if alg is not None and rec.get("alg") != alg:
                continue

            pub = bytes.fromhex(rec["public_key"])

            if rec["alg"] != "ml-dsa-44":
                # Strict PQ-only mode: ignore legacy/non-ML-DSA keys in JWKS output.
                continue

            jwk = {
                "kty": "PQC",
                "use": "sig",
                "kid": kid,
                "alg": rec["alg"],
                "pk": _b64url(pub),
                "key_len": len(pub),
                "status": rec.get("status"),
            }

            jwk_list.append(jwk)

        return {
            "schema_version": data.get("schema_version"),
            "updatedAt": data.get("updatedAt"),
            "keys": jwk_list,
        }


keystore = KeyStore(Path(settings.keystore_path))
