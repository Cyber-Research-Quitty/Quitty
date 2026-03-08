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

    def _normalize_active_map(self, active_raw: dict[str, Any], keys: dict[str, Any]) -> tuple[dict[str, list[str]], bool]:
        """
        Normalize `active` to the multi-active format:
          active[alg] = [kid1, kid2, ...]
        Returns (normalized_map, changed_flag).
        """
        normalized: dict[str, list[str]] = {}
        changed = False

        for alg, value in active_raw.items():
            if isinstance(value, str):
                candidates = [value]
                changed = True
            elif isinstance(value, list):
                candidates = [v for v in value if isinstance(v, str)]
                if len(candidates) != len(value):
                    changed = True
            else:
                candidates = []
                changed = True

            out: list[str] = []
            seen: set[str] = set()
            for kid in candidates:
                if kid in seen:
                    changed = True
                    continue
                if kid not in keys:
                    changed = True
                    continue
                seen.add(kid)
                out.append(kid)

            if out:
                normalized[alg] = out
            elif candidates:
                changed = True

        if normalized != active_raw:
            changed = True
        return normalized, changed

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

        # self-heal + normalize active map to multi-active format
        keys = data.get("keys", {})
        active_raw = data.get("active", {})
        active, changed = self._normalize_active_map(active_raw, keys)
        data["active"] = active
        if changed:
            self._apply_status_fields(data)
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
        Add record status ("active"/"inactive") based on the active key lists.
        This does NOT change your signing/verifying logic, only improves clarity/stability.
        """
        keys = data.get("keys", {})
        active, _ = self._normalize_active_map(data.get("active", {}), keys)
        data["active"] = active

        # Set all to inactive first
        for _, rec in keys.items():
            if isinstance(rec, dict):
                rec["status"] = "inactive"

        # Mark active ones
        for _, active_kids in active.items():
            for active_kid in active_kids:
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

    def get_active_kids(self, alg: AlgName) -> list[str]:
        data = self._load()
        active = data.get("active", {}).get(alg, [])
        if not isinstance(active, list):
            return []
        return list(active)

    def get_active_kid(self, alg: AlgName) -> str | None:
        active_kids = self.get_active_kids(alg)
        if not active_kids:
            return None
        # Latest active key signs new tokens by default.
        return active_kids[-1]

    def get_active_key(self, alg: AlgName) -> KeyPair:
        data = self._load()
        keys = data["keys"]
        active = data["active"]

        active_kids = active.get(alg, [])
        if not isinstance(active_kids, list):
            active_kids = []
            active[alg] = active_kids

        active_kid = active_kids[-1] if active_kids else None
        if active_kid:
            kp = self.get(active_kid)
            if kp and kp.alg == alg:
                return kp

        # If no active key (or broken pointer), generate one and set active
        backend = get_backend(alg)
        kp = backend.generate_keypair(alg)

        keys[kp.kid] = self._kp_to_record(kp, status="active")
        active_kids.append(kp.kid)
        active[alg] = active_kids
        self._apply_status_fields(data)
        self._save(data)

        return kp

    def rotate(self, alg: AlgName) -> KeyPair:
        """
        Generate a new keypair for alg and add it to the active set.
        Older active keys remain active; older inactive keys remain stored.
        """
        data = self._load()
        keys = data["keys"]
        active = data["active"]

        backend = get_backend(alg)
        kp = backend.generate_keypair(alg)

        keys[kp.kid] = self._kp_to_record(kp, status="active")
        active_kids = active.get(alg, [])
        if not isinstance(active_kids, list):
            active_kids = []
        active_kids.append(kp.kid)
        # Deduplicate while preserving order.
        active[alg] = list(dict.fromkeys(active_kids))
        self._apply_status_fields(data)
        self._save(data)

        return kp

    def set_signing_kid(self, alg: AlgName, kid: str) -> KeyPair:
        """
        Select which active key should sign new tokens for alg.
        Implementation detail: selected key is moved to the end of active list.
        """
        data = self._load()
        keys = data.get("keys", {})
        rec = keys.get(kid)
        if not isinstance(rec, dict):
            raise ValueError("kid_not_found")
        if rec.get("alg") != alg:
            raise ValueError("kid_alg_mismatch")

        active = data.setdefault("active", {})
        active_kids = active.get(alg, [])
        if not isinstance(active_kids, list):
            active_kids = []

        if kid not in active_kids:
            raise ValueError("kid_not_active")

        active_kids = [k for k in active_kids if k != kid]
        active_kids.append(kid)
        active[alg] = active_kids
        self._apply_status_fields(data)
        self._save(data)
        return self._record_to_kp(rec)

    def activate_kid(self, alg: AlgName, kid: str, make_signing: bool = True) -> KeyPair:
        """
        Mark an existing key as active for alg.
        If make_signing=True, it becomes default signer (moved to end).
        """
        data = self._load()
        keys = data.get("keys", {})
        rec = keys.get(kid)
        if not isinstance(rec, dict):
            raise ValueError("kid_not_found")
        if rec.get("alg") != alg:
            raise ValueError("kid_alg_mismatch")

        active = data.setdefault("active", {})
        active_kids = active.get(alg, [])
        if not isinstance(active_kids, list):
            active_kids = []

        if kid not in active_kids:
            active_kids.append(kid)
        if make_signing:
            active_kids = [k for k in active_kids if k != kid] + [kid]

        active[alg] = list(dict.fromkeys(active_kids))
        self._apply_status_fields(data)
        self._save(data)
        return self._record_to_kp(rec)

    def deactivate_kid(self, alg: AlgName, kid: str) -> KeyPair:
        """
        Mark an active key inactive for alg.
        Safety: does not allow deactivating the last active key for that alg.
        """
        data = self._load()
        keys = data.get("keys", {})
        rec = keys.get(kid)
        if not isinstance(rec, dict):
            raise ValueError("kid_not_found")
        if rec.get("alg") != alg:
            raise ValueError("kid_alg_mismatch")

        active = data.setdefault("active", {})
        active_kids = active.get(alg, [])
        if not isinstance(active_kids, list):
            active_kids = []

        if kid not in active_kids:
            raise ValueError("kid_not_active")
        if len(active_kids) <= 1:
            raise ValueError("cannot_deactivate_last_active_key")

        active[alg] = [k for k in active_kids if k != kid]
        self._apply_status_fields(data)
        self._save(data)
        return self._record_to_kp(rec)

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
            active_kids = {k for v in active.values() for k in (v if isinstance(v, list) else [])}
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
                    "is_active": kid in set(active.get(rec["alg"], [])),
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
            active_kids = {k for v in active.values() for k in (v if isinstance(v, list) else [])}
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
