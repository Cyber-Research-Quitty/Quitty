import base64
import hashlib
import json
import time
from typing import Any, Optional
from urllib.parse import quote

import httpx

from .config import (
    JWKS_BASE_URL,
    JWKS_CACHE_TTL_SECONDS,
    JWKS_PATHS,
    JWKS_PROOF_PATHS,
    JWKS_REQUIRE_PROOF,
    JWKS_TIMEOUT_SECONDS,
)


class JWKSFetchError(Exception):
    """Raised when JWKS cannot be fetched from P2."""
    pass


PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _public_jwk(jwk: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in jwk.items() if k not in PRIVATE_JWK_FIELDS}


def _leaf_hash(jwk: dict[str, Any]) -> bytes:
    return _sha256(b"\x00" + _canonical_json(_public_jwk(jwk)))


def _parent_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + left + right)


def _verify_merkle_proof(jwk: dict[str, Any], proof: list[dict[str, Any]], expected_root_b64: str) -> bool:
    current = _leaf_hash(jwk)
    for item in proof:
        if not isinstance(item, dict):
            return False
        position = item.get("position")
        sibling_b64 = item.get("hash")
        if not isinstance(position, str) or not isinstance(sibling_b64, str):
            return False
        try:
            sibling = _b64url_decode(sibling_b64)
        except Exception:
            return False

        if position == "left":
            current = _parent_hash(sibling, current)
        elif position == "right":
            current = _parent_hash(current, sibling)
        else:
            return False
    return _b64url_encode(current) == expected_root_b64


def _normalize_proof_path(path_template: str, kid: str) -> str:
    if "{kid}" in path_template:
        return path_template.replace("{kid}", quote(kid, safe=""))
    if path_template.endswith("/"):
        return path_template + quote(kid, safe="")
    return path_template + "/" + quote(kid, safe="")


class JWKSClient:
    def __init__(self) -> None:
        self._cache_by_kid: dict[str, tuple[dict[str, Any], float]] = {}
        self._cache_keys: Optional[list[dict]] = None
        self._cache_expires_at: float = 0.0

        self._client = httpx.AsyncClient(
            timeout=JWKS_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )

    def _extract_and_verify_jwk_from_proof_response(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("proof response is not an object")

        jwk = payload.get("jwk")
        proof = payload.get("merkle_proof")
        root = payload.get("root")

        if not isinstance(jwk, dict):
            raise ValueError("proof response missing jwk object")
        if not isinstance(proof, list):
            raise ValueError("proof response missing merkle_proof list")
        if not isinstance(root, dict):
            raise ValueError("proof response missing root object")

        root_hash = root.get("root_hash")
        if not isinstance(root_hash, str) or not root_hash:
            raise ValueError("proof response missing root.root_hash")

        # Require signed-root metadata presence even if signature verification
        # is performed elsewhere in the current guard flow.
        for field in ("sig_alg", "sig_kid", "signature"):
            if not isinstance(root.get(field), str) or not root.get(field):
                raise ValueError(f"proof response missing root.{field}")

        typed_proof: list[dict[str, Any]] = [item for item in proof if isinstance(item, dict)]
        if len(typed_proof) != len(proof):
            raise ValueError("proof response contains invalid proof item")

        if not _verify_merkle_proof(jwk, typed_proof, expected_root_b64=root_hash):
            raise ValueError("invalid merkle proof")

        return jwk

    async def _fetch_key_proof_by_kid(self, kid: str) -> Optional[dict]:
        if not JWKS_PROOF_PATHS:
            raise JWKSFetchError("JWKS_PROOF_PATHS is empty; proof-based key lookup is not configured")

        last_error: Optional[Exception] = None

        for path_template in JWKS_PROOF_PATHS:
            path = _normalize_proof_path(path_template, kid)
            url = JWKS_BASE_URL.rstrip("/") + path
            try:
                resp = await self._client.get(url)
                if resp.status_code == 404:
                    continue
                if resp.status_code != 200:
                    last_error = RuntimeError(f"JWKS proof HTTP {resp.status_code} from {url}")
                    continue

                data = resp.json()
                return self._extract_and_verify_jwk_from_proof_response(data)

            except Exception as exc:
                last_error = exc
                continue

        if last_error:
            raise JWKSFetchError(
                f"Could not fetch/verify proof for kid={kid} from {JWKS_BASE_URL} "
                f"using paths={JWKS_PROOF_PATHS}. Last error: {last_error}"
            )
        return None

    async def _fetch_jwks_keys(self) -> list[dict]:
        # Legacy fallback only.
        last_error: Optional[Exception] = None

        for path in JWKS_PATHS:
            url = JWKS_BASE_URL.rstrip("/") + path
            try:
                resp = await self._client.get(url)
                if resp.status_code != 200:
                    last_error = RuntimeError(f"JWKS HTTP {resp.status_code} from {url}")
                    continue

                data = resp.json()
                keys = data.get("keys")

                if not isinstance(keys, list):
                    last_error = RuntimeError(f"JWKS missing 'keys' list at {url}")
                    continue

                return keys

            except Exception as exc:
                last_error = exc
                continue

        raise JWKSFetchError(
            f"Could not fetch JWKS from {JWKS_BASE_URL} using paths={JWKS_PATHS}. Last error: {last_error}"
        )

    async def _legacy_get_key_by_kid(self, kid: str, *, force_refresh: bool) -> Optional[dict]:
        now = time.time()
        if force_refresh or self._cache_keys is None or now >= self._cache_expires_at:
            self._cache_keys = await self._fetch_jwks_keys()
            self._cache_expires_at = now + JWKS_CACHE_TTL_SECONDS

        for key in self._cache_keys:
            if isinstance(key, dict) and key.get("kid") == kid:
                return key
        return None

    async def get_key_by_kid(self, kid: str) -> Optional[dict]:
        now = time.time()

        cached = self._cache_by_kid.get(kid)
        if cached and now < cached[1]:
            return cached[0]

        proof_error: Optional[JWKSFetchError] = None
        try:
            proof_key = await self._fetch_key_proof_by_kid(kid)
        except JWKSFetchError as exc:
            proof_error = exc
            proof_key = None

        if proof_key is not None:
            self._cache_by_kid[kid] = (proof_key, now + JWKS_CACHE_TTL_SECONDS)
            return proof_key

        if JWKS_REQUIRE_PROOF:
            if proof_error:
                raise proof_error
            return None

        # Compatibility mode: allow legacy list endpoint fallback.
        legacy_key = await self._legacy_get_key_by_kid(kid, force_refresh=False)
        if legacy_key is not None:
            self._cache_by_kid[kid] = (legacy_key, now + JWKS_CACHE_TTL_SECONDS)
            return legacy_key

        return None

    async def refresh_and_get_key_by_kid(self, kid: str) -> Optional[dict]:
        """
        Force refresh for cache-race cases after key rotation.
        """
        self._cache_by_kid.pop(kid, None)
        now = time.time()

        proof_error: Optional[JWKSFetchError] = None
        try:
            proof_key = await self._fetch_key_proof_by_kid(kid)
        except JWKSFetchError as exc:
            proof_error = exc
            proof_key = None

        if proof_key is not None:
            self._cache_by_kid[kid] = (proof_key, now + JWKS_CACHE_TTL_SECONDS)
            return proof_key

        if JWKS_REQUIRE_PROOF:
            if proof_error:
                raise proof_error
            return None

        legacy_key = await self._legacy_get_key_by_kid(kid, force_refresh=True)
        if legacy_key is not None:
            self._cache_by_kid[kid] = (legacy_key, now + JWKS_CACHE_TTL_SECONDS)
            return legacy_key
        return None


jwks_client = JWKSClient()
