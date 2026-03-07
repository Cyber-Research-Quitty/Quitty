import time
from typing import Optional

import httpx

from .config import JWKS_BASE_URL, JWKS_PATHS, JWKS_CACHE_TTL_SECONDS, JWKS_TIMEOUT_SECONDS


class JWKSFetchError(Exception):
    """Raised when JWKS cannot be fetched from P2."""
    pass


class JWKSClient:
    def __init__(self) -> None:
        self._cache_keys: Optional[list[dict]] = None
        self._cache_expires_at: float = 0.0

        self._client = httpx.AsyncClient(
            timeout=JWKS_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )

    async def _fetch_jwks_keys(self) -> list[dict]:
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

    async def get_key_by_kid(self, kid: str) -> Optional[dict]:
        now = time.time()

        # refresh cache if expired
        if self._cache_keys is None or now >= self._cache_expires_at:
            self._cache_keys = await self._fetch_jwks_keys()
            self._cache_expires_at = now + JWKS_CACHE_TTL_SECONDS

        # find key by kid
        for key in self._cache_keys:
            if isinstance(key, dict) and key.get("kid") == kid:
                return key

        return None


jwks_client = JWKSClient()
