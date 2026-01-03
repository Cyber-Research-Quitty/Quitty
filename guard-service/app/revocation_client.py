from typing import Any, Dict, Optional

import httpx

from .config import (
    REVOCATION_BASE_URL,
    REVOCATION_CHECK_PATHS,
    REVOCATION_TIMEOUT_SECONDS,
)


class RevocationError(Exception):
    pass


class RevocationClient:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=REVOCATION_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )

    async def is_revoked(self, jti: str) -> Dict[str, Any]:
        """
        Calls P4:
          GET {REVOCATION_BASE_URL}{path}/{jti}

        Expected response:
          { "jti": "...", "revoked": true/false, "revokedAt": "... or null" }

        If P4 returns 404, we treat as not revoked (safe default).
        """
        last_error: Optional[Exception] = None

        for path in REVOCATION_CHECK_PATHS:
            url = REVOCATION_BASE_URL.rstrip("/") + path.rstrip("/") + f"/{jti}"
            try:
                resp = await self._client.get(url)

                if resp.status_code == 404:
                    return {"jti": jti, "revoked": False, "revokedAt": None}

                if resp.status_code != 200:
                    last_error = RuntimeError(f"P4 HTTP {resp.status_code} from {url}")
                    continue

                data = resp.json()
                if not isinstance(data, dict) or "revoked" not in data:
                    raise RevocationError(f"Bad P4 response shape from {url}: {data}")

                return data

            except Exception as exc:
                last_error = exc
                continue

        raise RevocationError(
            f"Could not check revocation via P4 at {REVOCATION_BASE_URL} paths={REVOCATION_CHECK_PATHS}. "
            f"Last error: {last_error}"
        )


revocation_client = RevocationClient()
