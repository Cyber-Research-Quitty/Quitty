from typing import Any, Dict, Optional

import httpx

from .config import SIGNER_BASE_URL, SIGNER_VERIFY_PATHS, SIGNER_TIMEOUT_SECONDS


class SignerVerifyError(Exception):
    pass


class SignerClient:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=SIGNER_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )

    async def verify(self, token: str) -> Dict[str, Any]:
        last_error: Optional[Exception] = None

        for path in SIGNER_VERIFY_PATHS:
            url = SIGNER_BASE_URL.rstrip("/") + path
            try:
                resp = await self._client.post(url, json={"token": token})

                if resp.status_code != 200:
                    last_error = RuntimeError(f"P1 verify HTTP {resp.status_code} from {url}")
                    continue

                data = resp.json()
                if not isinstance(data, dict) or "valid" not in data:
                    raise SignerVerifyError(f"Bad P1 response shape from {url}: {data}")

                return data

            except Exception as exc:
                last_error = exc
                continue

        raise SignerVerifyError(
            f"Could not verify token via P1 at {SIGNER_BASE_URL} paths={SIGNER_VERIFY_PATHS}. Last error: {last_error}"
        )


signer_client = SignerClient()
