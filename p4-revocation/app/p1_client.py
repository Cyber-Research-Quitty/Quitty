import httpx
from fastapi import HTTPException, status

from .config import P1_SIGN_BASE_URL, P1_SIGN_PATH, P1_SIGN_TIMEOUT_SECONDS, P1_ACCESS_TOKEN_ALG


class P1SignerClient:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=P1_SIGN_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def sign_access_token(self, claims: dict, alg: str | None = None) -> str:
        url = P1_SIGN_BASE_URL.rstrip("/") + P1_SIGN_PATH
        payload = {"claims": claims, "alg": alg or P1_ACCESS_TOKEN_ALG}

        try:
            resp = await self._client.post(url, json=payload)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"P1 signer unavailable: {exc}",
            ) from exc

        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"P1 signer error HTTP {resp.status_code}: {resp.text}",
            )

        data = resp.json()
        token = data.get("token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"P1 signer returned invalid payload: {data}",
            )

        return token

    async def verify_access_token(self, token: str) -> dict:
        url = P1_SIGN_BASE_URL.rstrip("/") + "/verify"
        payload = {"token": token}

        try:
            resp = await self._client.post(url, json=payload)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"P1 verifier unavailable: {exc}",
            ) from exc

        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"P1 verifier error HTTP {resp.status_code}: {resp.text}",
            )

        data = resp.json()
        if not isinstance(data, dict):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"P1 verifier returned invalid payload: {data}",
            )

        return data


p1_signer_client = P1SignerClient()
