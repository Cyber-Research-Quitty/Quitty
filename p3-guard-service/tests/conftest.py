import os
import sys

# Ensure guard-service root is in import path (MUST be before app imports)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import base64
import json
import time

import pytest_asyncio
import httpx

from app.main import create_app
import app.middleware as middleware


def _b64url_json(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_jwt(
    header: dict,
    payload: dict,
    signature: str = "sig",
) -> str:
    return f"{_b64url_json(header)}.{_b64url_json(payload)}.{signature}"


def make_valid_jwt(
    *,
    kid: str = "test-key",
    alg: str = "RS256",
    sub: str = "123",
    jti: str = "id-1",
    exp_offset: int = 600,
    iat_offset: int = 0,
    nbf_offset: int | None = None,
    include_typ: bool = True,
) -> str:
    now = int(time.time())
    header = {"alg": alg, "kid": kid}
    if include_typ:
        header["typ"] = "JWT"
    payload = {"sub": sub, "jti": jti, "iat": now + iat_offset, "exp": now + exp_offset}
    if nbf_offset is not None:
        payload["nbf"] = now + nbf_offset
    return make_jwt(header=header, payload=payload, signature="sig")


@pytest_asyncio.fixture
async def client():
    app = create_app()

    # Test-only protected endpoint so middleware is exercised
    @app.get("/protected-demo")
    async def protected_demo():
        return {"ok": True}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture(autouse=True)
async def default_mocks(monkeypatch):
    # Keep ISS/AUD off during unit tests to avoid env breaking tests
    monkeypatch.setattr(middleware, "EXPECTED_ISS", "")
    monkeypatch.setattr(middleware, "EXPECTED_AUD", "")

    # MUST be int 0 (avoid truthy "0" string behavior)
    monkeypatch.setattr(middleware, "MAX_TOKEN_AGE_SECONDS", 0)

    # Avoid time-leeway flakiness in expiry tests
    monkeypatch.setattr(middleware, "CLOCK_SKEW_SECONDS", 0)

    # Default P2: key exists + matching alg
    async def fake_get_key_by_kid(kid: str):
        return {"kid": kid, "alg": "RS256"}

    # Default P1: signature valid
    async def fake_verify(token: str):
        return {"valid": True}

    # Default P4: not revoked
    async def fake_is_revoked(jti: str):
        return {"revoked": False}

    monkeypatch.setattr(middleware.jwks_client, "get_key_by_kid", fake_get_key_by_kid)
    monkeypatch.setattr(middleware.signer_client, "verify", fake_verify)
    monkeypatch.setattr(middleware.revocation_client, "is_revoked", fake_is_revoked)