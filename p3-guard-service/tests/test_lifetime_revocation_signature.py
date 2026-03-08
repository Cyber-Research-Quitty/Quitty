import pytest
import time
import app.middleware as middleware
from .conftest import make_valid_jwt, make_jwt


@pytest.mark.asyncio
async def test_expired_token(client):
    token = make_valid_jwt(exp_offset=-9999)  # expired far beyond leeway
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "token_expired"}


@pytest.mark.asyncio
async def test_nbf_in_future(client):
    token = make_valid_jwt(exp_offset=7200, nbf_offset=3600)
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "nbf_in_future"}


@pytest.mark.asyncio
async def test_invalid_iat(client):
    now = int(time.time())
    header = {"alg": "ml-dsa-44", "typ": "JWT", "kid": "test-key"}
    payload = {"sub": "123", "jti": "id-1", "iat": "abc", "exp": now + 600}
    token = make_jwt(header, payload, "sig")

    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "invalid_iat"}


@pytest.mark.asyncio
async def test_revoked_jti(client, monkeypatch):
    async def fake_is_revoked_token(*, jti: str, sub: str | None = None, kid: str | None = None):
        return {"revoked": True}

    monkeypatch.setattr(middleware.revocation_client, "is_revoked_token", fake_is_revoked_token)

    token = make_valid_jwt(jti="revoked-1")
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "token_revoked"}


@pytest.mark.asyncio
async def test_invalid_signature_from_p1(client, monkeypatch):
    async def fake_verify(token: str):
        return {"valid": False, "reason": "signature_invalid"}

    monkeypatch.setattr(middleware.signer_client, "verify", fake_verify)

    token = make_valid_jwt()
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "signature_invalid"}


@pytest.mark.asyncio
async def test_positive_valid_allows(client):
    token = make_valid_jwt()
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
