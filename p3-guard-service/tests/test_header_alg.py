import pytest
import app.middleware as middleware
from .conftest import make_jwt, make_valid_jwt


@pytest.mark.asyncio
async def test_invalid_typ(client):
    # typ missing -> your code does: if typ != "JWT" => invalid_typ
    token = make_valid_jwt(include_typ=False)
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "invalid_typ"}


@pytest.mark.asyncio
async def test_missing_alg(client):
    header = {"typ": "JWT", "kid": "test-key"}
    payload = {"sub": "123", "jti": "id-1", "iat": 1, "exp": 9999999999}
    token = make_jwt(header, payload, "sig")
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "missing_alg"}


@pytest.mark.asyncio
async def test_missing_kid(client):
    header = {"typ": "JWT", "alg": "RS256"}
    payload = {"sub": "123", "jti": "id-1", "iat": 1, "exp": 9999999999}
    token = make_jwt(header, payload, "sig")
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "missing_kid"}


@pytest.mark.asyncio
async def test_alg_none_blocked(client):
    token = make_valid_jwt(alg="none")
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "alg_none_not_allowed"}


@pytest.mark.asyncio
async def test_unsupported_algorithm(client):
    token = make_valid_jwt(alg="HS256")
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "unsupported_algorithm"}


@pytest.mark.asyncio
async def test_kid_not_found_in_p2(client, monkeypatch):
    async def fake_get_key_by_kid(kid: str):
        return None

    monkeypatch.setattr(middleware.jwks_client, "get_key_by_kid", fake_get_key_by_kid)

    token = make_valid_jwt(kid="no-such-kid")
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "kid_not_found"}


@pytest.mark.asyncio
async def test_alg_confusion(client, monkeypatch):
    async def fake_get_key_by_kid(kid: str):
        return {"kid": kid, "alg": "RS256"}  # JWKS says RS256

    monkeypatch.setattr(middleware.jwks_client, "get_key_by_kid", fake_get_key_by_kid)

    token = make_valid_jwt(alg="ES256")  # header says ES256 -> mismatch => alg_confusion
    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "alg_confusion"}