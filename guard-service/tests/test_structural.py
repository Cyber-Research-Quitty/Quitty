import pytest
import base64
import json


@pytest.mark.asyncio
async def test_missing_authorization_header(client):
    r = await client.get("/protected-demo")
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "missing_authorization_header"}


@pytest.mark.asyncio
async def test_non_bearer_scheme(client):
    r = await client.get("/protected-demo", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "invalid_auth_scheme"}


@pytest.mark.asyncio
async def test_empty_token(client):
    r = await client.get("/protected-demo", headers={"Authorization": "Bearer "})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token", "reason": "invalid_auth_scheme"}


@pytest.mark.asyncio
async def test_invalid_segment_count_2(client):
    r = await client.get("/protected-demo", headers={"Authorization": "Bearer a.b"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "invalid_segment_count"}


@pytest.mark.asyncio
async def test_invalid_segment_count_4(client):
    r = await client.get("/protected-demo", headers={"Authorization": "Bearer a.b.c.d"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "invalid_segment_count"}


@pytest.mark.asyncio
async def test_empty_signature(client):
    r = await client.get("/protected-demo", headers={"Authorization": "Bearer a.b."})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "empty_signature"}


@pytest.mark.asyncio
async def test_malformed_base64(client):
    # '$' breaks your BASE64URL_RE -> malformed_base64
    r = await client.get("/protected-demo", headers={"Authorization": "Bearer abc$.def.sig"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "malformed_base64"}


@pytest.mark.asyncio
async def test_malformed_json(client):
    # header ok JSON, payload is "{" (invalid JSON) but base64url-valid
    header = {"alg": "RS256", "typ": "JWT", "kid": "test-key"}
    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    payload_b64 = base64.urlsafe_b64encode(b"{").rstrip(b"=").decode()
    token = f"{header_b64}.{payload_b64}.sig"

    r = await client.get("/protected-demo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_token", "reason": "malformed_json"}