from fastapi import FastAPI

app = FastAPI(title="Mock P2 JWKS Service")

JWKS = {
    "keys": [
        {
            "kid": "test-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": "sXch",     # dummy base64url-safe strings (not used yet)
            "e": "AQAB"
        },
        {
            "kid": "test-ml",
            "kty": "OKP",
            "use": "sig",
            "alg": "ml-dsa-44",
            "crv": "ML-DSA-44",
            "x": "AAAA"
        }
    ]
}

@app.get("/health")
async def health():
    return {"status": "ok", "component": "mock-jwks"}

@app.get("/.well-known/jwks.json")
async def well_known():
    return JWKS

@app.get("/jwks.json")
async def jwks_json():
    return JWKS

@app.get("/jwks")
async def jwks():
    return JWKS
