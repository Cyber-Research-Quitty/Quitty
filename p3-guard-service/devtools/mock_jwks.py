import base64
import hashlib
import json

from fastapi import FastAPI, HTTPException

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


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _leaf_hash(jwk: dict) -> str:
    return _b64url_encode(_sha256(b"\x00" + _canonical_json(jwk)))

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


@app.get("/jwks/proof/{kid}")
async def jwks_proof(kid: str):
    for key in JWKS["keys"]:
        if key.get("kid") == kid:
            root_hash = _leaf_hash(key)
            return {
                "kid": kid,
                "jkt": "mock-jkt",
                "jwk": key,
                "merkle_proof": [],
                "root": {
                    "root_hash": root_hash,
                    "epoch": 0,
                    "sig_alg": "mock",
                    "sig_kid": "mock-root",
                    "sig_pub": "mock-pub",
                    "signature": "mock-signature",
                },
            }
    raise HTTPException(status_code=404, detail="unknown kid")


@app.get("/jwks/{kid}")
async def jwks_by_kid(kid: str):
    return await jwks_proof(kid)
