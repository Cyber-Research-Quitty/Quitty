from __future__ import annotations
import os
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
from redis import Redis

from .schemas import JWKIn, ImportKeyOut, RootBundle, KeyWithProof
from .storage import KeyStore
from .signer import load_or_create_root_signer
from .service import EJWKSService

load_dotenv()

APP_DB_PATH = os.getenv("APP_DB_PATH", "./keys.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ROOT_SIGNER = os.getenv("ROOT_SIGNER", "ed25519")
ROOT_SIGNER_KEY_PATH = os.getenv("ROOT_SIGNER_KEY_PATH", "./root_signer_key.json")
BLOOM_BITS = int(os.getenv("BLOOM_BITS", "1048576"))
BLOOM_HASHES = int(os.getenv("BLOOM_HASHES", "7"))

app = FastAPI(title="Merkle-Enhanced E-JWKS", version="0.1.0")

store = KeyStore(APP_DB_PATH)
redis = Redis.from_url(REDIS_URL, decode_responses=False)
root_signer = load_or_create_root_signer(ROOT_SIGNER, ROOT_SIGNER_KEY_PATH)

svc = EJWKSService(
    store=store,
    redis=redis,
    root_signer=root_signer,
    bloom_bits=BLOOM_BITS,
    bloom_hashes=BLOOM_HASHES,
)

@app.on_event("startup")
def _startup() -> None:
    svc.rebuild_tree()

@app.get("/health")
def health():
    return {"ok": True}

# Legacy full-set endpoint (backward compatible)
@app.get("/jwks.json")
def legacy_jwks():
    keys = [rec.jwk for rec in store.list_all()]
    return {"keys": keys}

# Trust anchor: signed Merkle root
@app.get("/jwks/root", response_model=RootBundle)
def get_root():
    bundle = svc.get_root_bundle()
    if not bundle:
        bundle = svc.rebuild_tree()
    return bundle

# Diagram endpoint: fetch key+proof by kid
@app.get("/jwks/proof/{kid}", response_model=KeyWithProof)
def get_key_proof(kid: str):
    res = svc.get_key_and_proof_by_kid(kid)
    if not res:
        raise HTTPException(status_code=404, detail="unknown kid")
    jwk, proof = res
    root = svc.get_root_bundle() or svc.rebuild_tree()

    rec = store.get_by_kid(kid)
    if not rec:
        raise HTTPException(status_code=404, detail="unknown kid")

    return {
        "kid": kid,
        "jkt": rec.jkt,
        "jwk": jwk,
        "merkle_proof": proof,
        "root": root,
    }

# Proposal endpoint: fetch key+proof by jkt (thumbprint URI style)
@app.get("/jwks/by-jkt/{jkt}", response_model=KeyWithProof)
def get_key_by_jkt(jkt: str):
    res = svc.get_key_and_proof_by_jkt(jkt)
    if not res:
        raise HTTPException(status_code=404, detail="unknown jkt")
    jwk, proof = res
    root = svc.get_root_bundle() or svc.rebuild_tree()

    rec = store.get_by_jkt(jkt)
    if not rec:
        raise HTTPException(status_code=404, detail="unknown jkt")

    return {
        "kid": rec.kid,
        "jkt": rec.jkt,
        "jwk": jwk,
        "merkle_proof": proof,
        "root": root,
    }

# Internal/admin: import new key -> rebuild tree
@app.post("/internal/keys/import", response_model=ImportKeyOut)
def import_key(jwk: JWKIn):
    out = svc.import_key(jwk.model_dump())
    return out
