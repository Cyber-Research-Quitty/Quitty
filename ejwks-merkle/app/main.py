from __future__ import annotations
import os
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
from redis import Redis

from .schemas import JWKIn, ImportKeyOut
from .storage import KeyStore
from .signer import load_or_create_root_signer
from .service import EJWKSService

load_dotenv()

APP_DB_PATH = os.getenv("APP_DB_PATH", "./keys.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

ROOT_SIGNER = os.getenv("ROOT_SIGNER", "ed25519")
ROOT_SIGNER_KEY_PATH = os.getenv("ROOT_SIGNER_KEY_PATH", "./root_signer_key.json")

# NEW: Transparency log signer (keep separate key)
LOG_SIGNER = os.getenv("LOG_SIGNER", "ed25519")
LOG_SIGNER_KEY_PATH = os.getenv("LOG_SIGNER_KEY_PATH", "./log_signer_key.json")

BLOOM_BITS = int(os.getenv("BLOOM_BITS", "1048576"))
BLOOM_HASHES = int(os.getenv("BLOOM_HASHES", "7"))

app = FastAPI(title="Merkle-Enhanced E-JWKS + Transparency", version="0.2.0")

store = KeyStore(APP_DB_PATH)
redis = Redis.from_url(REDIS_URL, decode_responses=False)

root_signer = load_or_create_root_signer(ROOT_SIGNER, ROOT_SIGNER_KEY_PATH)
log_signer = load_or_create_root_signer(LOG_SIGNER, LOG_SIGNER_KEY_PATH)

svc = EJWKSService(
    store=store,
    redis=redis,
    root_signer=root_signer,
    log_signer=log_signer,
    bloom_bits=BLOOM_BITS,
    bloom_hashes=BLOOM_HASHES,
)

@app.on_event("startup")
def _startup() -> None:
    svc.rebuild_tree()

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/jwks.json")
def legacy_jwks():
    keys = [rec.jwk for rec in store.list_all()]
    return {"keys": keys}

@app.get("/jwks/root")
def get_jwks_root():
    bundle = svc.get_jwks_root_bundle()
    if not bundle:
        bundle = svc.rebuild_tree()
    return bundle

@app.get("/jwks/proof/{kid}")
def get_key_proof(kid: str):
    res = svc.get_key_and_proof_by_kid(kid)
    if not res:
        raise HTTPException(status_code=404, detail="unknown kid")
    jwk, proof = res
    cp_list = store.list_checkpoints()
    latest_cp = cp_list[-1] if cp_list else None
    return {
        "kid": kid,
        "jwk": jwk,
        "merkle_proof": proof,
        "jwks_root": svc.get_jwks_root_bundle() or svc.rebuild_tree(),
        "latest_checkpoint_idx": latest_cp.idx if latest_cp else None,
    }

@app.post("/internal/keys/import", response_model=ImportKeyOut)
def import_key(jwk: JWKIn):
    return svc.import_key(jwk.model_dump())

# -------------------- Transparency Log API --------------------

@app.get("/log/root")
def get_log_root():
    bundle = svc.get_log_bundle()
    if not bundle:
        svc.rebuild_tree()
        bundle = svc.get_log_bundle()
    return bundle

@app.get("/log/latest")
def get_log_latest():
    cps = store.list_checkpoints()
    if not cps:
        svc.rebuild_tree()
        cps = store.list_checkpoints()
    latest = cps[-1]
    log_bundle = svc.get_log_bundle() or (svc.rebuild_tree() or svc.get_log_bundle())
    proof = svc.get_log_inclusion_proof(latest.idx)
    return {
        "checkpoint": {
            "idx": latest.idx,
            "epoch": latest.epoch,
            "jwks_root_hash": latest.jwks_root_hash,
            "prev_hash": latest.prev_hash,
            "entry_hash": latest.entry_hash,
        },
        "log_root": log_bundle,
        "inclusion_proof": proof,
    }

@app.get("/log/checkpoint/{idx}")
def get_log_checkpoint(idx: int):
    cp = store.get_checkpoint(idx)
    if not cp:
        raise HTTPException(status_code=404, detail="unknown checkpoint")
    log_bundle = svc.get_log_bundle() or (svc.rebuild_tree() or svc.get_log_bundle())
    proof = svc.get_log_inclusion_proof(cp.idx)
    return {
        "checkpoint": {
            "idx": cp.idx,
            "epoch": cp.epoch,
            "jwks_root_hash": cp.jwks_root_hash,
            "prev_hash": cp.prev_hash,
            "entry_hash": cp.entry_hash,
        },
        "log_root": log_bundle,
        "inclusion_proof": proof,
    }
