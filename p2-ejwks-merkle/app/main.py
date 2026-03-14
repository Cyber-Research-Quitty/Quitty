from __future__ import annotations
import os
import logging
from typing import Any, Dict
from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
from pydantic import ValidationError
from redis import Redis

from .dashboard import render_dashboard_html, render_present_html
from .schemas import JWKIn, ImportKeyOut
from .storage import KeyStore
from .signer import load_or_create_root_signer
from .service import EJWKSService

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

APP_DB_PATH = os.getenv("APP_DB_PATH", "./keys.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

ROOT_SIGNER = os.getenv("ROOT_SIGNER", "ml-dsa-44")
ROOT_SIGNER_KEY_PATH = os.getenv("ROOT_SIGNER_KEY_PATH", "./root_signer_key.json")

# NEW: Transparency log signer (keep separate key)
LOG_SIGNER = os.getenv("LOG_SIGNER", "ml-dsa-44")
LOG_SIGNER_KEY_PATH = os.getenv("LOG_SIGNER_KEY_PATH", "./log_signer_key.json")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

BLOOM_BITS = int(os.getenv("BLOOM_BITS", "1048576"))
BLOOM_HASHES = int(os.getenv("BLOOM_HASHES", "7"))
BLOOM_ENABLED = os.getenv("BLOOM_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}

app = FastAPI(title="Merkle-Enhanced E-JWKS + Transparency", version="0.2.0")

logger.info(f"Initializing KeyStore at {APP_DB_PATH}")
store = KeyStore(APP_DB_PATH)

logger.info(f"Connecting to Redis at {REDIS_URL}")
redis = Redis.from_url(REDIS_URL, decode_responses=False)

logger.info(f"Loading root signer (alg={ROOT_SIGNER})")
root_signer = load_or_create_root_signer(ROOT_SIGNER, ROOT_SIGNER_KEY_PATH)

logger.info(f"Loading log signer (alg={LOG_SIGNER})")
log_signer = load_or_create_root_signer(LOG_SIGNER, LOG_SIGNER_KEY_PATH)

svc = EJWKSService(
    store=store,
    redis=redis,
    root_signer=root_signer,
    log_signer=log_signer,
    bloom_bits=BLOOM_BITS,
    bloom_hashes=BLOOM_HASHES,
    bloom_enabled=BLOOM_ENABLED,
)

@app.on_event("startup")
def _startup() -> None:
    logger.info("Building initial Merkle tree...")
    svc.rebuild_tree()
    key_count = len(store.list_all())
    checkpoint_count = len(store.list_checkpoints())
    logger.info(
        f"Startup complete: {key_count} keys, {checkpoint_count} checkpoints, "
        f"bloom_enabled={BLOOM_ENABLED}, bloom_bits={BLOOM_BITS}, bloom_hashes={BLOOM_HASHES}"
    )

@app.get("/health")
def health():
    return {"ok": True}


@app.get("/health/details")
def health_details():
    redis_ok = False
    redis_error: str | None = None
    try:
        redis.ping()
        redis_ok = True
    except Exception as e:
        redis_error = str(e)

    db_ok = True
    db_error: str | None = None
    key_count = 0
    checkpoint_count = 0
    try:
        key_count = len(store.list_all())
        checkpoint_count = len(store.list_checkpoints())
    except Exception as e:
        db_ok = False
        db_error = str(e)

    return {
        "ok": redis_ok and db_ok,
        "components": {
            "redis": {"ok": redis_ok, "error": redis_error},
            "sqlite": {
                "ok": db_ok,
                "error": db_error,
                "active_keys": key_count,
                "checkpoints": checkpoint_count,
            },
        },
    }


def _require_admin_api_key(x_admin_api_key: str | None = Header(default=None, alias="X-Admin-Api-Key")) -> None:
    if not ADMIN_API_KEY:
        logger.error("ADMIN_API_KEY is not configured; write endpoints are disabled")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="admin API key is not configured",
        )
    if x_admin_api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid admin API key",
        )


def _get_dashboard_snapshot() -> Dict[str, Any]:
    snapshot = svc.get_dashboard_snapshot()
    if not snapshot["jwks_root"]:
        snapshot["jwks_root"] = svc.rebuild_tree()
        snapshot = svc.get_dashboard_snapshot()
    if not snapshot["log_root"]:
        svc._rebuild_log_cache()
        snapshot = svc.get_dashboard_snapshot()
    return snapshot


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard():
    return HTMLResponse(render_dashboard_html())


@app.get("/dashboard/data", include_in_schema=False)
def dashboard_data():
    return _get_dashboard_snapshot()


@app.get("/present", response_class=HTMLResponse, include_in_schema=False)
def present():
    return HTMLResponse(render_present_html())

@app.get("/jwks.json", deprecated=True)
def legacy_jwks():
    keys = [rec.jwk for rec in store.list_all()]
    logger.debug(f"Served legacy JWKS with {len(keys)} keys")
    return {"keys": keys}

@app.get("/jwks/root")
def get_jwks_root():
    bundle = svc.get_jwks_root_bundle()
    if not bundle:
        logger.warning("JWKS root bundle not in cache, rebuilding...")
        bundle = svc.rebuild_tree()
    logger.debug(f"Served JWKS root (epoch={bundle.get('epoch')})")
    return bundle

@app.get("/jwks/proof/{kid}")
def get_key_proof(kid: str):
    logger.info(f"Proof request for kid={kid}")
    res = svc.get_key_and_proof_by_kid(kid)
    if not res:
        logger.warning(f"Key not found: kid={kid}")
        raise HTTPException(status_code=404, detail="unknown kid")
    jwk, proof, jkt = res
    cp_list = store.list_checkpoints()
    latest_cp = cp_list[-1] if cp_list else None
    logger.info(f"Served proof for kid={kid}, jkt={jkt}")
    return {
        "kid": kid,
        "jkt": jkt,
        "jwk": jwk,
        "merkle_proof": proof,
        "root": svc.get_jwks_root_bundle() or svc.rebuild_tree(),
        "latest_checkpoint_idx": latest_cp.idx if latest_cp else None,
    }

def _normalize_import_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accept both:
    - canonical import payload: top-level JWK fields
    - legacy wrapped payload: {"jwk": {...}, ...}
    """
    if isinstance(payload.get("jwk"), dict):
        return payload["jwk"]
    return payload

@app.get("/jwks/{kid}")
def get_key_by_kid(kid: str):
    # Alias endpoint for per-key retrieval in verifier microservices.
    return get_key_proof(kid)


@app.get("/jwks/proof-by-jkt/{jkt}")
def get_key_proof_by_jkt(jkt: str):
    logger.info(f"Proof request for jkt={jkt}")
    res = svc.get_key_and_proof_by_jkt(jkt)
    if not res:
        logger.warning(f"Key not found by jkt={jkt}")
        raise HTTPException(status_code=404, detail="unknown jkt")

    jwk, proof, resolved_jkt = res
    cp_list = store.list_checkpoints()
    latest_cp = cp_list[-1] if cp_list else None
    return {
        "kid": jwk.get("kid"),
        "jkt": resolved_jkt,
        "jwk": jwk,
        "merkle_proof": proof,
        "root": svc.get_jwks_root_bundle() or svc.rebuild_tree(),
        "latest_checkpoint_idx": latest_cp.idx if latest_cp else None,
    }

@app.post("/internal/keys/import", response_model=ImportKeyOut)
def import_key(payload: Dict[str, Any], x_admin_api_key: str | None = Header(default=None, alias="X-Admin-Api-Key")):
    _require_admin_api_key(x_admin_api_key)
    try:
        normalized = _normalize_import_payload(payload)
        jwk = JWKIn.model_validate(normalized)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    kid = jwk.kid
    logger.info(f"Importing key: kid={kid}, kty={jwk.kty}")
    try:
        result = svc.import_key(jwk.model_dump(exclude_none=True))
        logger.info(f"Key imported successfully: kid={kid}, jkt={result['jkt']}")
        return result
    except ValueError as e:
        logger.warning(f"Invalid import payload for kid={kid}: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid key payload: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to import key {kid}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Import failed: {str(e)}")


@app.delete("/internal/keys/{kid}")
def delete_key(kid: str, x_admin_api_key: str | None = Header(default=None, alias="X-Admin-Api-Key")):
    _require_admin_api_key(x_admin_api_key)
    logger.info(f"Deleting key: kid={kid}")
    result = svc.remove_key(kid)
    if not result["removed"]:
        raise HTTPException(status_code=404, detail="unknown kid")
    return result

# -------------------- Transparency Log API --------------------

@app.get("/log/root")
def get_log_root():
    bundle = svc.get_log_bundle()
    if not bundle:
        logger.warning("Log bundle not in cache, rebuilding...")
        svc._rebuild_log_cache()
        bundle = svc.get_log_bundle()
    if not bundle:
        logger.error("Failed to get log bundle after rebuild")
        raise HTTPException(status_code=503, detail="log bundle not available")
    logger.debug(f"Served log root (epoch={bundle.get('epoch')})")
    return bundle

@app.get("/log/latest")
def get_log_latest():
    cps = store.list_checkpoints()
    if not cps:
        logger.warning("No checkpoints found, rebuilding tree...")
        svc.rebuild_tree()
        cps = store.list_checkpoints()
    if not cps:
        logger.error("No checkpoints available after rebuild")
        raise HTTPException(status_code=404, detail="no checkpoints available")
    
    latest = cps[-1]
    logger.info(f"Latest checkpoint request: idx={latest.idx}")
    log_bundle = svc.get_log_bundle()
    if not log_bundle:
        svc._rebuild_log_cache()
        log_bundle = svc.get_log_bundle()
    if not log_bundle:
        raise HTTPException(status_code=503, detail="log bundle not available")
    
    proof = svc.get_log_inclusion_proof(latest.idx)
    if proof is None:
        raise HTTPException(status_code=503, detail="proof not available")
    
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
    logger.info(f"Checkpoint request: idx={idx}")
    cp = store.get_checkpoint(idx)
    if not cp:
        logger.warning(f"Checkpoint not found: idx={idx}")
        raise HTTPException(status_code=404, detail="unknown checkpoint")
    
    log_bundle = svc.get_log_bundle()
    if not log_bundle:
        svc._rebuild_log_cache()
        log_bundle = svc.get_log_bundle()
    if not log_bundle:
        raise HTTPException(status_code=503, detail="log bundle not available")
    
    proof = svc.get_log_inclusion_proof(cp.idx)
    if proof is None:
        raise HTTPException(status_code=503, detail="proof not available")
    
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


@app.get("/log/checkpoints")
def list_log_checkpoints(
    limit: int = Query(default=10, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    checkpoints = store.list_checkpoints()
    total = len(checkpoints)
    window = checkpoints[offset:offset + limit]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "idx": cp.idx,
                "epoch": cp.epoch,
                "jwks_root_hash": cp.jwks_root_hash,
                "prev_hash": cp.prev_hash,
                "entry_hash": cp.entry_hash,
            }
            for cp in window
        ],
    }
