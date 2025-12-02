from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from .jwks_store import get_all_keys, get_key_by_kid
from datetime import datetime, timezone


from .models import JWK, PublicKeyExport
from .jwks_store import (
    get_all_keys,
    get_key_by_kid,
    get_key_by_jkt,
    get_jkt_for_kid,
    add_or_update_key,
)


app = FastAPI(
    title="Enhanced JWKS Service (P2)",
    description="P2 – Per-Key PQC-Optimized JWKS distribution",
    version="0.1.0",
)

@app.get("/.well-known/jwks.json")
def get_jwks():
    jwks = get_all_keys()
    return JSONResponse(content=jwks.model_dump(by_alias=True))


@app.get("/jwks/by-kid/{kid}")
def get_jwk_by_kid(kid: str):
    jwk = get_key_by_kid(kid)
    if jwk is None:
        raise HTTPException(status_code=404, detail="Key not found")
    return JSONResponse(content=jwk.model_dump(by_alias=True))


@app.get("/.well-known/jwks.json")
def get_jwks():
    jwks = get_all_keys()
    return JSONResponse(content=jwks.model_dump())


@app.get("/jwks/by-kid/{kid}")
def get_jwk_by_kid(kid: str):
    jwk = get_key_by_kid(kid)
    if jwk is None:
        raise HTTPException(status_code=404, detail="Key not found")
    return JSONResponse(content=jwk.model_dump())


@app.get("/jwks/by-jkt/{jkt}")
def get_jwk_by_jkt(jkt: str):
    jwk = get_key_by_jkt(jkt)
    if jwk is None:
        raise HTTPException(status_code=404, detail="Key not found")
    return JSONResponse(content=jwk.model_dump(by_alias=True))


# Optional but very useful for you right now:
@app.get("/jwks/debug/jkt-by-kid/{kid}")
def debug_jkt_by_kid(kid: str):
    """
    Debug helper: given a kid, return its thumbprint (jkt).
    You can use this JKT to call /jwks/by-jkt/{jkt}.
    """
    jkt = get_jkt_for_kid(kid)
    if jkt is None:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"kid": kid, "jkt": jkt}


@app.post("/internal/keys/import")
def import_public_key(payload: PublicKeyExport):
    """
    Internal endpoint for P1 (sign/verify module) to push a new public key.
    """
    created_at = payload.created_at or datetime.now(timezone.utc)

    jwk = JWK(
        kty=payload.kty,
        kid=payload.kid,
        alg=payload.alg,
        use="sig",
        crv=payload.crv,
        x=payload.x,
        created_at=created_at,
    )

    try:
        jkt = add_or_update_key(jwk)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"kid": jwk.kid, "jkt": jkt}
