from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .crypto_backend import AlgName
from .keystore import keystore
from .config import settings
from .p2_client import post_json, P2ClientError

router = APIRouter(prefix="/internal/keys", tags=["internal"])


@router.get("/public")
def public_keys(alg: AlgName | None = None, include_all: bool = True):
    return keystore.list_public(alg=alg, include_all=include_all)


@router.get("/jwks")
def jwks_keys(alg: AlgName | None = None, include_all: bool = False):
    """
    JWKS-like output for P2 integration.
    By default returns only active keys.
    """
    return keystore.jwks(alg=alg, include_all=include_all)


class ExportRequest(BaseModel):
    alg: AlgName = Field(..., description="Which algorithm key to export to P2")
    kid: str | None = Field(
        default=None,
        description="Export a specific kid (optional). If missing, exports active kid for alg.",
    )


@router.post("/export")
def export_to_p2(body: ExportRequest):
    if not settings.p2_export_url:
        raise HTTPException(status_code=400, detail="p2_export_url_not_configured")

    kid = body.kid or keystore.get_active_kid(body.alg)
    if not kid:
        raise HTTPException(status_code=404, detail="no_active_key_for_alg")

    kp = keystore.get(kid)
    if not kp:
        raise HTTPException(status_code=404, detail="kid_not_found")

    pub_b64u = keystore.jwks(alg=body.alg, include_all=True)
    jwk_match = next((k for k in pub_b64u["keys"] if k["kid"] == kp.kid), None)

    payload = {
        "kid": kp.kid,
        "alg": kp.alg,
        "public_key_hex": kp.public_key.hex(),
        "public_key_b64u": jwk_match["pk"] if jwk_match and "pk" in jwk_match else jwk_match["x"] if jwk_match and "x" in jwk_match else None,
        "public_key_len": len(kp.public_key),
        "jwk": jwk_match,
    }

    try:
        resp = post_json(settings.p2_export_url, payload, timeout_seconds=settings.p2_timeout_seconds)
    except P2ClientError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return {
        "exported": True,
        "kid": kp.kid,
        "alg": kp.alg,
        "p2_response": resp,
    }


class RotateRequest(BaseModel):
    alg: AlgName = Field(..., description="Rotate which algorithm")
    export: bool = Field(default=True, description="If true, export new key to P2 (requires p2_export_url)")


@router.post("/rotate")
def rotate_key(body: RotateRequest):
    # rotate locally
    kp = keystore.rotate(body.alg)

    exported = False
    p2_resp = None

    if body.export:
        if not settings.p2_export_url:
            # rotation works even if export is not configured
            exported = False
        else:
            jwks_data = keystore.jwks(alg=body.alg, include_all=True)
            jwk_match = next((k for k in jwks_data["keys"] if k["kid"] == kp.kid), None)

            payload = {
                "kid": kp.kid,
                "alg": kp.alg,
                "public_key_hex": kp.public_key.hex(),
                "public_key_b64u": jwk_match["pk"] if jwk_match and "pk" in jwk_match else jwk_match["x"] if jwk_match and "x" in jwk_match else None,
                "public_key_len": len(kp.public_key),
                "jwk": jwk_match,
            }

            try:
                p2_resp = post_json(settings.p2_export_url, payload, timeout_seconds=settings.p2_timeout_seconds)
                exported = True
            except P2ClientError as e:
                raise HTTPException(status_code=502, detail=f"rotated_but_export_failed: {e}")

    return {
        "rotated": True,
        "kid": kp.kid,
        "alg": kp.alg,
        "exported": exported,
        "p2_response": p2_resp,
    }