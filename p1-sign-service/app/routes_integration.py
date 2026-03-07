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


def _resolve_export_jwk(alg: AlgName, kid: str) -> dict:
    jwks_data = keystore.jwks(alg=alg, include_all=True)
    jwk_match = next((k for k in jwks_data["keys"] if k["kid"] == kid), None)
    if not jwk_match:
        raise HTTPException(status_code=500, detail="failed_to_build_jwk_for_kid")
    return jwk_match


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

    export_jwk = _resolve_export_jwk(body.alg, kp.kid)

    try:
        resp = post_json(settings.p2_export_url, export_jwk, timeout_seconds=settings.p2_timeout_seconds)
    except P2ClientError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return {
        "exported": True,
        "kid": kp.kid,
        "alg": kp.alg,
        "jwk": export_jwk,
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
            export_jwk = _resolve_export_jwk(body.alg, kp.kid)

            try:
                p2_resp = post_json(settings.p2_export_url, export_jwk, timeout_seconds=settings.p2_timeout_seconds)
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
