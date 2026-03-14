from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .crypto_backend import AlgName
from .keystore import keystore
from .config import settings
from .p2_client import post_json, delete_json, P2ClientError

router = APIRouter(prefix="/internal/keys", tags=["internal"])


def _p2_headers() -> dict[str, str] | None:
    if not settings.p2_admin_api_key:
        return None
    return {"X-Admin-Api-Key": settings.p2_admin_api_key}


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


def _revoke_kid_in_p4(kid: str) -> dict:
    if not settings.p4_revoke_url:
        return {"revoked": False, "reason": "p4_revoke_url_not_configured"}
    payload = {"type": "revoke_kid", "value": kid}
    return post_json(settings.p4_revoke_url, payload, timeout_seconds=settings.p4_timeout_seconds)


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
        resp = post_json(
            settings.p2_export_url,
            export_jwk,
            timeout_seconds=settings.p2_timeout_seconds,
            headers=_p2_headers(),
        )
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
                p2_resp = post_json(
                    settings.p2_export_url,
                    export_jwk,
                    timeout_seconds=settings.p2_timeout_seconds,
                    headers=_p2_headers(),
                )
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


class SelectSigningKeyRequest(BaseModel):
    alg: AlgName = Field(..., description="Algorithm namespace")
    kid: str = Field(..., description="Active key id to use for new signatures")


@router.post("/select-signing")
def select_signing_key(body: SelectSigningKeyRequest):
    try:
        kp = keystore.set_signing_kid(body.alg, body.kid)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"selected": True, "alg": kp.alg, "kid": kp.kid}


class KeyStateChangeRequest(BaseModel):
    alg: AlgName = Field(..., description="Algorithm namespace")
    kid: str = Field(..., description="Key id to change")
    make_signing: bool = Field(default=True, description="When activating, set this key as signer for new tokens")


@router.post("/activate")
def activate_key(body: KeyStateChangeRequest):
    try:
        kp = keystore.activate_kid(body.alg, body.kid, make_signing=body.make_signing)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    exported = False
    p2_response = None
    if settings.p2_export_url:
        export_jwk = _resolve_export_jwk(body.alg, kp.kid)
        try:
            p2_response = post_json(
                settings.p2_export_url,
                export_jwk,
                timeout_seconds=settings.p2_timeout_seconds,
                headers=_p2_headers(),
            )
            exported = True
        except P2ClientError as e:
            raise HTTPException(status_code=502, detail=f"activated_but_export_failed: {e}")

    return {
        "activated": True,
        "alg": kp.alg,
        "kid": kp.kid,
        "make_signing": body.make_signing,
        "exported": exported,
        "p2_response": p2_response,
    }


class DeactivateKeyRequest(BaseModel):
    alg: AlgName = Field(..., description="Algorithm namespace")
    kid: str = Field(..., description="Key id to deactivate")


@router.post("/deactivate")
def deactivate_key(body: DeactivateKeyRequest):
    try:
        kp = keystore.deactivate_kid(body.alg, body.kid)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    p2_removed = False
    p2_response = None
    if settings.p2_delete_url:
        delete_url = settings.p2_delete_url.rstrip("/") + f"/{kp.kid}"
        try:
            p2_response = delete_json(
                delete_url,
                timeout_seconds=settings.p2_timeout_seconds,
                headers=_p2_headers(),
            )
            p2_removed = True
        except P2ClientError as e:
            # Idempotent behavior: if key is already absent in P2, continue.
            if "HTTP 404" in str(e):
                p2_removed = False
                p2_response = {"kid": kp.kid, "removed": False, "reason": "already_absent_in_p2"}
            else:
                raise HTTPException(status_code=502, detail=f"deactivated_but_p2_delete_failed: {e}")

    p4_revoked = False
    p4_response = None
    try:
        p4_response = _revoke_kid_in_p4(kp.kid)
        p4_revoked = bool(p4_response)
    except P2ClientError as e:
        raise HTTPException(status_code=502, detail=f"deactivated_but_p4_revoke_failed: {e}")

    return {
        "deactivated": True,
        "alg": kp.alg,
        "kid": kp.kid,
        "p2_removed": p2_removed,
        "p2_response": p2_response,
        "p4_revoked": p4_revoked,
        "p4_response": p4_response,
    }
