from __future__ import annotations

import time
import uuid
from typing import Any, Dict
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .config import settings
from .jose_utils import encode_header, encode_payload, b64url_encode
from .keystore import keystore
from .backend_factory import get_backend
from .crypto_backend import AlgName
from .metrics import SIGN_LATENCY_SECONDS, P1_ERRORS_TOTAL
from .p2_client import post_json, P2ClientError

router = APIRouter(prefix="/sign", tags=["sign"])
_EXPORTED_KIDS: set[str] = set()


def _p2_headers() -> dict[str, str] | None:
    if not settings.p2_admin_api_key:
        return None
    return {"X-Admin-Api-Key": settings.p2_admin_api_key}


def _now_unix() -> int:
    return int(datetime.now(timezone.utc).timestamp())


class SignRequest(BaseModel):
    claims: Dict[str, Any] = Field(..., description="JWT claims/payload")
    alg: AlgName = Field(default=settings.default_alg)
    kid: str | None = Field(default=None, description="Optional active kid override for signing")


class SignResponse(BaseModel):
    token: str
    alg: str
    kid: str
    sub: str | None = None
    jti: str
    token_size_bytes: int
    sign_time_ms: float


def _resolve_export_jwk(alg: AlgName, kid: str) -> dict[str, Any] | None:
    jwks_data = keystore.jwks(alg=alg, include_all=True)
    keys = jwks_data.get("keys")
    if not isinstance(keys, list):
        return None
    for item in keys:
        if isinstance(item, dict) and item.get("kid") == kid:
            return item
    return None


def _best_effort_export_signing_key_to_p2(alg: AlgName, kid: str) -> None:
    if not settings.p2_export_url:
        return
    if kid in _EXPORTED_KIDS:
        return

    export_jwk = _resolve_export_jwk(alg, kid)
    if not export_jwk:
        return

    try:
        post_json(
            settings.p2_export_url,
            export_jwk,
            timeout_seconds=settings.p2_timeout_seconds,
            headers=_p2_headers(),
        )
        _EXPORTED_KIDS.add(kid)
    except P2ClientError:
        # Do not fail token issuance if P2 is temporarily unavailable.
        pass


@router.post("", response_model=SignResponse)
def sign_token(body: SignRequest) -> SignResponse:
    # Copy claims so we never mutate the original request object directly
    claims = dict(body.claims)

    # Auto-add integration-friendly claims
    if "jti" not in claims:
        claims["jti"] = str(uuid.uuid4())

    if "iat" not in claims:
        claims["iat"] = _now_unix()

    try:
        if body.kid:
            kp = keystore.activate_kid(body.alg, body.kid, make_signing=True)
        else:
            kp = keystore.get_active_key(body.alg)
    except ValueError as e:
        P1_ERRORS_TOTAL.labels(type="invalid_signing_kid").inc()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        P1_ERRORS_TOTAL.labels(type="keystore_keygen_failed").inc()
        raise HTTPException(status_code=500, detail=f"keygen_failed: {type(e).__name__}: {e}")

    try:
        backend = get_backend(kp.alg)
    except Exception:
        P1_ERRORS_TOTAL.labels(type="alg_not_implemented").inc()
        raise HTTPException(status_code=501, detail=f"alg_not_implemented: {kp.alg}")

    header = {"typ": "JWT", "alg": kp.alg, "kid": kp.kid}
    encoded_header = encode_header(header)
    encoded_payload = encode_payload(claims)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

    t0 = time.perf_counter()
    try:
        signature = backend.sign(kp.alg, kp.private_key, signing_input)
    except Exception as e:
        P1_ERRORS_TOTAL.labels(type="sign_error").inc()
        raise HTTPException(status_code=500, detail=f"sign_failed: {type(e).__name__}: {e}")

    elapsed = time.perf_counter() - t0
    SIGN_LATENCY_SECONDS.observe(elapsed)
    dt_ms = elapsed * 1000.0

    token = f"{encoded_header}.{encoded_payload}.{b64url_encode(signature)}"

    # Keep P2 in sync so P3 can immediately resolve signer kids by proof.
    _best_effort_export_signing_key_to_p2(kp.alg, kp.kid)

    # Best-effort sync to P4 so P4 can expose/revoke sub/jti/kid for P1-issued tokens.
    if settings.p4_token_sync_url:
        try:
            post_json(
                settings.p4_token_sync_url,
                {"token": token},
                timeout_seconds=settings.p4_timeout_seconds,
            )
        except P2ClientError:
            # Do not fail token issuance if P4 sync is temporarily unavailable.
            pass

    return SignResponse(
        token=token,
        alg=kp.alg,
        kid=kp.kid,
        sub=claims.get("sub") if isinstance(claims.get("sub"), str) else None,
        jti=claims["jti"],
        token_size_bytes=len(token.encode("ascii")),
        sign_time_ms=dt_ms,
    )
