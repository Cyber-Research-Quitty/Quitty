from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .config import settings
from .jose_utils import encode_header, encode_payload, b64url_encode
from .keystore import keystore
from .backend_factory import get_backend
from .crypto_backend import AlgName
from .metrics import SIGN_LATENCY_SECONDS, P1_ERRORS_TOTAL

router = APIRouter(prefix="/sign", tags=["sign"])


class SignRequest(BaseModel):
    claims: Dict[str, Any] = Field(..., description="JWT claims/payload")
    alg: AlgName = Field(default=settings.default_alg)


class SignResponse(BaseModel):
    token: str
    alg: str
    kid: str
    token_size_bytes: int
    sign_time_ms: float


@router.post("", response_model=SignResponse)
def sign_token(body: SignRequest) -> SignResponse:
    try:
        kp = keystore.get_active_key(body.alg)
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
    encoded_payload = encode_payload(body.claims)
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

    return SignResponse(
        token=token,
        alg=kp.alg,
        kid=kp.kid,
        token_size_bytes=len(token.encode("ascii")),
        sign_time_ms=dt_ms,
    )
