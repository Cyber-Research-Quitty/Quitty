from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .config import settings
from .jose_utils import encode_header, encode_payload, b64url_encode
from .keystore import keystore
from .crypto_ed25519 import Ed25519Backend
from .metrics import SIGN_LATENCY_SECONDS, P1_ERRORS_TOTAL  # ✅ added


router = APIRouter(prefix="/sign", tags=["sign"])

backend = Ed25519Backend()


class SignRequest(BaseModel):
    """
    Request body for /sign
    """
    claims: Dict[str, Any] = Field(
        ..., description="JWT claims/payload to include in the token"
    )
    alg: str = Field(
        default=settings.default_alg,
        description="Algorithm to use (currently only 'ed25519-dev' is supported in dev mode).",
    )


class SignResponse(BaseModel):
    """
    Response from /sign
    """
    token: str
    alg: str
    kid: str
    token_size_bytes: int
    sign_time_ms: float


@router.post("", response_model=SignResponse)
def sign_token(body: SignRequest) -> SignResponse:
    """
    Issue a signed JWT using the active key from the keystore.
    """

    # 1) Get the active keypair from keystore
    kp = keystore.get_active_key()

    if body.alg != kp.alg:
        # for now we only support using the key's own alg
        raise HTTPException(status_code=400, detail="alg_mismatch_with_active_key")

    # 2) Build JOSE header + payload
    header = {
        "typ": "JWT",
        "alg": body.alg,
        "kid": kp.kid,
    }

    encoded_header = encode_header(header)
    encoded_payload = encode_payload(body.claims)

    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

    # 3) Sign (with Prometheus timing)
    t0 = time.perf_counter()
    try:
        signature = backend.sign(kp.alg, kp.private_key, signing_input)
        SIGN_LATENCY_SECONDS.observe(time.perf_counter() - t0)
    except Exception:
        P1_ERRORS_TOTAL.labels(type="sign_error").inc()
        raise

    dt_ms = (time.perf_counter() - t0) * 1000.0

    encoded_sig = b64url_encode(signature)

    token = f"{encoded_header}.{encoded_payload}.{encoded_sig}"

    return SignResponse(
        token=token,
        alg=kp.alg,
        kid=kp.kid,
        token_size_bytes=len(token.encode("ascii")),
        sign_time_ms=dt_ms,
    )
