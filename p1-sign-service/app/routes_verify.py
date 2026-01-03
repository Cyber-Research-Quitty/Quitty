from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel

from .jose_utils import split_jws, decode_segment, b64url_decode
from .keystore import keystore
from .crypto_ed25519 import Ed25519Backend
from .metrics import VERIFY_LATENCY_SECONDS, P1_ERRORS_TOTAL  # ✅ added

router = APIRouter(prefix="/verify", tags=["verify"])

backend = Ed25519Backend()


class VerifyRequest(BaseModel):
    token: str


class VerifyResponse(BaseModel):
    valid: bool
    alg: str | None = None
    kid: str | None = None
    claims: Dict[str, Any] | None = None
    verify_time_ms: float | None = None
    error: str | None = None


@router.post("", response_model=VerifyResponse)
def verify_token(body: VerifyRequest) -> VerifyResponse:
    # 1) Split token
    try:
        h_seg, p_seg, s_seg = split_jws(body.token)
        header = decode_segment(h_seg)
        payload = decode_segment(p_seg)
        signature = b64url_decode(s_seg)
    except Exception:
        return VerifyResponse(valid=False, error="malformed_token")

    alg = header.get("alg")
    kid = header.get("kid")

    if not alg or not kid:
        return VerifyResponse(valid=False, error="missing_alg_or_kid")

    # 2) Look up key by kid
    kp = keystore.get(kid)
    if kp is None:
        return VerifyResponse(valid=False, alg=alg, kid=kid, error="key_not_found")

    signing_input = f"{h_seg}.{p_seg}".encode("ascii")

    # 3) Verify (with Prometheus timing)
    t0 = time.perf_counter()
    try:
        ok = backend.verify(kp.alg, kp.public_key, signing_input, signature)
        VERIFY_LATENCY_SECONDS.observe(time.perf_counter() - t0)
        dt_ms = (time.perf_counter() - t0) * 1000.0
    except Exception:
        P1_ERRORS_TOTAL.labels(type="verify_error").inc()
        return VerifyResponse(valid=False, alg=alg, kid=kid, error="verify_exception")

    if not ok:
        return VerifyResponse(
            valid=False,
            alg=alg,
            kid=kid,
            verify_time_ms=dt_ms,
            error="signature_invalid",
        )

    return VerifyResponse(
        valid=True,
        alg=alg,
        kid=kid,
        claims=payload,
        verify_time_ms=dt_ms,
    )
