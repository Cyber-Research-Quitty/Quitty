from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel

from .jose_utils import split_jws, decode_segment, b64url_decode
from .keystore import keystore
from .backend_factory import get_backend
from .metrics import VERIFY_LATENCY_SECONDS, P1_ERRORS_TOTAL

router = APIRouter(prefix="/verify", tags=["verify"])


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
    try:
        h_seg, p_seg, s_seg = split_jws(body.token)
        header = decode_segment(h_seg)
        payload = decode_segment(p_seg)
        signature = b64url_decode(s_seg)
    except Exception:
        P1_ERRORS_TOTAL.labels(type="malformed_token").inc()
        return VerifyResponse(valid=False, error="malformed_token")

    alg = header.get("alg")
    kid = header.get("kid")
    if not alg or not kid:
        P1_ERRORS_TOTAL.labels(type="missing_alg_or_kid").inc()
        return VerifyResponse(valid=False, error="missing_alg_or_kid")

    kp = keystore.get(kid)
    if kp is None:
        P1_ERRORS_TOTAL.labels(type="key_not_found").inc()
        return VerifyResponse(valid=False, alg=alg, kid=kid, error="key_not_found")

    try:
        backend = get_backend(kp.alg)
    except Exception:
        P1_ERRORS_TOTAL.labels(type="alg_not_implemented").inc()
        return VerifyResponse(valid=False, alg=alg, kid=kid, error="alg_not_implemented")

    signing_input = f"{h_seg}.{p_seg}".encode("ascii")

    t0 = time.perf_counter()
    ok = backend.verify(kp.alg, kp.public_key, signing_input, signature)
    elapsed = time.perf_counter() - t0

    VERIFY_LATENCY_SECONDS.observe(elapsed)
    dt_ms = elapsed * 1000.0

    if not ok:
        P1_ERRORS_TOTAL.labels(type="signature_invalid").inc()
        return VerifyResponse(valid=False, alg=alg, kid=kid, verify_time_ms=dt_ms, error="signature_invalid")

    return VerifyResponse(valid=True, alg=alg, kid=kid, claims=payload, verify_time_ms=dt_ms)
