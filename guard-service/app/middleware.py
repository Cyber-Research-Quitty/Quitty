import base64
import json
import re
import time
from typing import Dict, Optional, Tuple

from app.metrics import (
    jwt_guard_requests_total,
    jwt_guard_reject_total,
    jwt_guard_overhead_ms,
)
from fastapi import status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import CLOCK_SKEW_SECONDS, EXPECTED_AUD, EXPECTED_ISS, MAX_TOKEN_AGE_SECONDS
from .jwks_client import JWKSFetchError, jwks_client
from .revocation_client import RevocationError, revocation_client
from .signer_client import SignerVerifyError, signer_client

# strict base64url charset: A–Z, a–z, 0–9, - and _
BASE64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")

# Allowed algorithms (case-insensitive compare)
ALLOWED_ALGORITHMS = {"ml-dsa-44", "rs256", "es256"}


def _b64url_decode(segment: str) -> bytes:
    if not segment:
        return b""
    if not BASE64URL_RE.fullmatch(segment):
        raise ValueError("invalid base64url characters")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError("invalid base64url") from exc


def _headers_to_dict(scope: Scope) -> Dict[str, str]:
    raw_headers = scope.get("headers") or []
    return {k.decode("latin1").lower(): v.decode("latin1") for k, v in raw_headers}


def _bearer_token_from_auth(auth_header: str) -> Optional[str]:
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header[7:].strip()
    return token if token else None


def _split_jwt(token: str) -> Optional[Tuple[str, str, str]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def _as_int_claim(value: object) -> Optional[int]:
    # accept int, accept float if it is whole-number (JSON numbers)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _log_reject(reason: str, path: str, kid: Optional[str]) -> None:
    # Phase 8: structured logging (reason/path/kid)
    print(
        json.dumps(
            {"event": "jwt_guard_reject", "reason": reason, "path": path, "kid": kid},
            separators=(",", ":"),
        )
    )


class JwtGuardMiddleware:
    """
    Phase 2: Authorization + structural validation
    Phase 3: typ/alg/kid rules + alg:none block + allow-list
    Phase 4: JWKS lookup by kid + alg confusion protection
    Phase 5: Signature verification (P1)
    Phase 6: Claims validation (sub/jti/exp + time checks)
    Phase 7: Revocation check (P4) using jti
    Phase 8: Metrics + structured logging + /metrics bypass
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def _reject(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        error: str,
        reason: str,
    ) -> None:
        # Phase 8: metrics by reason (must match JSON reason 1:1)
        jwt_guard_reject_total.labels(reason=reason).inc()

        path: str = scope.get("path", "")
        kid = scope.get("jwt_kid")
        if not isinstance(kid, str):
            kid = None
        _log_reject(reason=reason, path=path, kid=kid)

        start = scope.get("jwt_guard_start")
        if isinstance(start, (int, float)):
            jwt_guard_overhead_ms.observe((time.perf_counter() - start) * 1000)

        await JSONResponse({"error": error, "reason": reason}, status_code=status_code)(
            scope, receive, send
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Phase 8 requirement: allow /health and /metrics without auth
        if path.startswith("/health") or path.startswith("/metrics"):
            await self.app(scope, receive, send)
            return

        # Phase 8: start timing + count guarded requests
        scope["jwt_guard_start"] = time.perf_counter()
        jwt_guard_requests_total.inc()

        headers = _headers_to_dict(scope)
        auth_header = headers.get("authorization")

        # ---------------- PHASE 2: Authorization ----------------
        if not auth_header:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="missing_authorization_header",
            )
            return

        token = _bearer_token_from_auth(auth_header)
        if token is None:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="invalid_auth_scheme",
            )
            return

        scope["jwt_raw_token"] = token

        # ---------------- PHASE 2: Structure ----------------
        split = _split_jwt(token)
        if split is None:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="invalid_segment_count",
            )
            return

        header_b64, payload_b64, signature_b64 = split

        if not signature_b64:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="empty_signature",
            )
            return

        try:
            header_bytes = _b64url_decode(header_b64)
            payload_bytes = _b64url_decode(payload_b64)
        except ValueError:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="malformed_base64",
            )
            return

        try:
            header = json.loads(header_bytes.decode("utf-8"))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="malformed_json",
            )
            return

        # ---------------- PHASE 3: Header policy ----------------
        if not isinstance(header, dict):
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="header_not_object",
            )
            return

        typ = header.get("typ")
        alg = header.get("alg")
        kid = header.get("kid")

        if typ != "JWT":
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="invalid_typ",
            )
            return

        if not isinstance(alg, str) or not alg:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_alg",
            )
            return

        if not isinstance(kid, str) or not kid:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_kid",
            )
            return

        # Phase 8: store kid for reject logs
        scope["jwt_kid"] = kid

        alg_norm = alg.lower()

        if alg_norm == "none":
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="alg_none_not_allowed",
            )
            return

        if alg_norm not in ALLOWED_ALGORITHMS:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="unsupported_algorithm",
            )
            return

        # ---------------- PHASE 4: JWKS lookup ----------------
        try:
            jwk = await jwks_client.get_key_by_kid(kid)
        except JWKSFetchError:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                error="service_unavailable",
                reason="jwks_unavailable",
            )
            return

        if jwk is None:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="kid_not_found",
            )
            return

        jwk_alg = jwk.get("alg")
        if isinstance(jwk_alg, str) and jwk_alg and jwk_alg.lower() != alg_norm:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="alg_confusion",
            )
            return

        # ---------------- PHASE 5: P1 signature verify ----------------
        try:
            verify_result = await signer_client.verify(token)
        except SignerVerifyError:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                error="service_unavailable",
                reason="signer_unavailable",
            )
            return

        if not bool(verify_result.get("valid")):
            reason = verify_result.get("reason")
            if not isinstance(reason, str) or not reason:
                reason = "signature_invalid"
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason=reason,
            )
            return

        # ---------------- PHASE 6: claims validation ----------------
        if not isinstance(payload, dict):
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="claims_not_object",
            )
            return

        sub = payload.get("sub")
        jti = payload.get("jti")
        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")

        if not isinstance(sub, str) or not sub:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_sub",
            )
            return

        if not isinstance(jti, str) or not jti:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_jti",
            )
            return

        exp_i = _as_int_claim(exp)
        if exp_i is None:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_or_invalid_exp",
            )
            return

        now = int(time.time())
        leeway = max(0, int(CLOCK_SKEW_SECONDS))

        if exp_i <= (now - leeway):
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="token_expired",
            )
            return

        if iat is not None:
            iat_i = _as_int_claim(iat)
            if iat_i is None:
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error="malformed_token",
                    reason="invalid_iat",
                )
                return
            if iat_i > (now + leeway):
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    error="invalid_token",
                    reason="iat_in_future",
                )
                return

            if MAX_TOKEN_AGE_SECONDS and int(MAX_TOKEN_AGE_SECONDS) > 0:
                if (now - iat_i) > int(MAX_TOKEN_AGE_SECONDS) + leeway:
                    await self._reject(
                        scope,
                        receive,
                        send,
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        error="invalid_token",
                        reason="token_too_old",
                    )
                    return

        if nbf is not None:
            nbf_i = _as_int_claim(nbf)
            if nbf_i is None:
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error="malformed_token",
                    reason="invalid_nbf",
                )
                return
            if nbf_i > (now + leeway):
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    error="invalid_token",
                    reason="nbf_in_future",
                )
                return

        if EXPECTED_ISS:
            if payload.get("iss") != EXPECTED_ISS:
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    error="invalid_token",
                    reason="invalid_iss",
                )
                return

        if EXPECTED_AUD:
            aud = payload.get("aud")
            ok = False
            if isinstance(aud, str) and aud == EXPECTED_AUD:
                ok = True
            if isinstance(aud, list) and EXPECTED_AUD in aud:
                ok = True
            if not ok:
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    error="invalid_token",
                    reason="invalid_aud",
                )
                return

        # ---------------- PHASE 7: revocation check (P4) ----------------
        try:
            rev = await revocation_client.is_revoked(jti)
        except RevocationError:
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                error="service_unavailable",
                reason="revocation_unavailable",
            )
            return

        if bool(rev.get("revoked")):
            await self._reject(
                scope,
                receive,
                send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="token_revoked",
            )
            return

        # attach for debugging / downstream
        scope["jwt_header"] = header
        scope["jwt_payload"] = payload
        scope["jwk"] = jwk
        scope["jwt_verified"] = True
        scope["jwt_claims_ok"] = True
        scope["jwt_revoked"] = False

        # success path: forward request + record overhead
        try:
            await self.app(scope, receive, send)
        finally:
            start = scope.get("jwt_guard_start")
            if isinstance(start, (int, float)):
                jwt_guard_overhead_ms.observe((time.perf_counter() - start) * 1000)