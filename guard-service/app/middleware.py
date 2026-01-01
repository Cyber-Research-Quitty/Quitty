import base64
import json
import re
import time
from typing import Dict, Optional, Tuple

from fastapi import status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import CLOCK_SKEW_SECONDS, EXPECTED_AUD, EXPECTED_ISS, MAX_TOKEN_AGE_SECONDS
from .jwks_client import JWKSFetchError, jwks_client
from .signer_client import SignerVerifyError, signer_client

BASE64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")
ALLOWED_ALGORITHMS = {"ml-dsa-44", "rs256", "es256"}  # case-insensitive compare


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
    # JSON numbers are int or float in Python; accept int, accept float if whole
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


class JwtGuardMiddleware:
    """
    Phase 2: Authorization + structural validation
    Phase 3: typ/alg/kid rules + alg:none block + allow-list
    Phase 4: P2 JWKS lookup by kid + alg confusion protection
    Phase 5: P1 signature verification call
    Phase 6: Claims validation (sub/jti/exp + time-based checks)
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def _reject(self, scope: Scope, receive: Receive, send: Send, *,
                      status_code: int, error: str, reason: str) -> None:
        await JSONResponse({"error": error, "reason": reason}, status_code=status_code)(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        if path.startswith("/health"):
            await self.app(scope, receive, send)
            return

        headers = _headers_to_dict(scope)
        auth_header = headers.get("authorization")

        # ---------------- PHASE 2: Authorization ----------------
        if not auth_header:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="missing_authorization_header",
            )
            return

        token = _bearer_token_from_auth(auth_header)
        if token is None:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="invalid_auth_scheme",
            )
            return

        scope["jwt_raw_token"] = token

        # ---------------- PHASE 2: Structural validation ----------------
        split = _split_jwt(token)
        if split is None:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="invalid_segment_count",
            )
            return

        header_b64, payload_b64, signature_b64 = split

        if not signature_b64:
            await self._reject(
                scope, receive, send,
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
                scope, receive, send,
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
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="malformed_json",
            )
            return

        # ---------------- PHASE 3: Header rules + allow-list ----------------
        if not isinstance(header, dict):
            await self._reject(
                scope, receive, send,
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
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="invalid_typ",
            )
            return

        if not isinstance(alg, str) or not alg:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_alg",
            )
            return

        if not isinstance(kid, str) or not kid:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_kid",
            )
            return

        alg_norm = alg.lower()

        if alg_norm == "none":
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="alg_none_not_allowed",
            )
            return

        if alg_norm not in ALLOWED_ALGORITHMS:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="unsupported_algorithm",
            )
            return

        # ---------------- PHASE 4: P2 JWKS lookup ----------------
        try:
            jwk = await jwks_client.get_key_by_kid(kid)
        except JWKSFetchError:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                error="service_unavailable",
                reason="jwks_unavailable",
            )
            return

        if jwk is None:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="kid_not_found",
            )
            return

        jwk_alg = jwk.get("alg")
        if isinstance(jwk_alg, str) and jwk_alg and jwk_alg.lower() != alg_norm:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="alg_confusion",
            )
            return

        # ---------------- PHASE 5: P1 verify ----------------
        try:
            verify_result = await signer_client.verify(token)
        except SignerVerifyError:
            await self._reject(
                scope, receive, send,
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
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason=reason,
            )
            return

        # ---------------- PHASE 6: Claims validation ----------------
        if not isinstance(payload, dict):
            await self._reject(
                scope, receive, send,
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
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_sub",
            )
            return

        if not isinstance(jti, str) or not jti:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_jti",
            )
            return

        exp_i = _as_int_claim(exp)
        if exp_i is None:
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_400_BAD_REQUEST,
                error="malformed_token",
                reason="missing_or_invalid_exp",
            )
            return

        now = int(time.time())
        leeway = max(0, int(CLOCK_SKEW_SECONDS))

        # expired?
        if exp_i <= (now - leeway):
            await self._reject(
                scope, receive, send,
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                reason="token_expired",
            )
            return

        # iat sanity (optional)
        if iat is not None:
            iat_i = _as_int_claim(iat)
            if iat_i is None:
                await self._reject(
                    scope, receive, send,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error="malformed_token",
                    reason="invalid_iat",
                )
                return
            if iat_i > (now + leeway):
                await self._reject(
                    scope, receive, send,
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    error="invalid_token",
                    reason="iat_in_future",
                )
                return

            # max age (optional)
            if MAX_TOKEN_AGE_SECONDS and MAX_TOKEN_AGE_SECONDS > 0:
                if (now - iat_i) > int(MAX_TOKEN_AGE_SECONDS) + leeway:
                    await self._reject(
                        scope, receive, send,
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        error="invalid_token",
                        reason="token_too_old",
                    )
                    return

        # nbf check (optional)
        if nbf is not None:
            nbf_i = _as_int_claim(nbf)
            if nbf_i is None:
                await self._reject(
                    scope, receive, send,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error="malformed_token",
                    reason="invalid_nbf",
                )
                return
            if nbf_i > (now + leeway):
                await self._reject(
                    scope, receive, send,
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    error="invalid_token",
                    reason="nbf_in_future",
                )
                return

        # iss / aud enforcement only if configured
        if EXPECTED_ISS:
            if payload.get("iss") != EXPECTED_ISS:
                await self._reject(
                    scope, receive, send,
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
                    scope, receive, send,
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    error="invalid_token",
                    reason="invalid_aud",
                )
                return

        # Attach for later phases
        scope["jwt_header"] = header
        scope["jwt_payload"] = payload
        scope["jwk"] = jwk
        scope["jwt_verified"] = True
        scope["jwt_claims_ok"] = True

        await self.app(scope, receive, send)
