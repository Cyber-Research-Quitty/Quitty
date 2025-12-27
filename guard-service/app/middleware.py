import base64
import json
import re
from typing import Dict

from fastapi import status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

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


class JwtGuardMiddleware:
    """
    PHASE 2: Authorization + structural validation
    PHASE 3: typ/alg/kid rules + alg:none block + allow-list
    PHASE 4: P2 JWKS lookup by kid + alg confusion protection
    PHASE 5: P1 signature verification call
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Allow /health without auth
        if path.startswith("/health"):
            await self.app(scope, receive, send)
            return

        # Headers dict
        raw_headers = scope.get("headers") or []
        headers: Dict[str, str] = {
            k.decode("latin1").lower(): v.decode("latin1") for k, v in raw_headers
        }

        auth_header = headers.get("authorization")

        # ---------------- PHASE 2: Authorization ----------------
        if not auth_header:
            await JSONResponse(
                {"error": "invalid_token", "reason": "missing_authorization_header"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        if not auth_header.lower().startswith("bearer "):
            await JSONResponse(
                {"error": "invalid_token", "reason": "invalid_auth_scheme"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        token = auth_header[7:].strip()
        if not token:
            await JSONResponse(
                {"error": "invalid_token", "reason": "empty_bearer_token"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        scope["jwt_raw_token"] = token

        # ---------------- PHASE 2: Structural validation ----------------
        parts = token.split(".")
        if len(parts) != 3:
            await JSONResponse(
                {"error": "malformed_token", "reason": "invalid_segment_count"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        header_b64, payload_b64, signature_b64 = parts

        if not signature_b64:
            await JSONResponse(
                {"error": "malformed_token", "reason": "empty_signature"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        try:
            header_bytes = _b64url_decode(header_b64)
            payload_bytes = _b64url_decode(payload_b64)
        except ValueError:
            await JSONResponse(
                {"error": "malformed_token", "reason": "malformed_base64"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        try:
            header = json.loads(header_bytes.decode("utf-8"))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            await JSONResponse(
                {"error": "malformed_token", "reason": "malformed_json"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        # ---------------- PHASE 3: Header rules + allow-list ----------------
        if not isinstance(header, dict):
            await JSONResponse(
                {"error": "malformed_token", "reason": "header_not_object"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        typ = header.get("typ")
        alg = header.get("alg")
        kid = header.get("kid")

        if typ != "JWT":
            await JSONResponse(
                {"error": "malformed_token", "reason": "invalid_typ"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        if not isinstance(alg, str) or not alg:
            await JSONResponse(
                {"error": "malformed_token", "reason": "missing_alg"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        if not isinstance(kid, str) or not kid:
            await JSONResponse(
                {"error": "malformed_token", "reason": "missing_kid"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )(scope, receive, send)
            return

        alg_norm = alg.lower()

        if alg_norm == "none":
            await JSONResponse(
                {"error": "invalid_token", "reason": "alg_none_not_allowed"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        if alg_norm not in ALLOWED_ALGORITHMS:
            await JSONResponse(
                {"error": "invalid_token", "reason": "unsupported_algorithm"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        # ---------------- PHASE 4: P2 JWKS lookup ----------------
        try:
            jwk = await jwks_client.get_key_by_kid(kid)
        except JWKSFetchError:
            await JSONResponse(
                {"error": "service_unavailable", "reason": "jwks_unavailable"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )(scope, receive, send)
            return

        if jwk is None:
            await JSONResponse(
                {"error": "invalid_token", "reason": "kid_not_found"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        jwk_alg = jwk.get("alg")
        if isinstance(jwk_alg, str) and jwk_alg and jwk_alg.lower() != alg_norm:
            await JSONResponse(
                {"error": "invalid_token", "reason": "alg_confusion"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        # ---------------- PHASE 5: Call P1 verify ----------------
        try:
            verify_result = await signer_client.verify(token)
        except SignerVerifyError:
            await JSONResponse(
                {"error": "service_unavailable", "reason": "signer_unavailable"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )(scope, receive, send)
            return

        valid = bool(verify_result.get("valid"))
        if not valid:
            # allow signer to provide specific reason, fallback to signature_invalid
            reason = verify_result.get("reason") if isinstance(verify_result.get("reason"), str) else "signature_invalid"
            await JSONResponse(
                {"error": "invalid_token", "reason": reason},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )(scope, receive, send)
            return

        # Attach for later phases
        scope["jwt_header"] = header
        scope["jwt_payload"] = payload
        scope["jwk"] = jwk
        scope["jwt_verified"] = True

        await self.app(scope, receive, send)
