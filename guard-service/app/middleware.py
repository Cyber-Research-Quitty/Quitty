import base64
import json
import re
from typing import Dict

from fastapi import status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .jwks_client import JWKSFetchError, jwks_client

# strict base64url regex: only A–Z, a–z, 0–9, - and _
BASE64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")

# Allowed algorithms according to your P3 component spec (case-insensitive)
ALLOWED_ALGORITHMS = {"ml-dsa-44", "rs256", "es256"}


def _b64url_decode(segment: str) -> bytes:
    """
    Strict base64url decoder:
      - only allows characters A–Z, a–z, 0–9, - and _
      - fixes missing padding
      - raises ValueError on invalid characters or format
    """
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
    P3 JWT Guard middleware – PHASE 2 + PHASE 3 + PHASE 4

    Phase 2:
      - Authorization: Bearer <token>
      - Structural validation (3 segments, non-empty signature, base64url+json)

    Phase 3:
      - Header rules: typ="JWT", alg exists, kid exists
      - Block alg="none"
      - Allow-list alg: ml-dsa-44, RS256, ES256

    Phase 4:
      - Fetch JWKS key by kid from P2
      - If kid not found -> 401 kid_not_found
      - If jwk.alg exists and mismatches token alg -> 401 alg_confusion
      - If JWKS unavailable -> 503 jwks_unavailable
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

        # Build headers dict
        raw_headers = scope.get("headers") or []
        headers: Dict[str, str] = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in raw_headers
        }

        auth_header = headers.get("authorization")

        # ---------------- PHASE 2: Authorization ----------------
        if not auth_header:
            response = JSONResponse(
                {"error": "invalid_token", "reason": "missing_authorization_header"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        if not auth_header.lower().startswith("bearer "):
            response = JSONResponse(
                {"error": "invalid_token", "reason": "invalid_auth_scheme"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        token = auth_header[7:].strip()
        if not token:
            response = JSONResponse(
                {"error": "invalid_token", "reason": "empty_bearer_token"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        scope["jwt_raw_token"] = token

        # ---------------- PHASE 2: Structural validation ----------------
        parts = token.split(".")
        if len(parts) != 3:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "invalid_segment_count"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        header_b64, payload_b64, signature_b64 = parts

        if not signature_b64:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "empty_signature"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        try:
            header_bytes = _b64url_decode(header_b64)
            payload_bytes = _b64url_decode(payload_b64)
        except ValueError:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "malformed_base64"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        try:
            header = json.loads(header_bytes.decode("utf-8"))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            response = JSONResponse(
                {"error": "malformed_token", "reason": "malformed_json"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        # ---------------- PHASE 3: Header rules + allow-list ----------------
        if not isinstance(header, dict):
            response = JSONResponse(
                {"error": "malformed_token", "reason": "header_not_object"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        typ = header.get("typ")
        alg = header.get("alg")
        kid = header.get("kid")

        if typ != "JWT":
            response = JSONResponse(
                {"error": "malformed_token", "reason": "invalid_typ"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        if not isinstance(alg, str) or not alg:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "missing_alg"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        if not isinstance(kid, str) or not kid:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "missing_kid"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        alg_norm = alg.lower()

        if alg_norm == "none":
            response = JSONResponse(
                {"error": "invalid_token", "reason": "alg_none_not_allowed"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        if alg_norm not in ALLOWED_ALGORITHMS:
            response = JSONResponse(
                {"error": "invalid_token", "reason": "unsupported_algorithm"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        # ---------------- PHASE 4: Fetch JWKS key by kid (P2) ----------------
        try:
            jwk = await jwks_client.get_key_by_kid(kid)
        except JWKSFetchError:
            response = JSONResponse(
                {"error": "service_unavailable", "reason": "jwks_unavailable"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
            await response(scope, receive, send)
            return

        if jwk is None:
            response = JSONResponse(
                {"error": "invalid_token", "reason": "kid_not_found"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        # Alg confusion protection (only if JWKS key provides alg)
        jwk_alg = jwk.get("alg")
        if isinstance(jwk_alg, str) and jwk_alg:
            if jwk_alg.lower() != alg_norm:
                response = JSONResponse(
                    {"error": "invalid_token", "reason": "alg_confusion"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
                await response(scope, receive, send)
                return

        # Attach for later phases (P1 verify + P4 revoke)
        scope["jwt_header"] = header
        scope["jwt_payload"] = payload
        scope["jwk"] = jwk

        await self.app(scope, receive, send)
