import base64
import json
import re
from typing import Dict

from fastapi import status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

# strict base64url regex: only A–Z, a–z, 0–9, - and _
BASE64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")

# Allowed algorithms according to your P3 component spec
# We normalize to lowercase for comparison.
ALLOWED_ALGORITHMS = {"ml-dsa-44", "rs256", "es256"}


def _b64url_decode(segment: str) -> bytes:
    """
    Strict base64url decoder:
      - only allows characters A–Z, a–z, 0–9, - and _
      - fixes missing padding
      - raises ValueError on any invalid character or format
    """
    if not segment:
        # empty segment is allowed here; caller decides if that's valid
        return b""

    if not BASE64URL_RE.fullmatch(segment):
        # contains characters outside base64url alphabet
        raise ValueError("invalid base64url characters")

    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError("invalid base64url") from exc


class JwtGuardMiddleware:
    """
    P3 JWT Guard middleware – PHASE 2 + PHASE 3

    PHASE 2 (already done):
      - Allow /health without any auth
      - For all other paths:
          * Require Authorization: Bearer <token>
          * Basic JWT structural validation:
              - 3 segments: header.payload.signature
              - non-empty signature
              - header & payload are valid base64url-encoded JSON
      - Attaches:
          * scope["jwt_raw_token"]
          * scope["jwt_header"]
          * scope["jwt_payload"]

    PHASE 3 (new now):
      - Header rules:
          * typ must be "JWT"
          * alg must exist
          * kid must exist
      - Algorithm policy:
          * block alg = "none"
          * algorithm must be in allow-list:
              { "ml-dsa-44", "RS256", "ES256" }
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # only guard HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # 1) let health-check pass without auth
        if path.startswith("/health"):
            await self.app(scope, receive, send)
            return

        # 2) collect headers into a dict
        raw_headers = scope.get("headers") or []
        headers: Dict[str, str] = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in raw_headers
        }

        auth_header = headers.get("authorization")

        # --- Authorization header rules (PHASE 2 part 1) ---

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

        token = auth_header[7:].strip()  # strip off "Bearer "

        if not token:
            response = JSONResponse(
                {"error": "invalid_token", "reason": "empty_bearer_token"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        # store raw token for later phases
        scope["jwt_raw_token"] = token

        # --- JWT structural validation (PHASE 2 part 2) ---

        # 3) structural check: 3 segments
        parts = token.split(".")
        if len(parts) != 3:
            response = JSONResponse(
                {
                    "error": "malformed_token",
                    "reason": "invalid_segment_count",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        header_b64, payload_b64, signature_b64 = parts

        # non-empty signature
        if not signature_b64:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "empty_signature"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        # 4) base64url decode header & payload
        try:
            header_bytes = _b64url_decode(header_b64)
            payload_bytes = _b64url_decode(payload_b64)
        except ValueError:
            # base64url decoding itself failed
            response = JSONResponse(
                {"error": "malformed_token", "reason": "malformed_base64"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        # 5) parse JSON (and handle bad UTF-8)
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

        # --- Header rules & algorithm policy (PHASE 3) ---

        # header must be a JSON object
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

        # typ must be "JWT"
        if typ != "JWT":
            response = JSONResponse(
                {"error": "malformed_token", "reason": "invalid_typ"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        # alg must exist and be a non-empty string
        if not isinstance(alg, str) or not alg:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "missing_alg"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        # kid must exist and be a non-empty string
        if not isinstance(kid, str) or not kid:
            response = JSONResponse(
                {"error": "malformed_token", "reason": "missing_kid"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        alg_normalized = alg.lower()

        # block alg:none explicitly
        if alg_normalized == "none":
            response = JSONResponse(
                {"error": "invalid_token", "reason": "alg_none_not_allowed"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        # enforce allow-list
        if alg_normalized not in ALLOWED_ALGORITHMS:
            response = JSONResponse(
                {"error": "invalid_token", "reason": "unsupported_algorithm"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            await response(scope, receive, send)
            return

        # attach parsed parts to scope for later phases
        scope["jwt_header"] = header
        scope["jwt_payload"] = payload

        # continue to the next app (your FastAPI app / downstream service)
        await self.app(scope, receive, send)
