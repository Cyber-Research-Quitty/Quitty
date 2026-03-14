from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.merkle import verify_proof
from app.signer import verify_root_bundle_pinned


# Optional hardcoded fallback. Prefer env var or key file.
PINNED_ROOT_PUB_B64 = "PASTE_THE_ROOT_PUBLIC_KEY_HERE"
DEFAULT_P2_BASE_URL = "http://127.0.0.1:8200"
DEFAULT_KEY_FILE = "./root_signer_key.json"
IGNORED_PINNED_PUB_VALUES = {
    "",
    "string",
    "<base64url root public key>",
    "PASTE_THE_ROOT_PUBLIC_KEY_HERE",
}

app = FastAPI(
    title="Client Verify Service",
    description="Simulated client microservice that verifies E-JWKS keys from P2 using a pinned root public key.",
    version="1.0.0",
)


class VerifyRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "base_url": "http://ejwks-api:8000",
                "key_file": "/data/root_signer_key.json",
            }
        }
    )

    base_url: str = Field(default="http://ejwks-api:8000", description="P2 base URL")
    pinned_pub: str | None = Field(default=None, description="Pinned root public key (base64url)")
    key_file: str = Field(default="/data/root_signer_key.json", description="Path to root signer key JSON file")


class VerifyResponse(BaseModel):
    verified: bool
    kid: str
    jkt: str | None = None
    alg: str | None = None
    kty: str | None = None
    checkpoint_idx: int | None = None
    root_hash: str
    root_epoch: int
    source_base_url: str


def load_pinned_key_from_file(key_path: str) -> str:
    try:
        p = Path(key_path)
        if not p.is_absolute():
            p = (PROJECT_ROOT / p).resolve()
        if not p.exists():
            return ""
        obj = json.loads(p.read_text(encoding="utf-8"))
        if obj.get("alg") == "ml-dsa-44":
            return obj.get("public_key", "")
        return ""
    except Exception:
        return ""


def normalize_pinned_pub(value: str | None) -> str:
    normalized = (value or "").strip()
    if normalized in IGNORED_PINNED_PUB_VALUES:
        return ""
    return normalized


def resolve_pinned_pub(override_pinned_pub: str | None, key_file: str | None) -> str:
    override = normalize_pinned_pub(override_pinned_pub)
    if override:
        return override

    env_pinned = normalize_pinned_pub(os.getenv("CLIENT_VERIFY_PINNED_PUB"))
    if env_pinned:
        return env_pinned

    env_key_file = os.getenv("CLIENT_VERIFY_KEY_FILE", DEFAULT_KEY_FILE)
    key_path = key_file or env_key_file

    key_from_file = normalize_pinned_pub(load_pinned_key_from_file(key_path))
    if key_from_file:
        return key_from_file

    return normalize_pinned_pub(PINNED_ROOT_PUB_B64)


def verify_kid(
    kid: str,
    base_url: str | None = None,
    pinned_pub_override: str | None = None,
    key_file: str | None = None,
) -> VerifyResponse:
    resolved_base_url = (base_url or os.getenv("CLIENT_VERIFY_P2_BASE_URL", DEFAULT_P2_BASE_URL)).rstrip("/")
    pinned_pub = resolve_pinned_pub(pinned_pub_override, key_file)

    if not pinned_pub or pinned_pub == "PASTE_THE_ROOT_PUBLIC_KEY_HERE":
        raise HTTPException(
            status_code=500,
            detail=(
                "No pinned root public key available. Set CLIENT_VERIFY_PINNED_PUB, "
                "provide pinned_pub in request, or configure a valid key file."
            ),
        )

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"{resolved_base_url}/jwks/proof/{kid}")
            response.raise_for_status()
            data: dict[str, Any] = response.json()
    except httpx.HTTPStatusError as exc:
        upstream_status = exc.response.status_code
        raise HTTPException(
            status_code=upstream_status if 400 <= upstream_status < 600 else 502,
            detail=f"P2 returned HTTP {upstream_status} for kid '{kid}'",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to reach P2 service: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=f"Invalid JSON from P2: {exc}") from exc

    root = data.get("root")
    jwk = data.get("jwk")
    proof = data.get("merkle_proof")
    if not root or jwk is None or proof is None:
        raise HTTPException(status_code=400, detail="P2 response missing one of: root, jwk, merkle_proof")

    if not verify_root_bundle_pinned(root, pinned_pub):
        raise HTTPException(status_code=412, detail="Root signature is invalid against pinned key")

    root_hash = root.get("root_hash")
    if not root_hash:
        raise HTTPException(status_code=400, detail="P2 response root bundle missing root_hash")

    if not verify_proof(jwk, proof, expected_root_b64=root_hash):
        raise HTTPException(status_code=412, detail="Merkle proof is invalid for this key")

    return VerifyResponse(
        verified=True,
        kid=data.get("kid", kid),
        jkt=data.get("jkt"),
        alg=jwk.get("alg"),
        kty=jwk.get("kty"),
        checkpoint_idx=data.get("latest_checkpoint_idx"),
        root_hash=root_hash,
        root_epoch=root.get("epoch", 0),
        source_base_url=resolved_base_url,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/verify/{kid}", response_model=VerifyResponse)
def verify_kid_get(kid: str, base_url: str | None = None) -> VerifyResponse:
    return verify_kid(kid=kid, base_url=base_url)


@app.post("/verify/{kid}", response_model=VerifyResponse)
def verify_kid_post(kid: str, req: VerifyRequest) -> VerifyResponse:
    return verify_kid(
        kid=kid,
        base_url=req.base_url,
        pinned_pub_override=req.pinned_pub,
        key_file=req.key_file,
    )
