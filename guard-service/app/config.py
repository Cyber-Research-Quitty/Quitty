import os
from dotenv import load_dotenv

load_dotenv()  # loads guard-service/.env if present


def _split_csv(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


# ----------------------
# P2 (JWKS) configuration
# ----------------------

JWKS_BASE_URL = os.getenv("JWKS_BASE_URL", "http://127.0.0.1:8001")

JWKS_PATHS = _split_csv(
    os.getenv("JWKS_PATHS", "/.well-known/jwks.json,/jwks.json,/jwks")
)

JWKS_CACHE_TTL_SECONDS = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "60"))

JWKS_TIMEOUT_SECONDS = float(os.getenv("JWKS_TIMEOUT_SECONDS", "3"))


# ----------------------
# P1 (Signer) configuration
# ----------------------

SIGNER_BASE_URL = os.getenv("SIGNER_BASE_URL", "http://127.0.0.1:8002")

SIGNER_VERIFY_PATHS = _split_csv(
    os.getenv("SIGNER_VERIFY_PATHS", "/v1/jwt/verify,/verify")
)

SIGNER_TIMEOUT_SECONDS = float(os.getenv("SIGNER_TIMEOUT_SECONDS", "3"))
