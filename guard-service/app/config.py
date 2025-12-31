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

# ----------------------
# Phase 6 (Claims) configuration
# ----------------------

CLOCK_SKEW_SECONDS = int(os.getenv("CLOCK_SKEW_SECONDS", "30"))  # leeway for iat/nbf/exp

EXPECTED_ISS = os.getenv("EXPECTED_ISS", "")  # empty = don't enforce
EXPECTED_AUD = os.getenv("EXPECTED_AUD", "")  # empty = don't enforce

MAX_TOKEN_AGE_SECONDS = int(os.getenv("MAX_TOKEN_AGE_SECONDS", "0"))  # 0 = don't enforce
