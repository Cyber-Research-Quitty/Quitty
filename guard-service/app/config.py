import os
from dotenv import load_dotenv

load_dotenv()  # loads guard-service/.env if present


def _split_csv(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


# P2 JWKS Service base URL (change later without touching code)
JWKS_BASE_URL = os.getenv("JWKS_BASE_URL", "http://127.0.0.1:8001")

# Try these paths in order (supports different teammate implementations)
JWKS_PATHS = _split_csv(os.getenv("JWKS_PATHS", "/.well-known/jwks.json,/jwks.json,/jwks"))

# Cache TTL to avoid calling P2 every request
JWKS_CACHE_TTL_SECONDS = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "60"))

# HTTP timeout seconds
JWKS_TIMEOUT_SECONDS = float(os.getenv("JWKS_TIMEOUT_SECONDS", "3"))
