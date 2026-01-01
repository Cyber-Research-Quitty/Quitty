from fastapi import FastAPI

from .config import settings
from .routes_sign import router as sign_router
from .routes_verify import router as verify_router


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="P1 service: PQC JWT sign & verify (ML-DSA-44/65).",
)

# include /sign endpoints
app.include_router(sign_router)
app.include_router(verify_router)

@app.get("/health", tags=["internal"])
def health():
    """
    Simple health-check endpoint so we know the P1 service is alive.
    """
    return {
        "status": "ok",
        "component": "P1",
        "environment": settings.environment,
        "default_alg": settings.default_alg,
    }
