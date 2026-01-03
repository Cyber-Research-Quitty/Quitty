import time

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import generate_latest

from .config import settings
from .routes_sign import router as sign_router
from .routes_verify import router as verify_router
from .metrics import HTTP_REQUESTS_TOTAL, HTTP_REQUEST_LATENCY_SECONDS

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="P1 service: PQC JWT sign & verify (ML-DSA-44/65).",
)

app.include_router(sign_router)
app.include_router(verify_router)


@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method

    HTTP_REQUESTS_TOTAL.labels(method=method, path=path).inc()

    start = time.perf_counter()
    try:
        response = await call_next(request)
        return response
    finally:
        elapsed = time.perf_counter() - start
        HTTP_REQUEST_LATENCY_SECONDS.labels(path=path).observe(elapsed)


@app.get("/metrics", response_class=PlainTextResponse, tags=["internal"])
def metrics():
    # Prometheus scraping endpoint
    return PlainTextResponse(generate_latest().decode("utf-8"))


@app.get("/health", tags=["internal"])
def health():
    return {
        "status": "ok",
        "component": "P1",
        "environment": settings.environment,
        "default_alg": settings.default_alg,
    }
