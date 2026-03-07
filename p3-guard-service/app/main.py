from fastapi import FastAPI
from .middleware import JwtGuardMiddleware
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

def create_app() -> FastAPI:
    app = FastAPI(title="P3 - JWT Guard Service")

    # register middleware
    app.add_middleware(JwtGuardMiddleware)

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "component": "p3-guard"}

    # ✅ Phase 8: Prometheus metrics (must be NOT guarded)
    @app.get("/metrics")
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app

app = create_app()