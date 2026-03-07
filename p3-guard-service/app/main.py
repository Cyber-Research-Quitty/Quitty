from fastapi import FastAPI, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .middleware import JwtGuardMiddleware


def create_app() -> FastAPI:
    app = FastAPI(title="P3 - JWT Guard Service")

    # register middleware
    app.add_middleware(JwtGuardMiddleware)

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "component": "p3-guard"}

    @app.get("/guard/validate")
    async def guard_validate(request: Request):
        payload = request.scope.get("jwt_payload")
        header = request.scope.get("jwt_header")
        return {
            "valid": True,
            "claims": payload if isinstance(payload, dict) else {},
            "header": header if isinstance(header, dict) else {},
        }

    @app.get("/metrics")
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
