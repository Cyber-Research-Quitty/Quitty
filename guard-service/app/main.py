from fastapi import FastAPI
from .middleware import JwtGuardMiddleware


def create_app() -> FastAPI:
    app = FastAPI(title="P3 - JWT Guard Service")

    # register your middleware (right now it just passes through)
    app.add_middleware(JwtGuardMiddleware)

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "component": "P3-guard"}

    return app


app = create_app()
