from fastapi import FastAPI

app = FastAPI(title="Mock P4 Revocation Service")

# Simple in-memory revoked list (for testing)
REVOKED = {"revoked-1", "bad-jti"}


@app.get("/health")
async def health():
    return {"status": "ok", "component": "mock-revocation"}


@app.get("/v1/revocations/{jti}")
async def check(jti: str):
    if jti in REVOKED:
        return {"jti": jti, "revoked": True, "revokedAt": "2025-12-01T10:00:00Z"}
    return {"jti": jti, "revoked": False, "revokedAt": None}
