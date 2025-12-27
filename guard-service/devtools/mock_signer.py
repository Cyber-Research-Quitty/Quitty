from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mock P1 Sign/Verify Service")


class VerifyRequest(BaseModel):
    token: str


@app.get("/health")
async def health():
    return {"status": "ok", "component": "mock-signer"}


# Main contract endpoint
@app.post("/v1/jwt/verify")
async def verify(req: VerifyRequest):
    # very simple fake logic for testing:
    # if token signature segment == "xxx" -> valid
    # otherwise invalid
    parts = req.token.split(".")
    if len(parts) != 3:
        return {"valid": False, "reason": "invalid_segment_count"}

    signature = parts[2]
    if signature == "xxx":
        return {"valid": True}
    return {"valid": False, "reason": "signature_invalid"}


# fallback endpoint in case teammate uses /verify
@app.post("/verify")
async def verify_alt(req: VerifyRequest):
    return await verify(req)
