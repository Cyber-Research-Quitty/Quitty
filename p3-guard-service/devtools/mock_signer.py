from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mock P1 Sign/Verify Service")


class VerifyRequest(BaseModel):
    token: str


@app.post("/v1/jwt/verify")
async def verify(req: VerifyRequest):
    parts = req.token.split(".")
    if len(parts) != 3:
        return {"valid": False, "reason": "invalid_segment_count"}

    # test rule:
    # signature == "xxx" => valid
    # else invalid
    if parts[2] == "xxx":
        return {"valid": True}
    return {"valid": False, "reason": "signature_invalid"}


@app.post("/verify")
async def verify_alt(req: VerifyRequest):
    return await verify(req)
