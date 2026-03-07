import os
from typing import Annotated, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_SERVICE_URL = os.getenv("DB_SERVICE_URL", "http://db:8002")
P3_VALIDATE_URL = os.getenv("P3_VALIDATE_URL", "http://host.docker.internal:8300/guard/validate")
TOKEN_TIMEOUT_SECONDS = float(os.getenv("TOKEN_TIMEOUT_SECONDS", "5"))

app = FastAPI(title="cart-service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CartItemCreate(BaseModel):
    product_name: str
    quantity: int
    price: float


async def get_current_user(authorization: Annotated[Optional[str], Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1]
    try:
        async with httpx.AsyncClient(timeout=TOKEN_TIMEOUT_SECONDS) as client:
            response = await client.get(
                P3_VALIDATE_URL,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (400, 401):
            raise HTTPException(status_code=401, detail="Invalid token") from exc
        raise HTTPException(status_code=503, detail="P3 guard unavailable") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail="P3 guard unavailable") from exc

    body = response.json()
    if not body.get("valid"):
        raise HTTPException(status_code=401, detail="Invalid token")
    claims = body.get("claims")
    if not isinstance(claims, dict):
        raise HTTPException(status_code=401, detail="Invalid token claims")
    return claims


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/cart")
async def get_cart(current_user: dict = Depends(get_current_user)) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{DB_SERVICE_URL}/cart/{current_user['sub']}")
        response.raise_for_status()
        return response.json()


@app.post("/cart")
async def add_to_cart(payload: CartItemCreate, current_user: dict = Depends(get_current_user)) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{DB_SERVICE_URL}/cart",
            json={
                "user_id": current_user["sub"],
                "product_name": payload.product_name,
                "quantity": payload.quantity,
                "price": payload.price,
            },
        )
        response.raise_for_status()
        return response.json()


@app.delete("/cart/{item_id}")
async def delete_item(item_id: int, current_user: dict = Depends(get_current_user)) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.delete(f"{DB_SERVICE_URL}/cart/{current_user['sub']}/{item_id}")
        response.raise_for_status()
        return response.json()
