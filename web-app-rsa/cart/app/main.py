import os
from typing import Annotated, Optional

import httpx
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
JWT_PUBLIC_KEY = os.getenv(
    "JWT_PUBLIC_KEY",
    """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwgYXTInrNc90OpHbRnzZ
J6+X71YutxIhmiU8NByHp4/nvXRgtKT8CA7Uf2/Qfo+hYVsdo9i99El/TcTU2cJn
lwUV0SO46HLLJK0uPFvNcAfpOM9YqNMcHaPX8/JWWVlnVr3yaNcmpWURKA2F5Slo
b41N4F0IiYh1uqDwipsM8+mcUsfpzzP4amD7XLl5zIykV+Ut9jec/gKlM7zOSwrz
gXhJH9qGRwoyPXZxN9GdF0mb7e7hs1Omo5hunzmOPOPM0sfxAVx0zyUMkjvkMN7n
yU3z5W109aXXQRYNoMFWz/9PruaUUNAmT/KqaXxAxC0/DVeuO1wqgwdIXDCHXNld
xQIDAQAB
-----END PUBLIC KEY-----
""",
)
DB_SERVICE_URL = os.getenv("DB_SERVICE_URL", "http://db:8002")


def normalize_pem(pem: str) -> str:
    return pem.replace("\\n", "\n").strip() + "\n"


JWT_PUBLIC_KEY = normalize_pem(JWT_PUBLIC_KEY)


def get_verification_key() -> str:
    if JWT_ALGORITHM.upper().startswith("RS"):
        return JWT_PUBLIC_KEY
    return JWT_SECRET

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
        return jwt.decode(token, get_verification_key(), algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


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
