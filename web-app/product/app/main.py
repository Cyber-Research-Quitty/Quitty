import os
from typing import Annotated, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

P3_VALIDATE_URL = os.getenv("P3_VALIDATE_URL", "http://host.docker.internal:8300/guard/validate")
TOKEN_TIMEOUT_SECONDS = float(os.getenv("TOKEN_TIMEOUT_SECONDS", "5"))

app = FastAPI(title="product-service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

PRODUCTS = [
    {
        "id": 1,
        "name": "Noise-Cancel Headphones",
        "price": 149.99,
        "category": "Audio",
        "description": "Wireless over-ear headphones for focused work and travel.",
        "image": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=900&q=80",
        "featured": True,
    },
    {
        "id": 2,
        "name": "Mechanical Keyboard",
        "price": 89.00,
        "category": "Accessories",
        "description": "Compact tactile keyboard with hot-swappable switches.",
        "image": "https://images.unsplash.com/photo-1511467687858-23d96c32e4ae?auto=format&fit=crop&w=900&q=80",
        "featured": True,
    },
    {
        "id": 3,
        "name": "Travel Backpack",
        "price": 74.50,
        "category": "Lifestyle",
        "description": "Water-resistant backpack with a protected laptop sleeve.",
        "image": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=900&q=80",
        "featured": False,
    },
    {
        "id": 4,
        "name": "Smart Desk Lamp",
        "price": 54.25,
        "category": "Home Office",
        "description": "Adjustable warm-to-cool lighting for long sessions.",
        "image": "https://images.unsplash.com/photo-1519710164239-da123dc03ef4?auto=format&fit=crop&w=900&q=80",
        "featured": False,
    },
    {
        "id": 5,
        "name": "Ceramic Coffee Set",
        "price": 39.99,
        "category": "Kitchen",
        "description": "Minimal ceramic set for a calmer morning routine.",
        "image": "https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?auto=format&fit=crop&w=900&q=80",
        "featured": True,
    },
    {
        "id": 6,
        "name": "4K Webcam",
        "price": 119.00,
        "category": "Office",
        "description": "Sharp video and fast auto-focus for meetings and streaming.",
        "image": "https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=900&q=80",
        "featured": False,
    },
]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/products")
async def list_products(_: dict = Depends(get_current_user)) -> dict:
    return {"items": PRODUCTS}


@app.get("/products/featured")
async def featured_products(_: dict = Depends(get_current_user)) -> dict:
    return {"items": [product for product in PRODUCTS if product["featured"]]}
