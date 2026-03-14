from contextlib import asynccontextmanager
import os
from typing import Annotated, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import Float, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cart.db")
P3_VALIDATE_URL = os.getenv("P3_VALIDATE_URL", "http://host.docker.internal:8300/guard/validate")
TOKEN_TIMEOUT_SECONDS = float(os.getenv("TOKEN_TIMEOUT_SECONDS", "5"))
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


class CartItem(Base):
    __tablename__ = "cart_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True)
    product_name: Mapped[str] = mapped_column(String(255))
    quantity: Mapped[int] = mapped_column(Integer)
    price: Mapped[float] = mapped_column(Float)


class CartItemCreate(BaseModel):
    user_id: str
    product_name: str
    quantity: int
    price: float


class CartItemResponse(BaseModel):
    id: int
    user_id: str
    product_name: str
    quantity: int
    price: float

    class Config:
        from_attributes = True


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="db-service", lifespan=lifespan)


def get_current_user(authorization: Annotated[Optional[str], Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1]
    try:
        response = httpx.get(
            P3_VALIDATE_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=TOKEN_TIMEOUT_SECONDS,
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


@app.get("/cart/{user_id}")
def get_cart(user_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("sub") != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with SessionLocal() as session:
        items = session.scalars(select(CartItem).where(CartItem.user_id == user_id)).all()
        serialized = [CartItemResponse.model_validate(item).model_dump() for item in items]
        total = sum(item["quantity"] * item["price"] for item in serialized)
        return {"items": serialized, "total": total}


@app.post("/cart", response_model=CartItemResponse)
def add_to_cart(payload: CartItemCreate, current_user: dict = Depends(get_current_user)) -> CartItemResponse:
    if current_user.get("sub") != payload.user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if payload.quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity must be positive")
    if payload.price < 0:
        raise HTTPException(status_code=400, detail="Price must be non-negative")

    with SessionLocal() as session:
        item = CartItem(**payload.model_dump())
        session.add(item)
        session.commit()
        session.refresh(item)
        return CartItemResponse.model_validate(item)


@app.delete("/cart/{user_id}/{item_id}")
def delete_item(user_id: str, item_id: int, current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("sub") != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with SessionLocal() as session:
        item = session.get(CartItem, item_id)
        if item is None or item.user_id != user_id:
            raise HTTPException(status_code=404, detail="Item not found")
        session.delete(item)
        session.commit()
        return {"deleted": True}
