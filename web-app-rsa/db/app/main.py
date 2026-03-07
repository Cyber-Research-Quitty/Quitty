from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import Float, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cart.db")
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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/cart/{user_id}")
def get_cart(user_id: str) -> dict:
    with SessionLocal() as session:
        items = session.scalars(select(CartItem).where(CartItem.user_id == user_id)).all()
        serialized = [CartItemResponse.model_validate(item).model_dump() for item in items]
        total = sum(item["quantity"] * item["price"] for item in serialized)
        return {"items": serialized, "total": total}


@app.post("/cart", response_model=CartItemResponse)
def add_to_cart(payload: CartItemCreate) -> CartItemResponse:
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
def delete_item(user_id: str, item_id: int) -> dict:
    with SessionLocal() as session:
        item = session.get(CartItem, item_id)
        if item is None or item.user_id != user_id:
            raise HTTPException(status_code=404, detail="Item not found")
        session.delete(item)
        session.commit()
        return {"deleted": True}
