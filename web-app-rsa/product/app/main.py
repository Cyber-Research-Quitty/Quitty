from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="product-service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
def list_products() -> dict:
    return {"items": PRODUCTS}


@app.get("/products/featured")
def featured_products() -> dict:
    return {"items": [product for product in PRODUCTS if product["featured"]]}
