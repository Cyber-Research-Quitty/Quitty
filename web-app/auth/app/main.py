from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Annotated, Optional

import jwt
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "60"))
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", "/data/auth.db")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    address: str
    phone: str


class VerifyRequest(BaseModel):
    token: str


class ProfileUpdateRequest(BaseModel):
    name: str
    address: str
    phone: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    seed_default_users()
    yield


app = FastAPI(title="auth-service", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(AUTH_DB_PATH), exist_ok=True)
    connection = sqlite3.connect(AUTH_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT NOT NULL,
                address TEXT NOT NULL,
                phone TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()


def create_password_record(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    return salt, hash_password(password, salt)


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), password_hash)


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with get_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def create_access_token(user: sqlite3.Row) -> dict:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user["id"]),
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).timestamp()),
    }
    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "user": claims}


def insert_user(payload: RegisterRequest, role: str = "member") -> sqlite3.Row:
    salt, password_hash = create_password_record(payload.password)
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO users (name, email, password_hash, password_salt, role, address, phone, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.name,
                payload.email,
                password_hash,
                salt,
                role,
                payload.address,
                payload.phone,
                created_at,
            ),
        )
        connection.commit()
        user_id = cursor.lastrowid
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with get_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def update_user_profile(user_id: int, payload: ProfileUpdateRequest) -> sqlite3.Row:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET name = ?, address = ?, phone = ?
            WHERE id = ?
            """,
            (payload.name, payload.address, payload.phone, user_id),
        )
        connection.commit()
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def change_user_password(user_id: int, new_password: str) -> None:
    salt, password_hash = create_password_record(new_password)
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, password_salt = ?
            WHERE id = ?
            """,
            (password_hash, salt, user_id),
        )
        connection.commit()


def seed_default_users() -> None:
    defaults = [
        RegisterRequest(
            name="Alice",
            email="alice@example.com",
            password="password123",
            address="742 Evergreen Terrace, Springfield",
            phone="+1 555 0101",
        ),
        RegisterRequest(
            name="Bob",
            email="bob@example.com",
            password="password123",
            address="18 Market Street, Seattle",
            phone="+1 555 0102",
        ),
    ]
    for user in defaults:
        if get_user_by_email(user.email) is None:
            insert_user(user)


def get_current_user(authorization: Annotated[Optional[str], Header()] = None) -> sqlite3.Row:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1]
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    user = get_user_by_email(claims["email"])
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/register")
def register(payload: RegisterRequest) -> dict:
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if get_user_by_email(payload.email) is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = insert_user(payload)
    return create_access_token(user)


@app.post("/login")
def login(payload: LoginRequest) -> dict:
    user = get_user_by_email(payload.email)
    if user is None or not verify_password(payload.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return create_access_token(user)


@app.post("/verify")
def verify(payload: VerifyRequest) -> dict:
    try:
        claims = jwt.decode(payload.token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    return {"valid": True, "claims": claims}


@app.get("/me")
def me(authorization: Annotated[Optional[str], Header()] = None) -> dict:
    user = get_current_user(authorization)
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "address": user["address"],
        "phone": user["phone"],
        "created_at": user["created_at"],
    }


@app.patch("/me")
def update_me(payload: ProfileUpdateRequest, authorization: Annotated[Optional[str], Header()] = None) -> dict:
    user = get_current_user(authorization)
    updated = update_user_profile(user["id"], payload)
    return {
        "id": updated["id"],
        "email": updated["email"],
        "name": updated["name"],
        "role": updated["role"],
        "address": updated["address"],
        "phone": updated["phone"],
        "created_at": updated["created_at"],
    }


@app.post("/change-password")
def change_password(payload: PasswordChangeRequest, authorization: Annotated[Optional[str], Header()] = None) -> dict:
    user = get_current_user(authorization)
    if not verify_password(payload.current_password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    change_user_password(user["id"], payload.new_password)
    updated = get_user_by_id(user["id"])
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")
    return create_access_token(updated)
