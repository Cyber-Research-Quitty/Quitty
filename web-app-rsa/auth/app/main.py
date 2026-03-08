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
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
JWT_PRIVATE_KEY = os.getenv(
    "JWT_PRIVATE_KEY",
    """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCBhdMies1z3Q6
kdtGfNknr5fvVi63EiGaJTw0HIenj+e9dGC0pPwIDtR/b9B+j6FhWx2j2L30SX9N
xNTZwmeXBRXRI7jocsskrS48W81wB+k4z1io0xwdo9fz8lZZWWdWvfJo1yalZREo
DYXlKWhvjU3gXQiJiHW6oPCKmwzz6ZxSx+nPM/hqYPtcuXnMjKRX5S32N5z+AqUz
vM5LCvOBeEkf2oZHCjI9dnE30Z0XSZvt7uGzU6ajmG6fOY4848zSx/EBXHTPJQyS
O+Qw3ufJTfPlbXT1pddBFg2gwVbP/0+u5pRQ0CZP8qppfEDELT8NV647XCqDB0hc
MIdc2V3FAgMBAAECggEANqHLbrBJDBpRgmpugU8HQF73m5s7RS40SvigFpZP9jUV
jimWT1dDZity1z1PSku8J7MlyexuNDp7v5SkUHqme4YhigWSe9VS8Q1YfwNked6o
Y2gy8TqcaJYpaRW8DaWYbPrIJpAqYBjwt0Pzhz7dGsgBfSMFE+DaMYY+pPCauZT4
VzZ2/iQxUltTkc1jT6RUNbZFRmszDI2Spc15W5crTJegDauo6ly6kO5FCfmuDMnX
uDt7Vfy4ZuJzfcdZQwWYTkmltqCrnCge0H0sITaNa8P+YU1quQZ4OjT9ic0s4W68
XaCvIXs6JjgqG3yv+5HuTlt0I2r51HH4OErQknUTgwKBgQD2zXTpxXWqlXR/3MK3
APsTVwpL5Chx4YI/6UvpRmcTNNfqA/rclg9HRQJGC65Q+zdwfRIItl3sdeXvDVjk
gqea/c8+Ti0rcHhAMYCXg63nVXHXlBYxhgBuyaTZQGSvJaUOpE6ORBp/sBzD29AP
iY1ujmnyoehki9xrDSarH1CF3wKBgQDJQR1kpf012FruVhqF72nrl2/D4YMW1TcG
7iwDrs8wM9ZD1L7Po8rJmPaZqkW+La1LT/e7YlrOKukvrj/e7l0jRi4rnhmNPM00
lMg/f8F6KtP//9r8A2bTJS5T6z0XjeQd7K05d28s+3XegxcxYo0WhzbHlI24APNS
o/W2S3Qo2wKBgDm95f2PojDv2JrVpoS0aQmkUpdg4QmLzjJvvb/tJc57jYyFs9qK
DTcKcTa8IuN1cwoRaPe62wyopMwiHksQOnBrs2ILXkwMe0Xhjwlj2HsIJaNfVTXu
+Qjyimv9wdCsiQp87JgiXOTE6mX0dqA7+WgFT8phkQJ9KmutXv+oSumXAoGAFQRT
yXr8Im9hr5oWUv5ZlVzPMymNwwipInQk7I2I3YPMUHEbLBvyxXLP7eQ2PFIQ0tib
ClqPGRCqIWyVBvblixV9JNjx2ioLU/5lmxwAXH20fft+JutEBbDQUbszOg57UBSz
UlkCpzPrbz1JYsLj8QJV2inNUvXmcy7kLhFbJBkCgYEArfAg/1wPjr47kZryB5k5
ac1VtNwyiZib9i+urj2RU2dnxh57I8iijrsJ9hjVRlT8CVsmOXoINXdeK8ZgrRKI
bpZQucOBWepQuqvB2UOXbWV6Wd0nYPmvU2TpaEEKUWGyjjdGRva0DMwK5GM693W3
PtDA9u7iJ0fNrlGMWY9nx7E=
-----END PRIVATE KEY-----
""",
)
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
ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "60"))
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", "/data/auth.db")


def normalize_pem(pem: str) -> str:
    return pem.replace("\\n", "\n").strip() + "\n"


JWT_PRIVATE_KEY = normalize_pem(JWT_PRIVATE_KEY)
JWT_PUBLIC_KEY = normalize_pem(JWT_PUBLIC_KEY)


def get_signing_key() -> str:
    if JWT_ALGORITHM.upper().startswith("RS"):
        return JWT_PRIVATE_KEY
    return JWT_SECRET


def get_verification_key() -> str:
    if JWT_ALGORITHM.upper().startswith("RS"):
        return JWT_PUBLIC_KEY
    return JWT_SECRET


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
    token = jwt.encode(claims, get_signing_key(), algorithm=JWT_ALGORITHM)
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
        claims = jwt.decode(token, get_verification_key(), algorithms=[JWT_ALGORITHM])
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
        claims = jwt.decode(payload.token, get_verification_key(), algorithms=[JWT_ALGORITHM])
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
