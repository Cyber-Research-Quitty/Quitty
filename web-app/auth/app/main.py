from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from typing import Annotated, Any, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "60"))
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", "/data/auth.db")
P1_SIGN_URL = os.getenv("P1_SIGN_URL", "http://host.docker.internal:8100/sign")
P1_SIGN_ALG = os.getenv("P1_SIGN_ALG", "ml-dsa-44")
P2_BASE_URL = os.getenv("P2_BASE_URL", "http://host.docker.internal:8200")
P3_VALIDATE_URL = os.getenv("P3_VALIDATE_URL", "http://host.docker.internal:8300/guard/validate")
P4_REVOKE_URL = os.getenv("P4_REVOKE_URL", "http://host.docker.internal:8400/revoke")
P4_TOKEN_META_URL_TEMPLATE = os.getenv(
    "P4_TOKEN_META_URL_TEMPLATE",
    "http://host.docker.internal:8400/v1/tokens/{jti}",
)
TOKEN_TIMEOUT_SECONDS = float(os.getenv("TOKEN_TIMEOUT_SECONDS", "5"))
JWT_ISSUER = os.getenv("JWT_ISSUER", "p4-revocation-service")


def _origin_from_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url
    return f"{parts.scheme}://{parts.netloc}"


P1_BASE_URL = os.getenv("P1_BASE_URL", _origin_from_url(P1_SIGN_URL))
P3_BASE_URL = os.getenv("P3_BASE_URL", _origin_from_url(P3_VALIDATE_URL))
P4_BASE_URL = os.getenv("P4_BASE_URL", _origin_from_url(P4_REVOKE_URL))
P2_JWKS_ROOT_URL = os.getenv("P2_JWKS_ROOT_URL", f"{P2_BASE_URL}/jwks/root")
P2_KEY_PROOF_URL_TEMPLATE = os.getenv("P2_KEY_PROOF_URL_TEMPLATE", f"{P2_BASE_URL}/jwks/{{kid}}")
P2_LOG_LATEST_URL = os.getenv("P2_LOG_LATEST_URL", f"{P2_BASE_URL}/log/latest")


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


def decode_jwt_segment_unsafe(token: str, segment_index: int) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        segment = parts[segment_index]
        segment += "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(segment.encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        return {}
    return {}


def decode_jwt_header_unsafe(token: str) -> dict[str, Any]:
    return decode_jwt_segment_unsafe(token, 0)


def decode_jwt_payload_unsafe(token: str) -> dict[str, Any]:
    return decode_jwt_segment_unsafe(token, 1)


def safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Upstream service returned malformed JSON") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Upstream service returned malformed JSON")
    return data


def http_get_json(url: str, *, headers: Optional[dict[str, str]] = None, timeout: Optional[float] = None) -> tuple[int, dict[str, Any]]:
    try:
        response = httpx.get(url, headers=headers, timeout=timeout or TOKEN_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Dependent service unavailable") from exc
    return response.status_code, safe_json(response)


def http_post_json(url: str, payload: dict[str, Any], *, headers: Optional[dict[str, str]] = None, timeout: Optional[float] = None) -> tuple[int, dict[str, Any]]:
    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=timeout or TOKEN_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Dependent service unavailable") from exc
    return response.status_code, safe_json(response)


def get_service_health(label: str, base_url: str) -> dict[str, Any]:
    health_url = f"{base_url.rstrip('/')}/health"
    try:
        response = httpx.get(health_url, timeout=TOKEN_TIMEOUT_SECONDS)
        details = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        healthy = response.status_code == 200
        error = None if healthy else f"unexpected_status_{response.status_code}"
    except (httpx.HTTPError, ValueError) as exc:
        healthy = False
        details = {}
        error = type(exc).__name__

    return {
        "service": label,
        "url": base_url,
        "health_url": health_url,
        "healthy": healthy,
        "error": error,
        "details": details if isinstance(details, dict) else {},
    }


def get_p2_root_summary() -> dict[str, Any]:
    status_code, payload = http_get_json(P2_JWKS_ROOT_URL)
    if status_code != 200:
        raise HTTPException(status_code=502, detail="P2 JWKS root unavailable")
    return {
        "root_hash": payload.get("root_hash"),
        "epoch": payload.get("epoch"),
        "sig_alg": payload.get("sig_alg"),
        "sig_kid": payload.get("sig_kid"),
    }


def get_p2_log_summary() -> dict[str, Any]:
    status_code, payload = http_get_json(P2_LOG_LATEST_URL)
    if status_code != 200:
        raise HTTPException(status_code=502, detail="P2 transparency log unavailable")

    checkpoint = payload.get("checkpoint") if isinstance(payload.get("checkpoint"), dict) else {}
    log_root = payload.get("log_root") if isinstance(payload.get("log_root"), dict) else {}
    proof = payload.get("inclusion_proof") if isinstance(payload.get("inclusion_proof"), list) else []
    return {
        "checkpoint_idx": checkpoint.get("idx"),
        "checkpoint_epoch": checkpoint.get("epoch"),
        "checkpoint_root_hash": checkpoint.get("jwks_root_hash"),
        "log_root_hash": log_root.get("root_hash"),
        "log_epoch": log_root.get("epoch"),
        "proof_hops": len(proof),
    }


def get_p2_key_summary(kid: str) -> dict[str, Any]:
    status_code, payload = http_get_json(P2_KEY_PROOF_URL_TEMPLATE.format(kid=kid))
    if status_code == 404:
        return {"found": False, "kid": kid}
    if status_code != 200:
        raise HTTPException(status_code=502, detail="P2 key proof unavailable")

    proof = payload.get("merkle_proof") if isinstance(payload.get("merkle_proof"), list) else []
    root = payload.get("root") if isinstance(payload.get("root"), dict) else {}
    jwk = payload.get("jwk") if isinstance(payload.get("jwk"), dict) else {}
    return {
        "found": True,
        "kid": payload.get("kid") or kid,
        "jkt": payload.get("jkt"),
        "proof_hops": len(proof),
        "kty": jwk.get("kty"),
        "alg": jwk.get("alg"),
        "root_hash": root.get("root_hash"),
        "root_epoch": root.get("epoch"),
        "checkpoint_idx": payload.get("latest_checkpoint_idx"),
    }


def get_p4_token_meta(jti: str) -> dict[str, Any]:
    status_code, payload = http_get_json(P4_TOKEN_META_URL_TEMPLATE.format(jti=jti))
    if status_code == 404:
        return {"found": False, "jti": jti, "revoked": False}
    if status_code != 200:
        raise HTTPException(status_code=502, detail="P4 token metadata unavailable")
    return payload


def create_access_token(user: sqlite3.Row) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user["id"]),
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "iss": JWT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).timestamp()),
    }
    token, token_claims, signing_meta = sign_claims(claims)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": token_claims,
        "framework": {"signer": signing_meta},
    }


def sign_claims(claims: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    status_code, body = http_post_json(
        P1_SIGN_URL,
        {"claims": claims, "alg": P1_SIGN_ALG},
    )
    if status_code >= 400:
        raise HTTPException(status_code=503, detail="Token signer unavailable")

    token = body.get("token")
    if not isinstance(token, str) or not token:
        raise HTTPException(status_code=502, detail="Token signer returned malformed response")

    signed_claims = decode_jwt_payload_unsafe(token)
    header = decode_jwt_header_unsafe(token)
    if not signed_claims:
        raise HTTPException(status_code=502, detail="Signed token payload is malformed")

    signing_meta = {
        "alg": body.get("alg") if isinstance(body.get("alg"), str) else header.get("alg"),
        "kid": body.get("kid") if isinstance(body.get("kid"), str) else header.get("kid"),
        "jti": body.get("jti") if isinstance(body.get("jti"), str) else signed_claims.get("jti"),
        "token_size_bytes": body.get("token_size_bytes"),
        "sign_time_ms": body.get("sign_time_ms"),
    }
    return token, signed_claims, signing_meta


def guard_validate(token: str) -> dict[str, Any]:
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

    body = safe_json(response)
    if not body.get("valid"):
        raise HTTPException(status_code=401, detail="Invalid token")
    claims = body.get("claims")
    if not isinstance(claims, dict):
        raise HTTPException(status_code=401, detail="Invalid token claims")
    return body


def validate_token(token: str) -> dict[str, Any]:
    return guard_validate(token)["claims"]


def revoke_jti(jti: str) -> None:
    status_code, _ = http_post_json(
        P4_REVOKE_URL,
        {"type": "revoke_jti", "value": jti},
    )
    if status_code >= 400:
        raise HTTPException(status_code=503, detail="Revocation service unavailable")


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
    claims = validate_token(token)
    sub = claims.get("sub")
    if sub is None:
        raise HTTPException(status_code=401, detail="Invalid token claims")
    try:
        user_id = int(sub)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token subject") from exc

    user = get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def summarize_session(token: str) -> dict[str, Any]:
    guard_body = guard_validate(token)
    claims = guard_body.get("claims") if isinstance(guard_body.get("claims"), dict) else {}
    header = guard_body.get("header") if isinstance(guard_body.get("header"), dict) else decode_jwt_header_unsafe(token)
    jti = claims.get("jti") if isinstance(claims.get("jti"), str) else None
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None

    session = {
        "token": {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "name": claims.get("name"),
            "role": claims.get("role"),
            "iss": claims.get("iss"),
            "iat": claims.get("iat"),
            "exp": claims.get("exp"),
            "jti": jti,
            "alg": header.get("alg"),
            "kid": kid,
        },
        "validation": {
            "valid": True,
            "claims_source": "p3-guard-service",
            "header": header,
        },
    }

    if kid:
        session["p2"] = {
            "jwks_root": get_p2_root_summary(),
            "key_proof": get_p2_key_summary(kid),
            "transparency_log": get_p2_log_summary(),
        }
    else:
        session["p2"] = {
            "jwks_root": get_p2_root_summary(),
            "key_proof": {"found": False},
            "transparency_log": get_p2_log_summary(),
        }

    if jti:
        token_meta = get_p4_token_meta(jti)
        session["p4"] = {
            "token_meta": token_meta,
            "revoked": bool(token_meta.get("revoked")),
        }
    else:
        session["p4"] = {
            "token_meta": {"found": False},
            "revoked": False,
        }

    return session


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/framework/status")
def framework_status() -> dict[str, Any]:
    services = {
        "p1": get_service_health("p1-sign-service", P1_BASE_URL),
        "p2": get_service_health("p2-ejwks-merkle", P2_BASE_URL),
        "p3": get_service_health("p3-guard-service", P3_BASE_URL),
        "p4": get_service_health("p4-revocation", P4_BASE_URL),
    }

    root_summary: dict[str, Any] = {}
    log_summary: dict[str, Any] = {}
    try:
        root_summary = get_p2_root_summary()
    except HTTPException:
        root_summary = {}
    try:
        log_summary = get_p2_log_summary()
    except HTTPException:
        log_summary = {}

    return {
        "services": services,
        "p2": {
            "jwks_root": root_summary,
            "transparency_log": log_summary,
        },
    }


@app.post("/register")
def register(payload: RegisterRequest) -> dict[str, Any]:
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if get_user_by_email(payload.email) is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = insert_user(payload)
    return create_access_token(user)


@app.post("/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    user = get_user_by_email(payload.email)
    if user is None or not verify_password(payload.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return create_access_token(user)


@app.post("/verify")
def verify(payload: VerifyRequest) -> dict[str, Any]:
    claims = validate_token(payload.token)
    return {"valid": True, "claims": claims}


@app.post("/logout")
def logout(authorization: Annotated[Optional[str], Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    claims = validate_token(token)
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=400, detail="Token has no jti")
    revoke_jti(jti)
    return {"revoked": True, "jti": jti}


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


@app.get("/session/details")
def session_details(authorization: Annotated[Optional[str], Header()] = None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1]
    session = summarize_session(token)
    claims = session["token"]
    sub = claims.get("sub")
    user = None
    if isinstance(sub, str) and sub.isdigit():
        user = get_user_by_id(int(sub))

    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
            "address": user["address"],
            "phone": user["phone"],
            "created_at": user["created_at"],
        } if user is not None else None,
        **session,
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
def change_password(payload: PasswordChangeRequest, authorization: Annotated[Optional[str], Header()] = None) -> dict[str, Any]:
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
