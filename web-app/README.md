# Web App Microservices Demo (PQC Integrated)

This folder contains a shopping application with separate services for:

- `auth`: login, PQC token issuance via `p1`, and authenticated profile data
- `product`: product catalog for the storefront home page
- `cart`: PQC-token-protected cart API (validation via `p3`)
- `db`: cart persistence with SQLite
- `frontend`: Next.js storefront with Home, Cart, and Profile views

## External PQ Services (Required)

Before starting this stack, make sure these services are already running:

- `p1-sign-service` on `http://localhost:8100`
- `p2-ejwks-merkle` on `http://localhost:8200`
- `p3-guard-service` on `http://localhost:8300`
- `p4-revocation` on `http://localhost:8400`

## User Flow

1. Visitors land on a storefront home page with products.
2. They log in through `auth`.
3. The frontend stores the JWT and loads the profile from `auth /me`.
4. Products are fetched from `product`.
5. Cart actions go through `cart`, which validates the JWT.
6. `db` stores cart items.

## Run with Docker

```bash
docker compose -f web-app/docker-compose.yml up --build -d
```

Web-app services:

- Frontend: `http://localhost:3000`
- Auth API: `http://localhost:8001`
- DB API: `http://localhost:8002`
- Cart API: `http://localhost:8003`
- Product API: `http://localhost:8004`

## Auth/AuthZ Integration Notes

- `auth` no longer signs local `HS256` tokens.
- `auth` issues access tokens by calling `p1 /sign`.
- `auth /logout` revokes the current token by `jti` via `p4 /revoke`.
- Protected APIs validate bearer tokens through `p3 /guard/validate`.
- `p3` enforces full guard checks backed by:
  - `p2` for key discovery,
  - `p1` for signature verification,
  - `p4` for revocation checks.

## Stop the stack

```bash
docker compose -f web-app/docker-compose.yml down
```
