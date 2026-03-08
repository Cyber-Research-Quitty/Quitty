# Web App Microservices Demo (PQC Integrated)

This folder contains a shopping application with separate services for:

- `auth`: login, token issuance via `p1`, framework diagnostics, and authenticated profile data
- `product`: product catalog for the storefront home page
- `cart`: PQC-token-protected cart API (validation via `p3`)
- `db`: cart persistence with SQLite
- `frontend`: Next.js storefront with Home, Cart, and Profile views

## External Quitty Services (Required)

Before starting this stack, make sure these services are already running:

- `p1-sign-service` on `http://localhost:8100`
- `p2-ejwks-merkle` on `http://localhost:8200`
- `p3-guard-service` on `http://localhost:8300`
- `p4-revocation` on `http://localhost:8400`

## What Is Integrated

The web app now uses the framework as an active part of the product flow instead of a hidden token backend:

- `auth` issues access tokens by calling `p1 /sign`
- `auth` validates tokens by calling `p3 /guard/validate`
- `auth /logout` revokes the current token by `jti` via `p4 /revoke`
- `auth /session/details` pulls live token metadata from `p4` and JWKS / Merkle / transparency data from `p2`
- `auth /framework/status` checks live health for `p1` through `p4`
- the frontend surfaces the active token pipeline, signer `kid`, Merkle evidence, and revocation state

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

## Optional Compose Configuration

`web-app/docker-compose.yml` accepts these external service overrides:

- `QUITTY_P1_BASE_URL`
- `QUITTY_P1_SIGN_URL`
- `QUITTY_P1_SIGN_ALG`
- `QUITTY_P2_BASE_URL`
- `QUITTY_P3_BASE_URL`
- `QUITTY_P3_VALIDATE_URL`
- `QUITTY_P4_BASE_URL`
- `QUITTY_P4_REVOKE_URL`
- `QUITTY_P4_TOKEN_META_URL_TEMPLATE`
- `QUITTY_JWT_ISSUER`

Frontend API URLs can also be overridden with:

- `WEB_AUTH_API_URL`
- `WEB_CART_API_URL`
- `WEB_PRODUCT_API_URL`

## Stop the stack

```bash
docker compose -f web-app/docker-compose.yml down
```
