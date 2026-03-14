# p1-sign-service

P1 service for signing and verifying JWTs using PQC-ready algorithms.

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2)

## Run With Docker Compose

From `p1-sign-service/` directory:

```bash
docker compose up --build
```

Run detached:

```bash
docker compose up --build -d
```

Stop and remove container:

```bash
docker compose down
```

The API is exposed on `http://localhost:8100`.

## Configuration

The compose file already sets defaults:

- `ENVIRONMENT=dev`
- `DEFAULT_ALG=ml-dsa-44`
- `KEYSTORE_PATH=data/p1-keystore.json`
- `P2_EXPORT_URL` optional (empty by default)
- `P2_ADMIN_API_KEY` should match P2 `ADMIN_API_KEY` when export/delete is enabled
- `P2_TIMEOUT_SECONDS=3.0`

Notes:

- Keys are persisted to `./data` on your host via volume mount.
- On first sign/rotate call, the keystore file is generated automatically if missing.

## Quick Health Check

```bash
curl http://localhost:8100/health
```

Expected response includes:

- `status: "ok"`
- `component: "P1"`

## Quick API Test

### 1) Sign a token

```bash
curl -X POST http://localhost:8100/sign \
  -H "Content-Type: application/json" \
  -d '{"claims":{"sub":"alice","role":"user"},"alg":"ml-dsa-44"}'
```

### 2) Verify the token

Use the token from step 1:

```bash
curl -X POST http://localhost:8100/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"<PASTE_TOKEN_HERE>"}'
```

## Useful Endpoints

- `GET /health`
- `GET /metrics`
- `POST /sign`
- `POST /verify`
- `GET /internal/keys/public`
- `GET /internal/keys/jwks`
- `POST /internal/keys/rotate`
- `POST /internal/keys/export` (requires `P2_EXPORT_URL`)
