# Client Verify Microservice

This service simulates a client that verifies a public key fetched from P2 (`/jwks/proof/{kid}`) using:

1. Root signature verification against a pinned root public key
2. Merkle inclusion proof verification for the returned JWK

## Run locally

From `p2-ejwks-merkle`:

```bash
uvicorn client-verify.client_verify_service:app --host 0.0.0.0 --port 8201
```

## Endpoints

- `GET /health`
- `GET /verify/{kid}?base_url=http://127.0.0.1:8200`
- `POST /verify/{kid}`

POST body (all fields optional):

```json
{
  "base_url": "http://127.0.0.1:8200",
  "key_file": "./root_signer_key.json"
}
```

Only send `pinned_pub` when you have the real base64url root public key. Placeholder values such as Swagger's default `"string"` are ignored so the service can fall back to `key_file`.

## Pinned key resolution order

1. `pinned_pub` in POST body
2. `CLIENT_VERIFY_PINNED_PUB` env var
3. `key_file` in POST body (or `CLIENT_VERIFY_KEY_FILE`, default `./root_signer_key.json`)
4. Hardcoded `PINNED_ROOT_PUB_B64` fallback in `client_verify_service.py`

If none is valid, verification fails (security requirement).

## Docker

Build from `p2-ejwks-merkle`:

```bash
docker build -f client-verify/Dockerfile -t client-verify-service .
docker run --rm -p 8201:8201 \
  -e CLIENT_VERIFY_P2_BASE_URL=http://host.docker.internal:8200 \
  -e CLIENT_VERIFY_PINNED_PUB=<base64url_root_pub> \
  client-verify-service
```
