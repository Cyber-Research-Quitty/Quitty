python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env

docker compose up -d
uvicorn app.main:app --reload --port 8200



---------------------
Test with curl
Import a key

curl -X POST http://127.0.0.1:8200/internal/keys/import \
  -H "Content-Type: application/json" \
  -H "X-Admin-Api-Key: dev-admin-key" \
  -d '{
    "kid": "demo-ml-dsa-44-1",
    "kty": "PQC",
    "pk": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "alg": "ml-dsa-44"
  }'


Get Signed root

curl http://127.0.0.1:8200/jwks/root

Get key + proof

curl http://127.0.0.1:8200/jwks/proof/demo-ml-dsa-44-1


Client verification

python client_verify.py --kid demo-ml-dsa-44-1 --base-url http://127.0.0.1:8200

--------------------------
8) How to connect this to your P1 Sign Service (real integration)

Your P2 design expects issuers/verifiers to update JWKS store and clients fetch per-key proofs

Proposal-Version-2 IT22192332

. The clean integration is:

P1 exports public key → P2 imports it

P1 (sign-service) generates new keypair, then calls:

POST http://p2-jwks:8200/internal/keys/import

headers include X-Admin-Api-Key and body = public JWK with kid, kty, alg, and the public material (x for OKP / n,e for RSA / your PQC encoding fields)

That’s it — P2 rebuilds the tree and republishes a new root.
