python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
# P2 E-JWKS Merkle + Transparency Service

This service maintains an active JWKS set, publishes signed Merkle roots,
and appends each published root into a checkpoint transparency log.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Local
uvicorn app.main:app --reload --port 8200

# Or Docker
docker compose up -d
```

## Minimal Flow

Import a key (admin-protected):

```bash
curl -X POST http://127.0.0.1:8200/internal/keys/import \
  -H "Content-Type: application/json" \
  -H "X-Admin-Api-Key: dev-admin-key" \
  -d '{
    "kid": "demo-ml-dsa-44-1",
    "kty": "PQC",
    "pk": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "alg": "ml-dsa-44"
  }'
```

Fetch signed active-set root:

```bash
curl http://127.0.0.1:8200/jwks/root
```

Fetch key + inclusion proof:

```bash
curl http://127.0.0.1:8200/jwks/proof/demo-ml-dsa-44-1
```

Verify from client with pinned key + freshness policy:

```bash
python client-verify/client_verify.py \
  --kid demo-ml-dsa-44-1 \
  --base-url http://127.0.0.1:8200 \
  --max-root-age-seconds 300 \
  --max-clock-skew-seconds 60
```

## New Research-Grade Additions

### 1) Append-Only Consistency Between Log Sizes

P2 now exposes a chain-based consistency proof:

```bash
curl "http://127.0.0.1:8200/log/consistency?from_idx=10&to_idx=25"
```

Returned proof includes the contiguous checkpoint range and validation status
that each checkpoint links by `prev_hash` and recomputed `entry_hash`.

Important: this is a checkpoint hash-chain append-only proof for this prototype,
not an RFC6962 Merkle consistency proof.

P2 now also exposes full RFC6962-style consistency proofs and server-side verifier:

```bash
# Generate proof between old/new tree sizes
curl "http://127.0.0.1:8200/log/consistency/rfc6962?old_size=10&new_size=25"

# Verify proof payload
curl -X POST "http://127.0.0.1:8200/log/consistency/rfc6962/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "old_size": 10,
    "new_size": 25,
    "old_root": "...",
    "new_root": "...",
    "proof": ["..."]
  }'
```

### 2) Explicit Freshness Model in Verifier Logic

Verifier now enforces recency bounds against root epoch:

- `max_root_age_seconds` (default `300`)
- `max_clock_skew_seconds` (default `60`)

If root age violates policy, verification fails with `412` in service mode
or non-zero exit in CLI mode.

### 3) Witness / Gossip Model Hooks

P2 now supports witness observations and equivocation detection:

- `POST /log/witness/observe` (admin-protected)
- `GET /log/witness/state`

For signed multi-witness exchange (anti-equivocation quorum):

- `POST /log/witness/register` (admin-protected)
- `GET /log/witness/registry`
- `POST /log/witness/sign` (witness submits detached signature)
- `GET /log/witness/exchange/{checkpoint_idx}?min_signatures=2`

An equivocation conflict is recorded when the same `observer_id` reports a
different `log_root_hash` for the same `checkpoint_idx`.

Witness signatures are verified against registered witness public keys
(`ml-dsa-44`) over canonical payload:

```json
{"checkpoint_idx": <int>, "epoch": <int>, "log_root_hash": "<base64url>"}
```

### 4) Scalability Positioning

Current rebuild behavior remains full recomputation of active-set Merkle data
and related caches after key import/delete.

- Active-set rebuild complexity is `O(n)` in number of active keys.
- This is suitable for prototype/research scale.
- For production-scale deployments, incremental tree updates and batched
  checkpointing should be considered.

### 5) Revocation Semantics (Formal Wording)

P2 key deletion marks a key as `inactive` and removes it from the active-set tree
in subsequent epochs.

This means:

- P2 alone proves active inclusion at a given epoch.
- P2 alone does not prove revocation freshness across arbitrary verifier time.
- Verifiers should enforce epoch freshness policy and/or combine with P4
  revocation checks for stronger revocation guarantees.

## Core API Summary

- `GET /jwks/root`: signed active-set root bundle.
- `GET /jwks/proof/{kid}`: key + Merkle inclusion proof.
- `GET /jwks/proof-by-jkt/{jkt}`: same lookup by thumbprint.
- `POST /internal/keys/import`: admin key import.
- `DELETE /internal/keys/{kid}`: admin key deactivate.
- `GET /log/root`: signed log root bundle.
- `GET /log/latest`: latest checkpoint + inclusion proof.
- `GET /log/checkpoint/{idx}`: checkpoint + inclusion proof.
- `GET /log/checkpoints`: paginated checkpoint listing.
- `GET /log/consistency`: append-only checkpoint chain proof.
- `GET /log/consistency/rfc6962`: RFC6962 consistency proof generation.
- `POST /log/consistency/rfc6962/verify`: RFC6962 consistency proof verification.
- `POST /log/witness/observe`: submit witness observation.
- `GET /log/witness/state`: witness observation/conflict state.
- `POST /log/witness/register`: register/update witness public key.
- `GET /log/witness/registry`: list registered witnesses.
- `POST /log/witness/sign`: submit witness-signed checkpoint.
- `GET /log/witness/exchange/{checkpoint_idx}`: fetch signed checkpoint package and quorum status.

## Integration with P1

P1 sign service should export public key material into P2:

- Endpoint: `POST /internal/keys/import`
- Header: `X-Admin-Api-Key`
- Payload: public JWK fields (`kid`, `kty`, `alg`, and public key material)

Each import updates active-set root and appends a new transparency checkpoint.
