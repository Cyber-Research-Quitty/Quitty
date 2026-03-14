# P2 Demo Script (5 Minutes, Swagger-Aligned)

## Goal
Present P2 as a research component that provides:
- cryptographic key inclusion proofs,
- append-only transparency guarantees,
- witness-based anti-equivocation signals.

Use Swagger sections in this order:
1. 01 Health
2. 02 JWKS Active Set
3. 03 Transparency Log
4. 04 Consistency Proofs
5. 05 Witness and Gossip

## 0. Setup Checklist (Before Panel)
- Open http://127.0.0.1:8200/docs
- Hard refresh once: Cmd+Shift+R
- Confirm all grouped sections are visible in Swagger.
- If witness registry is empty, run your witness seed step before presenting.

## 1) 01 Health (20-30 seconds)
Action:
- Execute GET /health

What to say:
- "This confirms P2 is live and ready."

## 2) 02 JWKS Active Set (90 seconds)
Action A:
- Execute GET /jwks/root

Point to:
- root_hash
- epoch
- signature
- sig_alg (ML-DSA-44)

What to say:
- "Whenever active keys change, P2 publishes a new signed root for the active key set."

Action B:
- Execute GET /jwks/proof/{kid}
- Use a known kid from your data.

Point to:
- jwk
- merkle_proof
- root.root_hash
- latest_checkpoint_idx

What to say:
- "This is a compact cryptographic inclusion proof. A verifier does not need the full key list to verify membership at this epoch."

Optional mention:
- "P1 pushes key updates through internal admin endpoints, and P2 republishes a new signed root."

## 3) 03 Transparency Log (60 seconds)
Action A:
- Execute GET /log/checkpoints

Point to:
- idx progression
- prev_hash / entry_hash chain structure

Action B:
- Execute GET /log/checkpoint/{idx}
- Use idx=1 or a recent one.

Point to:
- checkpoint payload
- inclusion_proof

What to say:
- "Each published JWKS root is committed into a transparency log checkpoint."

## 4) 04 Consistency Proofs (Strongest Research Claim, 90 seconds)
Action A:
- Execute GET /log/consistency/rfc6962
- Use old_size=2 and new_size=5 (or any valid increasing sizes).

Action B:
- Copy full response JSON.
- Execute POST /log/consistency/rfc6962/verify
- Paste the exact response body.

Expected output:
- {"valid": true}

What to say:
- "This proves append-only growth between two log sizes under RFC6962 consistency logic."
- "So newer state extends older state; it was not rewritten or reordered."

## 5) 05 Witness and Gossip (Anti-Equivocation, 90 seconds)
Action A:
- Execute GET /log/witness/registry

Point to:
- registered witness identities

Action B:
- Get checkpoint index from GET /log/latest (checkpoint.idx)
- Execute GET /log/witness/exchange/{checkpoint_idx}?min_signatures=2

Point to:
- witness_count
- witnesses
- quorum_met

What to say:
- "Independent witnesses sign the same checkpoint payload."
- "If the service equivocated across clients, witness disagreement/conflicts make it detectable."

## Final Close (20 seconds)
Say:
- "P2 moves key distribution from trust-only delivery to evidence-based verification: signed active roots, append-only consistency proofs, and witness-backed checkpoint exchange."

## Quick Troubleshooting During Demo
- If endpoints are missing in Swagger:
  - refresh docs page and check /openapi.json.
- If witness endpoints return empty data:
  - witness registry/signatures have not been seeded yet.
- If consistency verify returns false:
  - ensure you pasted the exact proof payload from generate endpoint without edits.
