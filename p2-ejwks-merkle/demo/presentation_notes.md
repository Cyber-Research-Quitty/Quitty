# Dashboard Demo Notes

## What to Show

1. Open `/dashboard` and point out the summary cards.
2. Show the active and inactive key counts.
3. Explain the difference between the two trees:
   - Live Key Merkle Tree: active public keys
   - Transparency Log Tree: checkpoint history
4. Click a key leaf and show the inclusion proof in the Key Proof Inspector.
5. Click a checkpoint leaf and show the inclusion proof in the Checkpoint Proof Inspector.
6. Highlight the latest JWKS root and latest log root.

## Suggested Talking Points

- The key tree proves that a public key is part of the current signed key set.
- The log tree proves that a published JWKS root exists in the append-only history.
- Inactive keys are preserved for observability and dashboard reporting.
- The dashboard auto-refreshes and reflects live state from `/dashboard/data`.

## Main Objective Slide

### Corrected Slide Text

**Main Objective**

Left column:

- Prevent public key substitution attacks, where an attacker injects a fake JWKS through a proxy, CDN, or ingress.
- Provide zero-trust JWKS distribution that does not rely only on TLS or transport trust.
- Enable per-key retrieval (key plus proof) so clients do not need to download the full `jwks.json` for every verification.
- Keep verification efficient for PQC-sized keys by using `O(log n)` Merkle proofs, Redis caching, and Bloom pre-checks.

Right column title:

- User Requirements Addressed

Right column bullets:

- Serve a signed JWKS root at `/jwks/root` as the commitment to the current key set.
- Provide a per-key proof endpoint at `/jwks/proof/{kid}` so a client can verify one key securely.
- Let the client verify using a pinned root public key instead of trusting a public key received from the network.
- Maintain an append-only transparency log with `/log/root`, `/log/latest`, and `/log/checkpoint/{idx}`.
- Improve lookup resilience with a Bloom filter and short-lived negative caching for missing keys.

### What To Avoid Saying

- Do not say the system replaces TLS. It reduces reliance on transport trust, but TLS is still useful.
- Do not say rollback detection is perfect. The project has an append-only log, but it does not yet implement consistency proofs.
- Do not focus on `jwks.json` as the main delivery path. In this project it is a legacy deprecated endpoint.
- Do not say only one Merkle tree exists. The implementation has two: one for active keys and one for transparency checkpoints.

### Slide Alignment Notes

- Give both boxes headings, or remove the heading from the right box. Right now the two columns are not visually parallel.
- Use one capitalization style throughout: `User Requirements Addressed`, `JWKS`, `Bloom Filter`, `Merkle Proof`.
- Replace `public-key` with `public key` for consistency with the rest of the presentation.
- Replace `Key + Proof` with `key plus proof` unless you are using symbols consistently across all slides.
- If you mention performance, say `O(log n)` once and avoid repeating both `fast` and `scalable` in the same bullet.

## Repo Locations

- Runtime dashboard assets: `app/demo/`
- Dashboard loader: `app/dashboard.py`
- Demo material: `demo/`
