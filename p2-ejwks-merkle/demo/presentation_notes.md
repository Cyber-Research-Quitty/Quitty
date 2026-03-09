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

## Repo Locations

- Runtime dashboard assets: `app/demo/`
- Dashboard loader: `app/dashboard.py`
- Demo material: `demo/`
