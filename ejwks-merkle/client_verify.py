from __future__ import annotations

import argparse
import httpx

from app.merkle import verify_proof
from app.signer import verify_root_bundle_pinned

# Paste the *pinned* root public key here (base64url).
# You must obtain it out-of-band (not from the network during verification).
PINNED_ROOT_PUB_B64 = "PASTE_THE_ROOT_PUBLIC_KEY_HERE"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--kid", required=True)
    ap.add_argument(
        "--pinned-pub",
        default=None,
        help="Optional: override pinned root public key (base64url).",
    )
    args = ap.parse_args()

    pinned_pub = args.pinned_pub or PINNED_ROOT_PUB_B64
    if not pinned_pub or pinned_pub == "PASTE_THE_ROOT_PUBLIC_KEY_HERE":
        print("❌ You must set PINNED_ROOT_PUB_B64 or pass --pinned-pub")
        return 10

    with httpx.Client(timeout=10.0) as c:
        r = c.get(f"{args.base_url}/jwks/proof/{args.kid}")
        r.raise_for_status()
        data = r.json()

    root = data["root"]

    # ✅ Research-grade: verify signature using pinned public key (NOT network key)
    if not verify_root_bundle_pinned(root, pinned_pub):
        print("❌ Root signature INVALID (pinned key)")
        return 2
    print("✅ Root signature OK (pinned key)")

    jwk = data["jwk"]
    proof = data["merkle_proof"]

    if not verify_proof(jwk, proof, expected_root_b64=root["root_hash"]):
        print("❌ Merkle proof INVALID")
        return 3
    print("✅ Merkle proof OK (key is included in signed root)")

    print("\nKey accepted:")
    print(" kid:", data["kid"])
    print(" jkt:", data["jkt"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
