from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
import httpx

from app.merkle import verify_proof
from app.signer import verify_root_bundle_pinned

# Paste the *pinned* root public key here (base64url).
# You must obtain it out-of-band (not from the network during verification).
PINNED_ROOT_PUB_B64 = "PASTE_THE_ROOT_PUBLIC_KEY_HERE"


def load_pinned_key_from_file(key_path: str) -> str:
    """Load the pinned public key from the root signer key file"""
    try:
        p = Path(key_path)
        if not p.exists():
            return ""
        obj = json.loads(p.read_text())
        if obj["alg"] == "ed25519":
            # For Ed25519, derive public key from private key
            from app.signer import Ed25519RootSigner
            signer = Ed25519RootSigner.from_json(obj)
            return signer.info().public_key
        elif obj["alg"] == "dilithium2":
            return obj.get("public_key", "")
        return ""
    except Exception as e:
        print(f"⚠️  Warning: Could not load key from {key_path}: {e}")
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify a key from E-JWKS server using pinned root public key"
    )
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--kid", required=True, help="Key ID to verify")
    ap.add_argument(
        "--pinned-pub",
        default=None,
        help="Optional: override pinned root public key (base64url).",
    )
    ap.add_argument(
        "--key-file",
        default="./root_signer_key.json",
        help="Path to root signer key file to auto-extract public key",
    )
    args = ap.parse_args()

    # Try to get pinned public key in order of priority:
    # 1. Command line argument
    # 2. Auto-extract from key file
    # 3. Hardcoded constant
    pinned_pub = args.pinned_pub
    
    if not pinned_pub:
        pinned_pub = load_pinned_key_from_file(args.key_file)
        if pinned_pub:
            print(f"✅ Loaded pinned public key from {args.key_file}")
    
    if not pinned_pub:
        pinned_pub = PINNED_ROOT_PUB_B64
    
    if not pinned_pub or pinned_pub == "PASTE_THE_ROOT_PUBLIC_KEY_HERE":
        print("❌ ERROR: No pinned root public key available!")
        print("\nYou must either:")
        print("  1. Pass --pinned-pub <base64url_key>")
        print("  2. Have a root_signer_key.json file in the current directory")
        print("  3. Set PINNED_ROOT_PUB_B64 in this script")
        print("\nThis is a security requirement - the public key must be obtained")
        print("out-of-band (not from the network during verification).")
        return 10

    print(f"🔍 Fetching key proof for kid: {args.kid}")
    try:
        with httpx.Client(timeout=10.0) as c:
            r = c.get(f"{args.base_url}/jwks/proof/{args.kid}")
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
        return 1

    root = data.get("root")
    if not root:
        print("❌ ERROR: Response missing 'root' field")
        return 2

    # ✅ Research-grade: verify signature using pinned public key (NOT network key)
    print("🔐 Verifying root signature with pinned public key...")
    if not verify_root_bundle_pinned(root, pinned_pub):
        print("❌ Root signature INVALID (pinned key)")
        print("   The JWKS root hash signature does not match the pinned public key!")
        return 3
    print("✅ Root signature OK (pinned key)")

    jwk = data.get("jwk")
    proof = data.get("merkle_proof")
    
    if not jwk or not proof:
        print("❌ ERROR: Response missing 'jwk' or 'merkle_proof' fields")
        return 4

    print("🌳 Verifying Merkle proof...")
    if not verify_proof(jwk, proof, expected_root_b64=root["root_hash"]):
        print("❌ Merkle proof INVALID")
        print("   The key is not included in the signed root!")
        return 5
    print("✅ Merkle proof OK (key is included in signed root)")

    print("\n" + "="*60)
    print("✅ VERIFICATION SUCCESSFUL")
    print("="*60)
    print(f"Key ID (kid):  {data.get('kid')}")
    print(f"Thumbprint:    {data.get('jkt')}")
    print(f"Algorithm:     {jwk.get('alg', 'N/A')}")
    print(f"Key Type:      {jwk.get('kty')}")
    if data.get('latest_checkpoint_idx'):
        print(f"Checkpoint:    #{data.get('latest_checkpoint_idx')}")
    print("\nThe key has been cryptographically verified against the pinned")
    print("root public key and is included in the Merkle tree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
