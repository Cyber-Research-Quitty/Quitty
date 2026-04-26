import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.pqc_crypto import encapsulate_kyber_secret, generate_kyber_keypair
from app.refresh_token_utils import decrypt_refresh_payload, get_refresh_token_claims


BASE_URL = os.environ.get("P4_BASE_URL", "http://127.0.0.1:8400").rstrip("/")


def post_json(path: str, payload: dict) -> tuple[int, dict]:
    request = Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"detail": body}


def decode_access_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT format")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    import base64

    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    subject = f"refresh-test-{uuid.uuid4().hex[:8]}"
    client_binding = f"device-{uuid.uuid4().hex[:8]}"
    additional_claims = {"role": "tester", "env": "endpoint-check"}

    create_status, create_data = post_json(
        "/token/refresh/create",
        {
            "subject": subject,
            "client_binding": client_binding,
            "additional_claims": additional_claims,
        },
    )
    require(create_status == 200, f"create failed: {create_data}")
    require(bool(create_data.get("client_public_key")), "create response missing client_public_key")
    require(bool(create_data.get("kid")), "create response missing kid")

    proof_ciphertext, proof_shared_secret_hex = encapsulate_kyber_secret(create_data["client_public_key"])
    proof_hash = hashlib.sha256(bytes.fromhex(proof_shared_secret_hex)).hexdigest()
    proof_status, proof_data = post_json(
        "/token/refresh/prove-keypair",
        {
            "refresh_token": create_data["refresh_token"],
            "kem_ciphertext": proof_ciphertext,
            "expected_shared_secret_sha256": proof_hash,
        },
    )
    require(proof_status == 200, f"prove-keypair failed: {proof_data}")
    require(proof_data.get("proof_valid") is True, f"prove-keypair invalid: {proof_data}")
    require(proof_data.get("matches_expected") is True, f"prove-keypair mismatch: {proof_data}")

    client_public_key, client_private_key = generate_kyber_keypair()
    refresh_status, refresh_data = post_json(
        "/token/refresh",
        {
            "refresh_token": create_data["refresh_token"],
            "client_binding": client_binding,
            "client_public_key": client_public_key,
        },
    )
    require(refresh_status == 200, f"refresh failed: {refresh_data}")
    require("encrypted_payload" in refresh_data, "refresh response missing encrypted_payload")
    require("kem_ciphertext" in refresh_data, "refresh response missing kem_ciphertext")

    protected = decrypt_refresh_payload(
        client_private_key=client_private_key,
        kem_ciphertext=refresh_data["kem_ciphertext"],
        encrypted_payload=refresh_data["encrypted_payload"],
        payload_nonce=refresh_data["payload_nonce"],
    )
    require("access_token" in protected, "decrypted refresh payload missing access_token")
    require("refresh_token" in protected, "decrypted refresh payload missing refresh_token")

    rotated_refresh_claims = get_refresh_token_claims(protected["refresh_token"])
    rotated_access_claims = decode_access_claims(protected["access_token"])
    require(rotated_access_claims.get("role") == "tester", "custom claim role not preserved on access token")
    require(rotated_access_claims.get("env") == "endpoint-check", "custom claim env not preserved on access token")
    require(rotated_refresh_claims.get("role") == "tester", "custom claim role not preserved on refresh token")
    require(rotated_refresh_claims.get("env") == "endpoint-check", "custom claim env not preserved on refresh token")

    revoke_status, revoke_data = post_json(
        "/token/refresh/revoke",
        {"refresh_token": protected["refresh_token"]},
    )
    require(revoke_status == 200, f"revoke failed: {revoke_data}")
    require(revoke_data.get("published") is True, f"revoke did not publish: {revoke_data}")

    post_revoke_refresh_status, post_revoke_refresh_data = post_json(
        "/token/refresh",
        {
            "refresh_token": protected["refresh_token"],
            "client_binding": client_binding,
            "client_public_key": client_public_key,
        },
    )
    require(post_revoke_refresh_status == 401, f"revoked token reuse expected 401, got {post_revoke_refresh_status}: {post_revoke_refresh_data}")

    summary = {
        "base_url": BASE_URL,
        "create": {
            "status": create_status,
            "kid": create_data["kid"],
            "client_public_key_present": True,
        },
        "prove_keypair": {
            "status": proof_status,
            "proof_valid": proof_data["proof_valid"],
            "matches_expected": proof_data["matches_expected"],
            "kem_algorithm": proof_data["kem_algorithm"],
            "refresh_jti": proof_data["refresh_jti"],
        },
        "refresh": {
            "status": refresh_status,
            "rotated_refresh_jti": refresh_data["refresh_jti"],
            "access_jti": refresh_data["access_jti"],
            "encrypted_fields": sorted(
                key for key in refresh_data.keys()
                if key in {"kem_ciphertext", "encrypted_payload", "payload_nonce", "encryption_alg", "kdf"}
            ),
        },
        "revoke": {
            "status": revoke_status,
            "published": revoke_data["published"],
        },
        "post_revoke_refresh": {
            "status": post_revoke_refresh_status,
            "detail": post_revoke_refresh_data.get("detail"),
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"base_url": BASE_URL, "error": str(exc)}, indent=2))
        raise SystemExit(1)
