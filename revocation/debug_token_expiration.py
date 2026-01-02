"""
Debug script to check token expiration issue
"""
import requests
import jwt
from datetime import datetime, timezone

BASE_URL = "http://localhost:8000"

def debug_token():
    print("=" * 60)
    print("Token Expiration Debug")
    print("=" * 60)
    print()
    
    # Create a token
    print("1. Creating token...")
    response = requests.post(
        f"{BASE_URL}/token",
        json={"subject": "test_user"}
    )
    
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return
    
    token_data = response.json()
    token = token_data["access_token"]
    
    print(f"✓ Token created")
    print(f"  Expires in: {token_data['expires_in']} seconds")
    print()
    
    # Decode token to check expiration
    decoded = jwt.decode(token, options={"verify_signature": False})
    exp_ts = decoded.get("exp")
    iat_ts = decoded.get("iat")
    
    now_ts = int(datetime.now(timezone.utc).timestamp())
    
    print("2. Token Details:")
    print(f"  iat (issued at): {iat_ts}")
    print(f"  exp (expires at): {exp_ts}")
    print(f"  Current time: {now_ts}")
    print(f"  Token lifetime: {exp_ts - iat_ts} seconds")
    print(f"  Time until expiration: {exp_ts - now_ts} seconds")
    print()
    
    if exp_ts - iat_ts < 1800:
        print("⚠️  PROBLEM: Token lifetime is less than 30 minutes!")
        print(f"   Expected: 1800 seconds (30 minutes)")
        print(f"   Actual: {exp_ts - iat_ts} seconds")
    else:
        print("✓ Token lifetime is correct")
    
    if exp_ts < now_ts:
        print("⚠️  PROBLEM: Token is already expired!")
        print(f"   Expired {now_ts - exp_ts} seconds ago")
    else:
        print(f"✓ Token is valid for {exp_ts - now_ts} more seconds")
    
    print()
    
    # Validate token
    print("3. Validating token...")
    validate_response = requests.post(
        f"{BASE_URL}/token/validate",
        json={"token": token, "check_revocation": True}
    )
    
    validation = validate_response.json()
    print(f"  Valid: {validation['valid']}")
    print(f"  Revoked: {validation['revoked']}")
    print(f"  Message: {validation['message']}")
    print()
    
    if not validation['valid']:
        if "expired" in validation['message'].lower():
            print("⚠️  Token is expired (not revoked)")
        elif "revoked" in validation['message'].lower():
            print("⚠️  Token is revoked")
    else:
        print("✓ Token is valid!")

if __name__ == "__main__":
    try:
        debug_token()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

