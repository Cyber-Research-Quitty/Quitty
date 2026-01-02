"""
Test script to debug the token expiration issue
Run this to verify tokens are created and validated correctly
"""
import requests
import json
from datetime import datetime, timezone
import jwt

BASE_URL = "http://localhost:8000"

def test_token_creation_and_validation():
    """Test creating a token and immediately validating it"""
    print("=" * 60)
    print("Testing Token Creation and Validation")
    print("=" * 60)
    print()
    
    # Step 1: Create a token
    print("1. Creating access token...")
    try:
        response = requests.post(
            f"{BASE_URL}/token",
            json={
                "subject": "test_user",
                "expires_minutes": 60  # 1 hour expiration
            }
        )
        
        if response.status_code != 200:
            print(f"   ✗ Error creating token: {response.status_code}")
            print(f"   Response: {response.text}")
            return
        
        token_data = response.json()
        access_token = token_data["access_token"]
        jti = token_data["jti"]
        
        print(f"   ✓ Token created successfully")
        print(f"   JTI: {jti}")
        print(f"   Expires in: {token_data['expires_in']} seconds")
        print()
        
        # Decode token to check expiration
        try:
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            exp_timestamp = decoded.get("exp")
            iat_timestamp = decoded.get("iat")
            
            if exp_timestamp:
                exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
                iat_datetime = datetime.fromtimestamp(iat_timestamp, tz=timezone.utc) if iat_timestamp else None
                now = datetime.now(timezone.utc)
                
                print(f"   Token Details:")
                print(f"   - Issued at: {iat_datetime}")
                print(f"   - Expires at: {exp_datetime}")
                print(f"   - Current time: {now}")
                print(f"   - Time until expiration: {(exp_datetime - now).total_seconds()} seconds")
                print()
                
                if exp_datetime < now:
                    print(f"   ⚠️  WARNING: Token expiration is in the past!")
                    print(f"   This is the bug - token appears expired immediately")
                else:
                    print(f"   ✓ Token expiration is in the future")
        except Exception as e:
            print(f"   ⚠️  Could not decode token: {e}")
            print()
        
        # Step 2: Immediately validate the token
        print("2. Validating token immediately after creation...")
        try:
            validate_response = requests.post(
                f"{BASE_URL}/token/validate",
                json={
                    "token": access_token,
                    "check_revocation": True
                }
            )
            
            if validate_response.status_code == 200:
                validation = validate_response.json()
                print(f"   Validation Response:")
                print(f"   - Valid: {validation['valid']}")
                print(f"   - Revoked: {validation['revoked']}")
                print(f"   - Message: {validation['message']}")
                print()
                
                if not validation['valid']:
                    print(f"   ✗ PROBLEM: Token is invalid!")
                    if validation['revoked']:
                        print(f"   - Token shows as REVOKED (but it was just created)")
                    if "expired" in validation['message'].lower():
                        print(f"   - Token shows as EXPIRED (but it should be valid)")
                    
                    # Check claims
                    claims = validation.get('claims', {})
                    if claims:
                        exp_claim = claims.get('exp')
                        if exp_claim:
                            exp_dt = datetime.fromtimestamp(exp_claim, tz=timezone.utc)
                            now = datetime.now(timezone.utc)
                            print(f"   - Expiration claim: {exp_dt}")
                            print(f"   - Current time: {now}")
                            print(f"   - Difference: {(exp_dt - now).total_seconds()} seconds")
                else:
                    print(f"   ✓ Token is valid!")
            else:
                print(f"   ✗ Error validating token: {validate_response.status_code}")
                print(f"   Response: {validate_response.text}")
        except Exception as e:
            print(f"   ✗ Exception during validation: {e}")
            import traceback
            traceback.print_exc()
        
    except Exception as e:
        print(f"   ✗ Exception: {e}")
        import traceback
        traceback.print_exc()

def test_inspect_token():
    """Test inspecting a token"""
    print()
    print("=" * 60)
    print("Testing Token Inspection")
    print("=" * 60)
    print()
    
    # Create a token first
    response = requests.post(
        f"{BASE_URL}/token",
        json={"subject": "test_user"}
    )
    
    if response.status_code == 200:
        token = response.json()["access_token"]
        
        print("Inspecting token...")
        inspect_response = requests.get(
            f"{BASE_URL}/token/inspect",
            params={"token": token}
        )
        
        if inspect_response.status_code == 200:
            data = inspect_response.json()
            claims = data.get("claims", {})
            
            print(f"Claims:")
            for key, value in claims.items():
                if key in ["exp", "iat"]:
                    dt = datetime.fromtimestamp(value, tz=timezone.utc)
                    print(f"  {key}: {value} ({dt})")
                else:
                    print(f"  {key}: {value}")

if __name__ == "__main__":
    print()
    print("Token Issue Debugging Script")
    print("Make sure the server is running on http://localhost:8000")
    print()
    
    try:
        # Test health first
        health = requests.get(f"{BASE_URL}/health", timeout=5)
        if health.status_code != 200:
            print("Server is not responding correctly!")
            exit(1)
        
        test_token_creation_and_validation()
        test_inspect_token()
        
        print()
        print("=" * 60)
        print("Test Complete")
        print("=" * 60)
        
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to server.")
        print("Make sure the server is running on http://localhost:8000")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

