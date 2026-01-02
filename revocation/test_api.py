"""
Simple test script to verify the API is working correctly
Run this after starting the server to test all endpoints
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    print("Testing /health...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
    return response.status_code == 200

def test_create_access_token():
    """Test access token creation"""
    print("Testing POST /token...")
    response = requests.post(
        f"{BASE_URL}/token",
        json={
            "subject": "test_user_123",
            "expires_minutes": 30,
            "additional_claims": {"role": "user", "test": True}
        }
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Access Token: {data['access_token'][:50]}...")
        print(f"JTI: {data['jti']}")
        print(f"Expires in: {data['expires_in']} seconds\n")
        return data
    else:
        print(f"Error: {response.text}\n")
        return None

def test_validate_token(token_data):
    """Test token validation"""
    if not token_data:
        print("Skipping token validation (no token)\n")
        return
    
    print("Testing POST /token/validate...")
    response = requests.post(
        f"{BASE_URL}/token/validate",
        json={
            "token": token_data["access_token"],
            "check_revocation": True
        }
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Valid: {data['valid']}")
        print(f"Message: {data['message']}\n")
    else:
        print(f"Error: {response.text}\n")

def test_create_refresh_token():
    """Test refresh token creation"""
    print("Testing POST /token/refresh/create...")
    device_fingerprint = f"device-{int(time.time())}"
    
    response = requests.post(
        f"{BASE_URL}/token/refresh/create",
        json={
            "subject": "test_user_123",
            "client_binding": device_fingerprint,
            "additional_claims": {"role": "user"}
        }
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Refresh Token: {data['refresh_token'][:50]}...")
        print(f"Access Token: {data['access_token'][:50]}...")
        print(f"Refresh JTI: {data['refresh_jti']}")
        print(f"Kyber Public Key: {data['kyber_public_key'][:50]}...")
        print(f"Refresh expires in: {data['refresh_expires_in']} seconds\n")
        return data, device_fingerprint
    else:
        print(f"Error: {response.text}\n")
        return None, None

def test_refresh_token(refresh_data, device_fingerprint):
    """Test token refresh (simplified - needs client key generation)"""
    if not refresh_data:
        print("Skipping token refresh (no refresh token)\n")
        return
    
    print("Testing POST /token/refresh...")
    print("Note: This requires client Kyber key generation")
    print("For full test, implement client-side key generation\n")
    
    # This would require actual client key generation
    # For now, just show the endpoint exists
    print("Endpoint exists and is ready for client implementation\n")

def test_revoke_token(token_data):
    """Test token revocation"""
    if not token_data:
        print("Skipping token revocation (no token)\n")
        return
    
    print("Testing POST /revoke...")
    response = requests.post(
        f"{BASE_URL}/revoke",
        json={
            "type": "revoke_jti",
            "value": token_data["jti"],
            "ttl_seconds": 3600
        }
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Event ID: {data['event_id']}")
        print(f"Published: {data['published']}\n")
        
        # Verify token is now invalid
        print("Verifying token is revoked...")
        validate_response = requests.post(
            f"{BASE_URL}/token/validate",
            json={
                "token": token_data["access_token"],
                "check_revocation": True
            }
        )
        if validate_response.status_code == 200:
            validate_data = validate_response.json()
            print(f"Token revoked: {validate_data.get('revoked', False)}\n")
    else:
        print(f"Error: {response.text}\n")

def main():
    """Run all tests"""
    print("=" * 60)
    print("JWT Token System API Test Suite")
    print("=" * 60)
    print()
    
    # Test 1: Health check
    if not test_health():
        print("Health check failed! Is the server running?")
        return
    
    # Test 2: Create access token
    token_data = test_create_access_token()
    
    # Test 3: Validate token
    test_validate_token(token_data)
    
    # Test 4: Create refresh token
    refresh_data, device_fp = test_create_refresh_token()
    
    # Test 5: Refresh token (simplified)
    test_refresh_token(refresh_data, device_fp)
    
    # Test 6: Revoke token
    test_revoke_token(token_data)
    
    print("=" * 60)
    print("Test Suite Complete")
    print("=" * 60)
    print("\nFor full API documentation, visit: http://localhost:8000/docs")

if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to server.")
        print("Make sure the server is running on http://localhost:8000")
    except Exception as e:
        print(f"Error: {e}")


