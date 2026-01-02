"""
Test script to validate JSON format for refresh token endpoint
"""
import json

# Example of correct JSON format
correct_json = {
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHJpbmciLCJleHAiOjE3NzUxMjk4OTcsImlhdCI6MTc2NzM1Mzg5NywiaXNzIjoicDQtcmV2b2NhdGlvbi1zZXJ2aWNlIiwianRpIjoiMTA1OTNlYWEtMTRiMS00ZmFhLTk4OTQtNGFmZjI4NTc3YmZiIiwidHlwZSI6InJlZnJlc2giLCJjbGllbnRfaGFzaCI6IjQ3MzI4N2Y4Mjk4ZGJhNzE2M2E4OTc5MDg5NThmN2MwZWFlNzMzZTI1ZDJlMDI3OTkyZWEyZWRjOWJlZDJmYTgiLCJreWJlcl9wdWIiOiIzREtnZVRnWDhqdGwwYVRzbXB1X0Y1bUJfcmRsU053MXNQS1dMbnJNLVNBIn0.PprXBPCrDogX_gwwCZKsYib_t4f9L4rvI__A2HXzmrw",
    "client_binding": "string",
    "client_public_key": "3DKgeTgX8jtl0aTsmpu_F5mB_rdlSNw1sPKWLnrM-SA"
}

print("Correct JSON format:")
print(json.dumps(correct_json, indent=2))
print()

# Test JSON parsing
try:
    json_str = json.dumps(correct_json)
    parsed = json.loads(json_str)
    print("✓ JSON is valid")
    print(f"  refresh_token length: {len(parsed['refresh_token'])}")
    print(f"  client_binding: {parsed['client_binding']}")
    print(f"  client_public_key: {parsed['client_public_key']}")
except json.JSONDecodeError as e:
    print(f"✗ JSON error: {e}")
    print(f"  Position: {e.pos}")
    print(f"  Message: {e.msg}")

print()
print("Common JSON errors to check:")
print("1. Missing comma between fields")
print("2. Extra comma at the end")
print("3. Unclosed quotes in strings")
print("4. Special characters not escaped")
print("5. Trailing commas")

