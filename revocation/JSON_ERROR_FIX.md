# JSON Error Fix Guide

## Error: "Expecting ',' delimiter" at position 480

This error means your JSON request body has a syntax error. The JSON parser expected a comma but found something else.

## Correct JSON Format for `/token/refresh`

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_binding": "string",
  "client_public_key": "3DKgeTgX8jtl0aTsmpu_F5mB_rdlSNw1sPKWLnrM-SA"
}
```

## Common JSON Errors

### 1. Missing Comma
```json
❌ Wrong:
{
  "refresh_token": "token"
  "client_binding": "string"  // Missing comma!
}

✅ Correct:
{
  "refresh_token": "token",
  "client_binding": "string"
}
```

### 2. Extra Comma at End
```json
❌ Wrong:
{
  "refresh_token": "token",
  "client_binding": "string",  // Extra comma!
}

✅ Correct:
{
  "refresh_token": "token",
  "client_binding": "string"
}
```

### 3. Unclosed Quotes
```json
❌ Wrong:
{
  "refresh_token": "token,
  "client_binding": "string"
}

✅ Correct:
{
  "refresh_token": "token",
  "client_binding": "string"
}
```

### 4. Special Characters in Token
If your token contains special characters, make sure they're properly escaped or the string is properly quoted.

## How to Fix

### Option 1: Use Swagger UI
1. Go to http://localhost:8000/docs
2. Find `/token/refresh` endpoint
3. Click "Try it out"
4. Fill in the fields
5. Click "Execute"

Swagger UI will format the JSON correctly for you.

### Option 2: Validate Your JSON
Use an online JSON validator or run:
```bash
python test_refresh_json.py
```

### Option 3: Check Your curl Command
Make sure your JSON is properly formatted:

```bash
curl -X 'POST' \
  'http://localhost:8000/token/refresh' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "refresh_token": "YOUR_TOKEN_HERE",
  "client_binding": "string",
  "client_public_key": "YOUR_PUBLIC_KEY_HERE"
}'
```

**Important:** 
- Make sure there's a comma between each field
- No trailing comma after the last field
- All strings are properly quoted
- No line breaks inside string values (unless escaped)

## Quick Test

Copy this exact format and replace the values:

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHJpbmciLCJleHAiOjE3NzUxMjk4OTcsImlhdCI6MTc2NzM1Mzg5NywiaXNzIjoicDQtcmV2b2NhdGlvbi1zZXJ2aWNlIiwianRpIjoiMTA1OTNlYWEtMTRiMS00ZmFhLTk4OTQtNGFmZjI4NTc3YmZiIiwidHlwZSI6InJlZnJlc2giLCJjbGllbnRfaGFzaCI6IjQ3MzI4N2Y4Mjk4ZGJhNzE2M2E4OTc5MDg5NThmN2MwZWFlNzMzZTI1ZDJlMDI3OTkyZWEyZWRjOWJlZDJmYTgiLCJreWJlcl9wdWIiOiIzREtnZVRnWDhqdGwwYVRzbXB1X0Y1bUJfcmRsU053MXNQS1dMbnJNLVNBIn0.PprXBPCrDogX_gwwCZKsYib_t4f9L4rvI__A2HXzmrw",
  "client_binding": "string",
  "client_public_key": "3DKgeTgX8jtl0aTsmpu_F5mB_rdlSNw1sPKWLnrM-SA"
}
```

## Position 480 Error

If the error is at position 480, that's likely in the middle of your `refresh_token` string. Check:
1. The token string is properly quoted
2. No unescaped quotes inside the token
3. The token is complete (not truncated)

## Still Having Issues?

1. Use Swagger UI at http://localhost:8000/docs (easiest)
2. Use Postman or another API client
3. Check your JSON with: https://jsonlint.com/
4. Make sure you're using the latest refresh token (they expire)

