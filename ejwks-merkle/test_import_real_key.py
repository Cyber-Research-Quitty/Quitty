#!/usr/bin/env python3
"""
Test script to import the real Dilithium2 key into the EJWKS service
"""
import requests
import json

# The real key data from root_signer_key.json
# We only send the PUBLIC key to the JWKS endpoint
jwk_payload = {
    "kid": "root-dilithium2-2",
    "kty": "OKP",
    "alg": "dilithium2",
    "crv": "Dilithium2",
    "x": "oKd5SjwmVXtNmVEg1oKx1bKt9Ie7Alc77ScEn8GTcZaBNee4Ozsoo91jWj7NB9YskiFgn6bKfE2ynDFzfjNtgghM8_2OoPL5cq9iH0RQDBu-f29z0OaNUHV6iQDuTpszLf1fBVrw7kuj2xAizLNvHg37D3DeO8gjpgf4_xeRGwMNuLZSMKd2huc9ZjMu4HgIbjwnPsVXaLWUQC7Bov7vLdVSYgLLwQIRugfj7Sku09LoN_qaELd3W-lscbpeeaIA_Oshfewttax5Z4mBExCj4xxr7HgS_ghD9s7vnBeyYXvK6JJ53pphXQR3bfUpAuVnHlKHlrfsjXkrwtZmtlfSOB_YAcyABa3nfVT_MEdZzbAmEWVRictw2sA5MoXK05JO1SYjONIkdNhazQ5j8rU2qFsmwbyP7wacpdWmVbABS2Jq-DzL-uNXbHV0jcAzQR62JIx1EiliMqa799PqMGi9X8Vt6V-y-awQ16wkci7moQ6nPFRG456CTefwD1Qxx7G1c1nfWpI6bYPtSYbgxBTp27rrHVrLKsaWmLtFVD7C3rdgJklYKlB_1AY5o1MXCaxD44CuM0zqZxkC_GT8IgahATFdE3XHLRxFFex5KwEg1SNuuniGOb1CK_lO9rjJ671aBPu-Tewd5EDFujXNozhLzJQPaE45vrhcz6x52nSXgUyS00SL-cKbCSNXwIVPRxDMFm0iGtMGFp2jGqnE5KLqVb_wK7Qp20vhxtO5y6bhB1X8VnbJLyxbMjZMVLaaAKnFmxjMZHYwXUcVMw-YxUeJR9cURdA3mH6BAF85xU0wd6TQ_pLNcnqET-i58CKGQDa55pVNw5eTt2MScfhRauVtKE9Cnped94w2QSkRc5pBFr5-j3-Swzly5A1DXlW91_bcvKXQoCDErXImIg3eQeNnCVbA2CI9wSXMgxKNfQThLF5mgERlWZH5wB55JVUlq09kPz0leVvblpaSrNokANEwt4lICv9vRh2OolPgBs1Jyw5BX4usAm6j94iu8U1JdrZacWNOvp0De5McHAgOHWy_eoIZM76w8i-SrJkw_fjS0EVoqoSFl9jmiAFPvtzQdYMXxFIhsFOK4ZtZTid0bhCl-Vl2yLmKamPiUnZO4k7KYsZlISFIIjaaoQQOH0MoFjS1IlsmhQnid_hdo6KwsdMkK8-mgqY6A9XCED_9IUyeTPquwTeHOAMgw4VUZmLC0SXzX9fis_6HLMx8Olse2Ptb--FVDL5YO74YdJ8BARzI3bWVP3uhWQfDGMF2A_IFGA2DySDut3s1Tko1LsBRX5r3XsQQ-LNmv3pZjoKQwj1IO2TPGvo4ldAmUvIhuoWROwJPDRqSxn8tyLYBMsJL1Ufmd9DmpstbzH0D4aIYtuBMjA--brQkrK5YX8ow15-552ZefdplWVLO5vwuRxgL0CoX2iMSFnOR5Y54JQv2GwfjB7B9y3JIc0riTNmnWbWK3Dr3-HfZJZlxVX5YLr_AP1AS73-d6jhkQfZKV5qCXIilueS94ZYlBs21vfGr-KcHlAWH2_SvvSnlOZNw0xU4R-oaqzPm8KSqHw3CR5M4mMk3LT_0SIgwjwKV2IMbvTfYR_5biZHyTWPqhwWnW4NBmWoFUQjAKciWoEOaRKO3bvkt8djYtr-LhR0a7482SkCewW5NOI95HmhUx7EaD7tUiCeah7WHgR1kVpJKCqs6XJFeSh7zs9_PTFbFUTe3v1jEyYYgjstI16fXQpURIcQQXV_okA",
    "use": "sig"
}

url = "http://localhost:8000/internal/keys/import"

print("=" * 60)
print("Testing /internal/keys/import with REAL Dilithium2 key")
print("=" * 60)
print(f"\nEndpoint: {url}")
print(f"Key ID: {jwk_payload['kid']}")
print(f"Algorithm: {jwk_payload['alg']}")
print(f"Curve: {jwk_payload['crv']}")
print(f"Public key length: {len(jwk_payload['x'])} characters")
print("\nSending request...")

try:
    response = requests.post(
        url,
        json=jwk_payload,
        headers={"Content-Type": "application/json"},
        timeout=10
    )
    
    print(f"\nStatus Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    
    if response.status_code == 200:
        print("\n✅ SUCCESS! Key imported successfully!")
        result = response.json()
        print(f"\nResponse:")
        print(json.dumps(result, indent=2))
        print(f"\n✅ Key ID: {result['kid']}")
        print(f"✅ JKT (thumbprint): {result['jkt']}")
    else:
        print(f"\n❌ FAILED with status {response.status_code}")
        print(f"Response: {response.text}")
        
except requests.exceptions.ConnectionError:
    print("\n❌ ERROR: Could not connect to http://localhost:8000")
    print("Make sure the EJWKS service is running:")
    print("  docker compose up -d")
    print("  OR")
    print("  uvicorn app.main:app --reload --port 8000")
except Exception as e:
    print(f"\n❌ ERROR: {e}")

print("\n" + "=" * 60)
