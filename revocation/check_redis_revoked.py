"""
Script to check what's in Redis that might be causing tokens to be revoked
"""
import asyncio
import redis.asyncio as redis

async def check_redis():
    rds = redis.from_url("redis://localhost:6379/0", decode_responses=True)
    
    print("Checking Redis for revocation entries...")
    print("=" * 60)
    
    # Check all revoked keys
    revoked_keys = await rds.keys("revoked:*")
    
    if revoked_keys:
        print(f"Found {len(revoked_keys)} revocation entries:")
        print()
        for key in revoked_keys:
            value = await rds.get(key)
            print(f"  {key}: {value}")
    else:
        print("No revocation entries found in Redis")
    
    print()
    print("=" * 60)
    print("Checking for specific subject 'string':")
    sub_key = "revoked:sub:string"
    sub_value = await rds.get(sub_key)
    if sub_value:
        print(f"  ⚠️  FOUND: {sub_key} = {sub_value}")
        print(f"  This means ALL tokens for subject 'string' are revoked!")
        print(f"  To fix: Delete this key or revoke with TTL")
    else:
        print(f"  ✓ No revocation for subject 'string'")
    
    await rds.close()

if __name__ == "__main__":
    try:
        asyncio.run(check_redis())
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure Redis is running")

