"""
Script to clear revocation entries from Redis
Use this if you accidentally revoked all tokens for a subject
"""
import asyncio
import redis.asyncio as redis
import sys

async def clear_revocation(subject: str = None, jti: str = None):
    """Clear revocation entries from Redis"""
    rds = redis.from_url("redis://localhost:6379/0", decode_responses=True)
    
    if subject:
        key = f"revoked:sub:{subject}"
        deleted = await rds.delete(key)
        if deleted:
            print(f"✓ Cleared revocation for subject: {subject}")
        else:
            print(f"✗ No revocation found for subject: {subject}")
    
    if jti:
        key = f"revoked:jti:{jti}"
        deleted = await rds.delete(key)
        if deleted:
            print(f"✓ Cleared revocation for JTI: {jti}")
        else:
            print(f"✗ No revocation found for JTI: {jti}")
    
    if not subject and not jti:
        # Show all revocations
        keys = await rds.keys("revoked:*")
        if keys:
            print("Current revocation entries:")
            for key in keys:
                value = await rds.get(key)
                print(f"  {key}: {value}")
            print("\nTo clear a revocation, use:")
            print("  python clear_revocation.py --subject <subject>")
            print("  python clear_revocation.py --jti <jti>")
        else:
            print("No revocation entries found")
    
    await rds.close()

if __name__ == "__main__":
    subject = None
    jti = None
    
    if "--subject" in sys.argv:
        idx = sys.argv.index("--subject")
        if idx + 1 < len(sys.argv):
            subject = sys.argv[idx + 1]
    
    if "--jti" in sys.argv:
        idx = sys.argv.index("--jti")
        if idx + 1 < len(sys.argv):
            jti = sys.argv[idx + 1]
    
    if not subject and not jti:
        print("Usage:")
        print("  python clear_revocation.py --subject <subject>")
        print("  python clear_revocation.py --jti <jti>")
        print("\nOr run without arguments to see all revocations")
        print()
    
    try:
        asyncio.run(clear_revocation(subject, jti))
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure Redis is running")

