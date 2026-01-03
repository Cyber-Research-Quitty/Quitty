#!/usr/bin/env python3
"""
Script to explore and visualize the transparency log
"""
import sqlite3
import json
from datetime import datetime

def print_section(title):
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)

# Connect to database
conn = sqlite3.connect('data/keys.db')
cursor = conn.cursor()

# 1. Show all checkpoints
print_section("📋 CHECKPOINT HISTORY - Complete Audit Trail")
cursor.execute("""
    SELECT idx, epoch, jwks_root_hash, prev_hash, entry_hash 
    FROM checkpoints 
    ORDER BY idx
""")

checkpoints = cursor.fetchall()
for idx, epoch, root_hash, prev_hash, entry_hash in checkpoints:
    timestamp = datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n🔗 Checkpoint #{idx} - {timestamp}")
    print(f"   JWKS Root Hash: {root_hash[:40]}...")
    print(f"   Previous Hash:  {prev_hash[:40]}...")
    print(f"   Entry Hash:     {entry_hash[:40]}...")
    
# 2. Show checkpoint chain verification
print_section("🔗 CHECKPOINT CHAIN - Blockchain-like Integrity")
print("\nVerifying checkpoint chain integrity...")
prev = None
chain_valid = True
for idx, epoch, root_hash, prev_hash, entry_hash in checkpoints:
    timestamp = datetime.fromtimestamp(epoch).strftime('%H:%M:%S')
    if prev is not None:
        if prev[4] == prev_hash:  # prev entry_hash should match current prev_hash
            status = "✅ VALID"
        else:
            status = "❌ BROKEN"
            chain_valid = False
        print(f"  CP#{idx-1} → CP#{idx}: {status} ({timestamp})")
    prev = (idx, epoch, root_hash, prev_hash, entry_hash)

if chain_valid:
    print("\n✅ Chain integrity: VALID - All checkpoints properly linked!")
else:
    print("\n❌ Chain integrity: BROKEN - Tampering detected!")

# 3. Show keys and when they were added
print_section("🔑 KEY IMPORT TIMELINE")
cursor.execute("""
    SELECT kid, kty, alg, created_at 
    FROM keys 
    ORDER BY created_at
""")

keys = cursor.fetchall()
for kid, kty, alg, created_at in keys:
    timestamp = datetime.fromtimestamp(created_at).strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n📌 {timestamp}")
    print(f"   Key ID:     {kid}")
    print(f"   Type:       {kty}")
    print(f"   Algorithm:  {alg}")

# 4. Correlate checkpoints with key additions
print_section("🔄 CHECKPOINT ↔ KEY CORRELATION")
print("\nMatching checkpoints to key import events...\n")

cursor.execute("SELECT kid, created_at FROM keys ORDER BY created_at")
key_times = {kid: created_at for kid, created_at in cursor.fetchall()}

for idx, epoch, root_hash, prev_hash, entry_hash in checkpoints:
    timestamp = datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
    print(f"Checkpoint #{idx} at {timestamp}")
    
    # Find keys added around this time (within 10 seconds)
    keys_nearby = [kid for kid, kt in key_times.items() if abs(kt - epoch) < 10]
    if keys_nearby:
        print(f"  📥 Likely triggered by: {', '.join(keys_nearby)}")
    else:
        print(f"  🔧 Likely triggered by: Tree rebuild or system event")
    print(f"  🌳 JWKS Root: {root_hash[:50]}...")

# 5. Show transparency log statistics
print_section("📊 TRANSPARENCY LOG STATISTICS")
cursor.execute("SELECT COUNT(*) FROM checkpoints")
cp_count = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM keys")
key_count = cursor.fetchone()[0]

cursor.execute("SELECT MIN(epoch), MAX(epoch) FROM checkpoints")
min_epoch, max_epoch = cursor.fetchone()
duration = (max_epoch - min_epoch) / 60  # minutes

print(f"""
📈 Summary:
   Total Checkpoints:  {cp_count}
   Total Keys:         {key_count}
   Time Span:          {duration:.1f} minutes
   Avg CP Frequency:   {duration/cp_count:.1f} min/checkpoint
   
🔒 Security Properties:
   ✅ Append-only log (checkpoints never deleted)
   ✅ Tamper-evident (each CP links to previous)
   ✅ Verifiable (any client can audit the chain)
   ✅ Transparent (all changes are logged)
""")

# 6. Explain what each checkpoint represents
print_section("📖 UNDERSTANDING CHECKPOINTS")
print("""
What is a Checkpoint?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

A checkpoint is a cryptographic snapshot of the JWKS state at a specific moment.

Structure:
  • idx:            Sequential index (like a block number)
  • epoch:          Unix timestamp (when this state was recorded)
  • jwks_root_hash: Merkle root of all keys at this moment
  • prev_hash:      Links to previous checkpoint (blockchain-style)
  • entry_hash:     Hash of this checkpoint entry itself

Why This Matters:
  1. **Audit Trail**: See exactly when keys were added/changed
  2. **Tamper Detection**: Any change breaks the chain
  3. **Historical Verification**: Prove a key existed at a specific time
  4. **Accountability**: All changes are permanently recorded
  5. **Transparency**: Anyone can verify the log independently

Transparency Log vs Merkle Tree:
  • Merkle Tree:       Proves a key EXISTS in the current set
  • Transparency Log:  Proves WHEN and HOW the set changed over time
""")

conn.close()
