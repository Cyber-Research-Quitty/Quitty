# python .\check_db.py

import sqlite3
from pprint import pprint

db_path = r"..\data\keys.db"

conn = sqlite3.connect(db_path)
cur = conn.cursor()

print("=== TABLES ===")
cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
pprint(cur.fetchall())

# print("\n=== KEYS SCHEMA ===")
# cur.execute("PRAGMA table_info(keys);")
# pprint(cur.fetchall())

# print("\n=== CHECKPOINTS SCHEMA ===")
# cur.execute("PRAGMA table_info(checkpoints);")
# pprint(cur.fetchall())

# print("\n=== KEYS ROWS ===")
# cur.execute("SELECT * FROM keys;")
# pprint(cur.fetchall())

# print("\n=== CHECKPOINTS ROWS ===")
# cur.execute("SELECT * FROM checkpoints;")
# pprint(cur.fetchall())



# cur.execute("SELECT * FROM checkpoints ORDER BY idx DESC LIMIT 1;")


conn.close()