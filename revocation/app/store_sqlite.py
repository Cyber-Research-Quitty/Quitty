import sqlite3
from typing import Optional
from .config import SQLITE_PATH

def init_sqlite(db_path: Optional[str] = None) -> None:
    path = db_path or SQLITE_PATH
    conn = sqlite3.connect(path)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS revocation_events (
      event_id TEXT PRIMARY KEY,
      type     TEXT NOT NULL,
      value    TEXT NOT NULL,
      ts       TEXT NOT NULL,
      nonce    TEXT NOT NULL,
      kid      TEXT NOT NULL,
      sig      TEXT NOT NULL
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rev_type_value ON revocation_events(type, value);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rev_ts ON revocation_events(ts);")
    conn.commit()
    conn.close()

def insert_event(event: dict, db_path: Optional[str] = None) -> None:
    path = db_path or SQLITE_PATH
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO revocation_events(event_id, type, value, ts, nonce, kid, sig) VALUES (?,?,?,?,?,?,?)",
        (event["event_id"], event["type"], event["value"], event["ts"], event["nonce"], event["kid"], event["sig"])
    )
    conn.commit()
    conn.close()
