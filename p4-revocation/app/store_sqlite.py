import sqlite3
from typing import Optional
from .config import SQLITE_PATH

def init_sqlite(db_path: Optional[str] = None) -> None:
    path = db_path or SQLITE_PATH
    conn = sqlite3.connect(path)
    
    # Revocation events table
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
    
    # Refresh tokens audit table
    conn.execute("""
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token_id TEXT PRIMARY KEY,
      subject  TEXT NOT NULL,
      client_hash TEXT NOT NULL,
      kyber_public_key TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked BOOLEAN DEFAULT 0,
      revoked_at TEXT,
      last_used_at TEXT
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_refresh_subject ON refresh_tokens(subject);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_refresh_client_hash ON refresh_tokens(client_hash);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);")
    
    # Token events audit table (for Kafka event tracking)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS token_events (
      event_id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      token_id TEXT,
      subject TEXT,
      ts TEXT NOT NULL,
      data TEXT,
      published BOOLEAN DEFAULT 0
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_token_events_type ON token_events(event_type);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_token_events_ts ON token_events(ts);")
    
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


def insert_refresh_token(
    token_id: str,
    subject: str,
    client_hash: str,
    kyber_public_key: Optional[str],
    created_at: str,
    expires_at: str,
    db_path: Optional[str] = None
) -> None:
    """Insert refresh token record into audit log"""
    path = db_path or SQLITE_PATH
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO refresh_tokens(token_id, subject, client_hash, kyber_public_key, 
           created_at, expires_at) VALUES (?,?,?,?,?,?)""",
        (token_id, subject, client_hash, kyber_public_key, created_at, expires_at)
    )
    conn.commit()
    conn.close()


def update_refresh_token_usage(token_id: str, last_used_at: str, db_path: Optional[str] = None) -> None:
    """Update refresh token last used timestamp"""
    path = db_path or SQLITE_PATH
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE refresh_tokens SET last_used_at = ? WHERE token_id = ?",
        (last_used_at, token_id)
    )
    conn.commit()
    conn.close()


def revoke_refresh_token(token_id: str, revoked_at: str, db_path: Optional[str] = None) -> None:
    """Mark refresh token as revoked"""
    path = db_path or SQLITE_PATH
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE refresh_tokens SET revoked = 1, revoked_at = ? WHERE token_id = ?",
        (revoked_at, token_id)
    )
    conn.commit()
    conn.close()


def insert_token_event(
    event_id: str,
    event_type: str,
    token_id: Optional[str],
    subject: Optional[str],
    ts: str,
    data: Optional[str],
    published: bool = False,
    db_path: Optional[str] = None
) -> None:
    """Insert token event into audit log"""
    path = db_path or SQLITE_PATH
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO token_events(event_id, event_type, token_id, subject, ts, data, published) 
           VALUES (?,?,?,?,?,?,?)""",
        (event_id, event_type, token_id, subject, ts, data, published)
    )
    conn.commit()
    conn.close()
