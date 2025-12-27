from __future__ import annotations
import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

@dataclass
class KeyRecord:
    kid: str
    jkt: str
    jwk: Dict[str, Any]
    created_at: int

class KeyStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                  kid TEXT PRIMARY KEY,
                  jkt TEXT NOT NULL,
                  jwk_json TEXT NOT NULL,
                  created_at INTEGER NOT NULL
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_keys_jkt ON keys(jkt)")
            c.commit()

    def upsert_key(self, kid: str, jkt: str, jwk: Dict[str, Any]) -> None:
        now = int(time.time())
        with self._conn() as c:
            c.execute("""
                INSERT INTO keys(kid, jkt, jwk_json, created_at)
                VALUES(?,?,?,?)
                ON CONFLICT(kid) DO UPDATE SET
                  jkt=excluded.jkt,
                  jwk_json=excluded.jwk_json,
                  created_at=excluded.created_at
            """, (kid, jkt, json.dumps(jwk, separators=(",", ":"), sort_keys=True), now))
            c.commit()

    def get_by_kid(self, kid: str) -> Optional[KeyRecord]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM keys WHERE kid=?", (kid,)).fetchone()
            if not row:
                return None
            return KeyRecord(
                kid=row["kid"],
                jkt=row["jkt"],
                jwk=json.loads(row["jwk_json"]),
                created_at=row["created_at"],
            )

    def get_by_jkt(self, jkt: str) -> Optional[KeyRecord]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM keys WHERE jkt=?", (jkt,)).fetchone()
            if not row:
                return None
            return KeyRecord(
                kid=row["kid"],
                jkt=row["jkt"],
                jwk=json.loads(row["jwk_json"]),
                created_at=row["created_at"],
            )

    def list_all(self) -> List[KeyRecord]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM keys ORDER BY kid").fetchall()
            return [
                KeyRecord(
                    kid=r["kid"],
                    jkt=r["jkt"],
                    jwk=json.loads(r["jwk_json"]),
                    created_at=r["created_at"],
                )
                for r in rows
            ]
