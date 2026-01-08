from __future__ import annotations
import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from .utils import sha256, b64url_encode, canonical_json

@dataclass
class KeyRecord:
    kid: str
    jkt: str
    jwk: Dict[str, Any]
    created_at: int

@dataclass
class Checkpoint:
    idx: int
    epoch: int
    jwks_root_hash: str
    prev_hash: str
    entry_hash: str
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

            # Transparency log checkpoints
            c.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                  idx INTEGER PRIMARY KEY AUTOINCREMENT,
                  epoch INTEGER NOT NULL,
                  jwks_root_hash TEXT NOT NULL,
                  prev_hash TEXT NOT NULL,
                  entry_hash TEXT NOT NULL,
                  created_at INTEGER NOT NULL
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_checkpoints_epoch ON checkpoints(epoch)")
            c.commit()

    # -------------------- Keys --------------------
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

    # -------------------- Transparency checkpoints --------------------
    def _latest_checkpoint_row(self) -> Optional[sqlite3.Row]:
        with self._conn() as c:
            return c.execute("SELECT * FROM checkpoints ORDER BY idx DESC LIMIT 1").fetchone()

    def _verify_checkpoint_chain(self, c: sqlite3.Connection) -> bool:
        """Verify the integrity of the checkpoint chain"""
        rows = c.execute("SELECT * FROM checkpoints ORDER BY idx ASC").fetchall()
        if not rows:
            return True

        prev_entry_hash = b64url_encode(sha256(b"GENESIS"))
        for i, row in enumerate(rows):
            expected_prev_hash = prev_entry_hash
            actual_prev_hash = row["prev_hash"]

            if actual_prev_hash != expected_prev_hash:
                raise ValueError(f"Checkpoint chain broken at idx {row['idx']}: expected prev_hash {expected_prev_hash}, got {actual_prev_hash}")

            # Verify entry_hash computation
            entry_obj = {
                "epoch": int(row["epoch"]),
                "jwks_root_hash": row["jwks_root_hash"],
                "prev_hash": row["prev_hash"],
            }
            computed_entry_hash = b64url_encode(sha256(canonical_json(entry_obj)))
            if computed_entry_hash != row["entry_hash"]:
                raise ValueError(f"Checkpoint entry_hash mismatch at idx {row['idx']}")

            prev_entry_hash = row["entry_hash"]

        return True

    def append_checkpoint(self, epoch: int, jwks_root_hash: str) -> Checkpoint:
        now = int(time.time())
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            self._verify_checkpoint_chain(c)
            last = c.execute("SELECT * FROM checkpoints ORDER BY idx DESC LIMIT 1").fetchone()
            prev_hash = last["entry_hash"] if last else b64url_encode(sha256(b"GENESIS"))

            entry_obj = {
                "epoch": epoch,
                "jwks_root_hash": jwks_root_hash,
                "prev_hash": prev_hash,
            }
            entry_hash = b64url_encode(sha256(canonical_json(entry_obj)))

            c.execute("""
                INSERT INTO checkpoints(epoch, jwks_root_hash, prev_hash, entry_hash, created_at)
                VALUES(?,?,?,?,?)
            """, (epoch, jwks_root_hash, prev_hash, entry_hash, now))
            idx = int(c.execute("SELECT last_insert_rowid()").fetchone()[0])
            c.commit()

        return Checkpoint(
            idx=idx,
            epoch=epoch,
            jwks_root_hash=jwks_root_hash,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            created_at=now,
        )

    def list_checkpoints(self) -> List[Checkpoint]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM checkpoints ORDER BY idx ASC").fetchall()
            return [
                Checkpoint(
                    idx=int(r["idx"]),
                    epoch=int(r["epoch"]),
                    jwks_root_hash=r["jwks_root_hash"],
                    prev_hash=r["prev_hash"],
                    entry_hash=r["entry_hash"],
                    created_at=int(r["created_at"]),
                )
                for r in rows
            ]

    def get_checkpoint(self, idx: int) -> Optional[Checkpoint]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM checkpoints WHERE idx=?", (idx,)).fetchone()
            if not r:
                return None
            return Checkpoint(
                idx=int(r["idx"]),
                epoch=int(r["epoch"]),
                jwks_root_hash=r["jwks_root_hash"],
                prev_hash=r["prev_hash"],
                entry_hash=r["entry_hash"],
                created_at=int(r["created_at"]),
            )
