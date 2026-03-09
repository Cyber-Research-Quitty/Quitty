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
    status: str
    activated_at: int
    deactivated_at: Optional[int]
    last_updated_at: int

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
            key_columns = {row["name"] for row in c.execute("PRAGMA table_info(keys)").fetchall()}
            if "status" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            if "activated_at" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN activated_at INTEGER")
            if "deactivated_at" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN deactivated_at INTEGER")
            if "last_updated_at" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN last_updated_at INTEGER")
            c.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)")
            c.execute("""
                UPDATE keys
                SET status = COALESCE(NULLIF(status, ''), 'active'),
                    activated_at = COALESCE(activated_at, created_at),
                    last_updated_at = COALESCE(last_updated_at, created_at)
            """)

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
                INSERT INTO keys(kid, jkt, jwk_json, created_at, status, activated_at, deactivated_at, last_updated_at)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(kid) DO UPDATE SET
                  jkt=excluded.jkt,
                  jwk_json=excluded.jwk_json,
                  status='active',
                  activated_at=excluded.activated_at,
                  deactivated_at=NULL,
                  last_updated_at=excluded.last_updated_at
            """, (
                kid,
                jkt,
                json.dumps(jwk, separators=(",", ":"), sort_keys=True),
                now,
                "active",
                now,
                None,
                now,
            ))
            c.commit()

    def _row_to_key_record(self, row: sqlite3.Row) -> KeyRecord:
        return KeyRecord(
            kid=row["kid"],
            jkt=row["jkt"],
            jwk=json.loads(row["jwk_json"]),
            created_at=row["created_at"],
            status=row["status"],
            activated_at=row["activated_at"] or row["created_at"],
            deactivated_at=row["deactivated_at"],
            last_updated_at=row["last_updated_at"] or row["created_at"],
        )

    def get_by_kid(self, kid: str, include_inactive: bool = False) -> Optional[KeyRecord]:
        with self._conn() as c:
            query = "SELECT * FROM keys WHERE kid=?"
            params: Tuple[Any, ...] = (kid,)
            if not include_inactive:
                query += " AND status='active'"
            row = c.execute(query, params).fetchone()
            if not row:
                return None
            return self._row_to_key_record(row)

    def get_by_jkt(self, jkt: str, include_inactive: bool = False) -> Optional[KeyRecord]:
        with self._conn() as c:
            query = "SELECT * FROM keys WHERE jkt=?"
            params: Tuple[Any, ...] = (jkt,)
            if not include_inactive:
                query += " AND status='active'"
            row = c.execute(query, params).fetchone()
            if not row:
                return None
            return self._row_to_key_record(row)

    def list_all(self, include_inactive: bool = False) -> List[KeyRecord]:
        with self._conn() as c:
            query = "SELECT * FROM keys"
            if not include_inactive:
                query += " WHERE status='active'"
            query += " ORDER BY kid"
            rows = c.execute(query).fetchall()
            return [self._row_to_key_record(r) for r in rows]

    def count_keys(self, include_inactive: bool = True) -> int:
        with self._conn() as c:
            query = "SELECT COUNT(*) AS count FROM keys"
            if not include_inactive:
                query += " WHERE status='active'"
            row = c.execute(query).fetchone()
            return int(row["count"]) if row else 0

    def count_keys_by_status(self) -> Dict[str, int]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT status, COUNT(*) AS count
                FROM keys
                GROUP BY status
            """).fetchall()
            counts = {"active": 0, "inactive": 0}
            for row in rows:
                counts[row["status"]] = int(row["count"])
            counts["total"] = counts["active"] + counts["inactive"]
            return counts

    def delete_by_kid(self, kid: str) -> bool:
        now = int(time.time())
        with self._conn() as c:
            cur = c.execute("""
                UPDATE keys
                SET status='inactive',
                    deactivated_at=?,
                    last_updated_at=?
                WHERE kid=? AND status='active'
            """, (now, now, kid))
            c.commit()
            return int(cur.rowcount) > 0

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

    def list_recent_checkpoints(self, limit: int = 10) -> List[Checkpoint]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT * FROM checkpoints
                ORDER BY idx DESC
                LIMIT ?
            """, (limit,)).fetchall()
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
