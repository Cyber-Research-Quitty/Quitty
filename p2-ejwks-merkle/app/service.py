from __future__ import annotations
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from redis import Redis

from .bloom import BloomFilter
from .log_merkle import LogMerkleTree
from .merkle import MerkleTree
from .signer import RootSigner, sign_root_bundle
from .storage import KeyStore
from .utils import b64url_encode, jwk_thumbprint, public_jwk

class EJWKSService:
    def __init__(
        self,
        store: KeyStore,
        redis: Redis,
        root_signer: RootSigner,
        log_signer: RootSigner,
        bloom_bits: int,
        bloom_hashes: int,
        bloom_enabled: bool = True,
    ) -> None:
        self.store = store
        self.redis = redis
        self.root_signer = root_signer
        self.log_signer = log_signer
        self._bloom_bits = bloom_bits
        self._bloom_hashes = bloom_hashes
        self.bloom_enabled = bloom_enabled
        self.bloom = BloomFilter(m_bits=bloom_bits, k_hashes=bloom_hashes)

    # ---------------- JWKS Merkle ----------------
    def rebuild_tree(self) -> Dict[str, Any]:
        keys = self.store.list_all()
        id_to_jwk = {k.kid: k.jwk for k in keys}

        tree = MerkleTree.build(id_to_jwk)
        jwks_root_b64 = tree.root_b64()
        epoch = int(time.time())

        # Build new bloom filter before swapping (atomic operation)
        new_bloom = BloomFilter(m_bits=self._bloom_bits, k_hashes=self._bloom_hashes)
        for rec in keys:
            new_bloom.add(rec.kid)
            new_bloom.add(rec.jkt)
        
        # Atomically swap bloom filter
        self.bloom = new_bloom

        # Sign JWKS root
        jwks_bundle = sign_root_bundle(self.root_signer, root_b64=jwks_root_b64, epoch=epoch)
        self.redis.set("root:jwks_bundle", json.dumps(jwks_bundle), ex=24 * 3600)

        # Remove stale cache entries for keys that are no longer active.
        stale_keys: List[bytes | str] = []
        for pattern in ("key:kid:*", "proof:kid:*", "jkt:kid:*", "kid_by_jkt:*"):
            stale_keys.extend(list(self.redis.scan_iter(match=pattern)))
        if stale_keys:
            self.redis.delete(*stale_keys)

        # Cache key+proofs
        pipe = self.redis.pipeline()
        for rec in keys:
            proof_items = [item.__dict__ for item in tree.proof_for_id(rec.kid)]
            pipe.set(f"key:kid:{rec.kid}", json.dumps(rec.jwk), ex=24 * 3600)
            pipe.set(f"proof:kid:{rec.kid}", json.dumps(proof_items), ex=24 * 3600)
            pipe.set(f"jkt:kid:{rec.kid}", rec.jkt, ex=24 * 3600)
            pipe.set(f"kid_by_jkt:{rec.jkt}", rec.kid, ex=24 * 3600)
        pipe.execute()

        # ---------------- Transparency log checkpoint ----------------
        cp = self.store.append_checkpoint(epoch=epoch, jwks_root_hash=jwks_root_b64)
        self._rebuild_log_cache()

        return jwks_bundle

    def _rebuild_log_cache(self) -> None:
        cps = self.store.list_checkpoints()
        entry_hashes = [cp.entry_hash for cp in cps]
        log_tree = LogMerkleTree.build_from_entry_hashes(entry_hashes)
        log_root_b64 = log_tree.root_b64()

        # Sign log root (separate signer)
        now = int(time.time())
        log_bundle = sign_root_bundle(self.log_signer, root_b64=log_root_b64, epoch=now)
        self.redis.set("log:bundle", json.dumps(log_bundle), ex=24 * 3600)

        pipe = self.redis.pipeline()
        for i, cp in enumerate(cps):
            proof = [p.__dict__ for p in log_tree.proof_for_index(i)]
            pipe.set(f"log:proof:{cp.idx}", json.dumps(proof), ex=24 * 3600)
        pipe.execute()

    # ---------------- Admin import ----------------
    def import_key(self, jwk: Dict[str, Any]) -> Dict[str, Any]:
        kid = jwk["kid"]
        jwk_public = public_jwk(jwk)
        jkt = jwk_thumbprint(jwk_public)
        self.store.upsert_key(kid=kid, jkt=jkt, jwk=jwk_public)
        self.rebuild_tree()
        return {"kid": kid, "jkt": jkt}

    def remove_key(self, kid: str) -> Dict[str, Any]:
        removed = self.store.delete_by_kid(kid)
        if removed:
            self.rebuild_tree()
        return {"kid": kid, "removed": removed}

    # ---------------- Root bundles ----------------
    def get_jwks_root_bundle(self) -> Optional[Dict[str, Any]]:
        raw = self.redis.get("root:jwks_bundle")
        return json.loads(raw) if raw else None

    def get_log_bundle(self) -> Optional[Dict[str, Any]]:
        raw = self.redis.get("log:bundle")
        return json.loads(raw) if raw else None

    # ---------------- Key+Proof ----------------
    def get_key_and_proof_by_kid(self, kid: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, str]], str]]:
        if self.bloom_enabled:
            if kid not in self.bloom:
                self.redis.set(f"neg:kid:{kid}", "1", ex=60)
                return None
            if self.redis.get(f"neg:kid:{kid}"):
                return None

        raw_key = self.redis.get(f"key:kid:{kid}")
        raw_proof = self.redis.get(f"proof:kid:{kid}")
        raw_jkt = self.redis.get(f"jkt:kid:{kid}")
        
        if raw_key and raw_proof and raw_jkt:
            jkt = raw_jkt.decode("utf-8") if isinstance(raw_jkt, bytes) else raw_jkt
            return json.loads(raw_key), json.loads(raw_proof), jkt

        self.rebuild_tree()
        raw_key = self.redis.get(f"key:kid:{kid}")
        raw_proof = self.redis.get(f"proof:kid:{kid}")
        raw_jkt = self.redis.get(f"jkt:kid:{kid}")
        
        if raw_key and raw_proof and raw_jkt:
            jkt = raw_jkt.decode("utf-8") if isinstance(raw_jkt, bytes) else raw_jkt
            return json.loads(raw_key), json.loads(raw_proof), jkt

        if self.bloom_enabled:
            self.redis.set(f"neg:kid:{kid}", "1", ex=60)
        return None

    def get_key_and_proof_by_jkt(self, jkt: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, str]], str]]:
        if self.bloom_enabled:
            if jkt not in self.bloom:
                self.redis.set(f"neg:jkt:{jkt}", "1", ex=60)
                return None
            if self.redis.get(f"neg:jkt:{jkt}"):
                return None

        kid = self.redis.get(f"kid_by_jkt:{jkt}")
        if not kid:
            self.rebuild_tree()
            kid = self.redis.get(f"kid_by_jkt:{jkt}")
        if not kid:
            if self.bloom_enabled:
                self.redis.set(f"neg:jkt:{jkt}", "1", ex=60)
            return None

        if isinstance(kid, (bytes, bytearray)):
            kid = kid.decode("utf-8")
        return self.get_key_and_proof_by_kid(kid)

    # ---------------- Transparency endpoints helpers ----------------
    def get_log_inclusion_proof(self, checkpoint_idx: int) -> Optional[List[Dict[str, str]]]:
        raw = self.redis.get(f"log:proof:{checkpoint_idx}")
        if raw:
            return json.loads(raw)
        self._rebuild_log_cache()
        raw = self.redis.get(f"log:proof:{checkpoint_idx}")
        return json.loads(raw) if raw else None

    def _build_tree_snapshot(
        self,
        levels_input: List[List[bytes]],
        leaf_descriptors: List[Dict[str, Any]],
        root_hash: str,
    ) -> Dict[str, Any]:
        leaf_count = len(leaf_descriptors)
        level_count = len(levels_input)

        levels: List[Dict[str, Any]] = []
        for level_index in range(level_count - 1, -1, -1):
            depth_from_root = (level_count - 1) - level_index
            width = max(1, 2 ** depth_from_root)
            nodes: List[Dict[str, Any]] = []
            for node_index, node_hash in enumerate(levels_input[level_index]):
                span_width = max(1, 2 ** level_index)
                span_start = node_index * span_width
                span_end = min(span_start + span_width - 1, leaf_count - 1) if leaf_count else None
                node_kind = "leaf" if level_index == 0 else ("root" if level_index == level_count - 1 else "branch")
                node_data: Dict[str, Any] = {
                    "index": node_index,
                    "hash": b64url_encode(node_hash),
                    "kind": node_kind,
                    "span_start": span_start if leaf_count else None,
                    "span_end": span_end,
                }
                if level_index == 0 and leaf_count:
                    node_data.update(leaf_descriptors[node_index])
                nodes.append(node_data)

            levels.append(
                {
                    "depth_from_root": depth_from_root,
                    "level_index": level_index,
                    "label": "Root" if level_index == level_count - 1 else ("Leaves" if level_index == 0 else f"Level {level_index}"),
                    "nodes": nodes,
                    "grid_columns": width,
                }
            )

        return {
            "root_hash": root_hash,
            "leaf_count": leaf_count,
            "level_count": level_count,
            "leaves": leaf_descriptors,
            "levels": levels,
        }

    def _build_merkle_tree_snapshot(self, keys: List[Any]) -> Dict[str, Any]:
        id_to_jwk = {rec.kid: rec.jwk for rec in keys}
        tree = MerkleTree.build(id_to_jwk)
        leaf_descriptors = [
            {
                "leaf_id": rec.kid,
                "leaf_label": rec.kid,
                "leaf_meta": f"JKT {rec.jkt}",
            }
            for rec in keys
        ]
        return self._build_tree_snapshot(tree.levels, leaf_descriptors, tree.root_b64())

    def _build_log_tree_snapshot(self, checkpoints: List[Any]) -> Dict[str, Any]:
        entry_hashes = [cp.entry_hash for cp in checkpoints]
        tree = LogMerkleTree.build_from_entry_hashes(entry_hashes)
        leaf_descriptors = [
            {
                "leaf_id": f"checkpoint-{cp.idx}",
                "leaf_label": f"Checkpoint #{cp.idx}",
                "leaf_meta": f"Epoch {cp.epoch}",
                "checkpoint_idx": cp.idx,
                "entry_hash": cp.entry_hash,
                "jwks_root_hash": cp.jwks_root_hash,
            }
            for cp in checkpoints
        ]
        return self._build_tree_snapshot(tree.levels, leaf_descriptors, tree.root_b64())

    def get_dashboard_snapshot(self, checkpoint_limit: int = 10) -> Dict[str, Any]:
        all_keys = self.store.list_all(include_inactive=True)
        active_keys = [rec for rec in all_keys if rec.status == "active"]
        counts = self.store.count_keys_by_status()
        all_checkpoints = self.store.list_checkpoints()
        recent_checkpoints = self.store.list_recent_checkpoints(limit=checkpoint_limit)
        latest_checkpoint = recent_checkpoints[0] if recent_checkpoints else None
        jwks_root = self.get_jwks_root_bundle()
        log_root = self.get_log_bundle()

        return {
            "generated_at": int(time.time()),
            "counts": counts,
            "jwks_root": jwks_root,
            "log_root": log_root,
            "merkle_tree": self._build_merkle_tree_snapshot(active_keys),
            "log_merkle_tree": self._build_log_tree_snapshot(all_checkpoints),
            "latest_checkpoint": (
                {
                    "idx": latest_checkpoint.idx,
                    "epoch": latest_checkpoint.epoch,
                    "jwks_root_hash": latest_checkpoint.jwks_root_hash,
                    "prev_hash": latest_checkpoint.prev_hash,
                    "entry_hash": latest_checkpoint.entry_hash,
                    "created_at": latest_checkpoint.created_at,
                }
                if latest_checkpoint
                else None
            ),
            "keys": [
                {
                    "kid": rec.kid,
                    "jkt": rec.jkt,
                    "status": rec.status,
                    "created_at": rec.created_at,
                    "activated_at": rec.activated_at,
                    "deactivated_at": rec.deactivated_at,
                    "last_updated_at": rec.last_updated_at,
                    "kty": rec.jwk.get("kty"),
                    "alg": rec.jwk.get("alg"),
                    "use": rec.jwk.get("use"),
                }
                for rec in all_keys
            ],
            "recent_checkpoints": [
                {
                    "idx": cp.idx,
                    "epoch": cp.epoch,
                    "jwks_root_hash": cp.jwks_root_hash,
                    "prev_hash": cp.prev_hash,
                    "entry_hash": cp.entry_hash,
                    "created_at": cp.created_at,
                }
                for cp in recent_checkpoints
            ],
        }
