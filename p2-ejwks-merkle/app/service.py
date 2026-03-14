from __future__ import annotations
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from redis import Redis

from .bloom import BloomFilter
from .log_merkle import LogMerkleTree
from .merkle import MerkleTree
from .rfc6962 import RFC6962Tree, proof_to_b64, verify_consistency_proof
from .signer import RootSigner, sign_root_bundle, verify_detached_signature
from .storage import KeyStore
from .utils import b64url_encode, canonical_json, jwk_thumbprint, public_jwk, sha256

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
        self._bloom_metrics_key = "metrics:bloom"

    def _increment_bloom_metric(self, name: str) -> None:
        self.redis.hincrby(self._bloom_metrics_key, name, 1)

    def _get_bloom_metrics(self) -> Dict[str, int]:
        raw_metrics = self.redis.hgetall(self._bloom_metrics_key)
        metrics: Dict[str, int] = {}
        for raw_key, raw_value in raw_metrics.items():
            key = raw_key.decode("utf-8") if isinstance(raw_key, (bytes, bytearray)) else str(raw_key)
            value_text = raw_value.decode("utf-8") if isinstance(raw_value, (bytes, bytearray)) else str(raw_value)
            try:
                metrics[key] = int(value_text)
            except ValueError:
                continue
        return metrics

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
        self._increment_bloom_metric("rebuilds_total")

        # Sign JWKS root
        jwks_bundle = sign_root_bundle(self.root_signer, root_b64=jwks_root_b64, epoch=epoch)
        self.redis.set("root:jwks_bundle", json.dumps(jwks_bundle), ex=24 * 3600)

        # Remove stale cache entries for keys that are no longer active.
        stale_keys: List[bytes | str] = []
        for pattern in ("key:kid:*", "proof:kid:*", "jkt:kid:*", "kid_by_jkt:*", "neg:kid:*", "neg:jkt:*"):
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
        self._increment_bloom_metric("kid_queries_total")
        if self.bloom_enabled:
            if kid not in self.bloom:
                self._increment_bloom_metric("kid_definite_miss_total")
                self.redis.set(f"neg:kid:{kid}", "1", ex=60)
                return None
            self._increment_bloom_metric("kid_maybe_present_total")
            if self.redis.get(f"neg:kid:{kid}"):
                self._increment_bloom_metric("kid_negative_cache_hits_total")
                return None

        raw_key = self.redis.get(f"key:kid:{kid}")
        raw_proof = self.redis.get(f"proof:kid:{kid}")
        raw_jkt = self.redis.get(f"jkt:kid:{kid}")
        
        if raw_key and raw_proof and raw_jkt:
            self._increment_bloom_metric("kid_cache_hits_total")
            jkt = raw_jkt.decode("utf-8") if isinstance(raw_jkt, bytes) else raw_jkt
            return json.loads(raw_key), json.loads(raw_proof), jkt

        self._increment_bloom_metric("kid_rebuild_lookups_total")
        self.rebuild_tree()
        raw_key = self.redis.get(f"key:kid:{kid}")
        raw_proof = self.redis.get(f"proof:kid:{kid}")
        raw_jkt = self.redis.get(f"jkt:kid:{kid}")
        
        if raw_key and raw_proof and raw_jkt:
            self._increment_bloom_metric("kid_hits_after_rebuild_total")
            jkt = raw_jkt.decode("utf-8") if isinstance(raw_jkt, bytes) else raw_jkt
            return json.loads(raw_key), json.loads(raw_proof), jkt

        if self.bloom_enabled:
            self._increment_bloom_metric("kid_confirmed_missing_total")
            self.redis.set(f"neg:kid:{kid}", "1", ex=60)
        return None

    def get_key_and_proof_by_jkt(self, jkt: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, str]], str]]:
        self._increment_bloom_metric("jkt_queries_total")
        if self.bloom_enabled:
            if jkt not in self.bloom:
                self._increment_bloom_metric("jkt_definite_miss_total")
                self.redis.set(f"neg:jkt:{jkt}", "1", ex=60)
                return None
            self._increment_bloom_metric("jkt_maybe_present_total")
            if self.redis.get(f"neg:jkt:{jkt}"):
                self._increment_bloom_metric("jkt_negative_cache_hits_total")
                return None

        kid = self.redis.get(f"kid_by_jkt:{jkt}")
        if not kid:
            self._increment_bloom_metric("jkt_rebuild_lookups_total")
            self.rebuild_tree()
            kid = self.redis.get(f"kid_by_jkt:{jkt}")
        if not kid:
            if self.bloom_enabled:
                self._increment_bloom_metric("jkt_confirmed_missing_total")
                self.redis.set(f"neg:jkt:{jkt}", "1", ex=60)
            return None

        self._increment_bloom_metric("jkt_cache_hits_total")
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

    def get_rfc6962_consistency_proof(self, old_size: int, new_size: int) -> Optional[Dict[str, Any]]:
        checkpoints = self.store.list_checkpoints()
        total = len(checkpoints)
        if old_size < 0 or new_size < 0 or old_size > new_size or new_size > total:
            return None

        leaves = [cp.entry_hash.encode("utf-8") for cp in checkpoints]
        tree = RFC6962Tree(leaves)
        old_root_b64 = b64url_encode(tree.root_hash(old_size))
        new_root_b64 = b64url_encode(tree.root_hash(new_size))
        proof = tree.consistency_proof(old_size, new_size)

        return {
            "proof_type": "rfc6962_consistency",
            "old_size": old_size,
            "new_size": new_size,
            "old_root": old_root_b64,
            "new_root": new_root_b64,
            "proof": proof_to_b64(proof),
        }

    def verify_rfc6962_consistency_proof(
        self,
        old_size: int,
        new_size: int,
        old_root: str,
        new_root: str,
        proof: List[str],
    ) -> bool:
        return verify_consistency_proof(
            old_size=old_size,
            new_size=new_size,
            old_root_b64=old_root,
            new_root_b64=new_root,
            proof_b64=proof,
        )

    def get_append_only_consistency_proof(self, from_idx: int, to_idx: int) -> Optional[Dict[str, Any]]:
        """
        Returns a chain-based append-only proof between two checkpoints.

        This is not an RFC6962 Merkle consistency proof. It proves append-only
        semantics for this system's checkpoint hash-chain model by showing the
        contiguous sequence where each checkpoint commits to the previous via prev_hash.
        """
        if from_idx < 1 or to_idx < 1 or from_idx > to_idx:
            return None

        from_cp = self.store.get_checkpoint(from_idx)
        to_cp = self.store.get_checkpoint(to_idx)
        if not from_cp or not to_cp:
            return None

        segment = self.store.get_checkpoint_chain_segment(from_idx, to_idx)
        if len(segment) != (to_idx - from_idx + 1):
            return None

        genesis_hash = b64url_encode(sha256(b"GENESIS"))
        prior_cp = self.store.get_checkpoint(from_idx - 1) if from_idx > 1 else None
        base_prev_hash = prior_cp.entry_hash if prior_cp else genesis_hash
        chain_valid = True
        reason: Optional[str] = None
        for i, cp in enumerate(segment):
            expected_prev = segment[i - 1].entry_hash if i > 0 else base_prev_hash
            if cp.prev_hash != expected_prev:
                chain_valid = False
                reason = f"prev_hash mismatch at checkpoint idx={cp.idx}"
                break

            expected_entry_hash = b64url_encode(
                sha256(
                    canonical_json(
                        {
                            "epoch": int(cp.epoch),
                            "jwks_root_hash": cp.jwks_root_hash,
                            "prev_hash": cp.prev_hash,
                        }
                    )
                )
            )
            if cp.entry_hash != expected_entry_hash:
                chain_valid = False
                reason = f"entry_hash mismatch at checkpoint idx={cp.idx}"
                break

        return {
            "from_idx": from_idx,
            "to_idx": to_idx,
            "from_entry_hash": from_cp.entry_hash,
            "to_entry_hash": to_cp.entry_hash,
            "chain_valid": chain_valid,
            "verification_note": reason or "contiguous append-only chain verified",
            "proof_type": "checkpoint_hash_chain",
            "entries": [
                {
                    "idx": cp.idx,
                    "epoch": cp.epoch,
                    "jwks_root_hash": cp.jwks_root_hash,
                    "prev_hash": cp.prev_hash,
                    "entry_hash": cp.entry_hash,
                    "created_at": cp.created_at,
                }
                for cp in segment
            ],
        }

    def record_witness_observation(
        self,
        observer_id: str,
        checkpoint_idx: int,
        epoch: int,
        log_root_hash: str,
        observed_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        inserted, conflict = self.store.record_witness_observation(
            observer_id=observer_id,
            checkpoint_idx=checkpoint_idx,
            epoch=epoch,
            log_root_hash=log_root_hash,
            observed_at=observed_at,
        )
        return {
            "inserted": inserted,
            "equivocation_detected": conflict is not None,
            "conflict": (
                {
                    "checkpoint_idx": conflict.checkpoint_idx,
                    "observer_id": conflict.observer_id,
                    "known_log_root_hash": conflict.known_log_root_hash,
                    "observed_log_root_hash": conflict.observed_log_root_hash,
                    "first_observed_at": conflict.first_observed_at,
                    "conflict_observed_at": conflict.conflict_observed_at,
                }
                if conflict
                else None
            ),
        }

    def get_witness_state(self, limit: int = 50) -> Dict[str, Any]:
        conflicts = self.store.list_recent_witness_conflicts(limit=limit)
        return {
            "observation_count": self.store.count_witness_observations(),
            "recent_conflicts": [
                {
                    "checkpoint_idx": c.checkpoint_idx,
                    "observer_id": c.observer_id,
                    "known_log_root_hash": c.known_log_root_hash,
                    "observed_log_root_hash": c.observed_log_root_hash,
                    "first_observed_at": c.first_observed_at,
                    "conflict_observed_at": c.conflict_observed_at,
                }
                for c in conflicts
            ],
        }

    def register_witness_identity(self, witness_id: str, sig_alg: str, public_key: str) -> Dict[str, Any]:
        rec = self.store.upsert_witness_identity(
            witness_id=witness_id,
            sig_alg=sig_alg,
            public_key=public_key,
        )
        return {
            "witness_id": rec.witness_id,
            "sig_alg": rec.sig_alg,
            "public_key": rec.public_key,
            "created_at": rec.created_at,
            "updated_at": rec.updated_at,
        }

    def list_witness_identities(self) -> List[Dict[str, Any]]:
        return [
            {
                "witness_id": rec.witness_id,
                "sig_alg": rec.sig_alg,
                "public_key": rec.public_key,
                "created_at": rec.created_at,
                "updated_at": rec.updated_at,
            }
            for rec in self.store.list_witness_identities()
        ]

    def ingest_witness_signed_checkpoint(
        self,
        witness_id: str,
        checkpoint_idx: int,
        epoch: int,
        log_root_hash: str,
        signature: str,
        observed_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        witness = self.store.get_witness_identity(witness_id)
        if not witness:
            raise ValueError("unknown witness_id")

        cp = self.store.get_checkpoint(checkpoint_idx)
        if not cp:
            raise ValueError("unknown checkpoint_idx")
        if cp.epoch != epoch:
            raise ValueError("epoch does not match checkpoint")

        checkpoints = self.store.list_checkpoints()
        leaves = [row.entry_hash.encode("utf-8") for row in checkpoints]
        tree = RFC6962Tree(leaves)
        expected_log_root_hash = b64url_encode(tree.root_hash(checkpoint_idx))
        if log_root_hash != expected_log_root_hash:
            raise ValueError("log_root_hash does not match canonical RFC6962 root for checkpoint size")

        payload = canonical_json(
            {
                "checkpoint_idx": checkpoint_idx,
                "epoch": epoch,
                "log_root_hash": log_root_hash,
            }
        )
        if not verify_detached_signature(
            sig_alg=witness.sig_alg,
            public_key_b64=witness.public_key,
            message=payload,
            signature_b64=signature,
        ):
            raise ValueError("invalid witness signature")

        inserted = self.store.add_witness_signature(
            witness_id=witness_id,
            checkpoint_idx=checkpoint_idx,
            epoch=epoch,
            log_root_hash=log_root_hash,
            signature=signature,
            observed_at=observed_at,
        )

        observation_result = self.record_witness_observation(
            observer_id=witness_id,
            checkpoint_idx=checkpoint_idx,
            epoch=epoch,
            log_root_hash=log_root_hash,
            observed_at=observed_at,
        )

        return {
            "accepted": True,
            "signature_recorded": inserted,
            "equivocation_detected": observation_result["equivocation_detected"],
            "conflict": observation_result["conflict"],
        }

    def get_signed_checkpoint_exchange(self, checkpoint_idx: int, min_signatures: int = 2) -> Optional[Dict[str, Any]]:
        cp = self.store.get_checkpoint(checkpoint_idx)
        if not cp:
            return None

        checkpoints = self.store.list_checkpoints()
        leaves = [row.entry_hash.encode("utf-8") for row in checkpoints]
        tree = RFC6962Tree(leaves)
        checkpoint_log_root = b64url_encode(tree.root_hash(checkpoint_idx))

        signatures = self.store.list_witness_signatures_for_checkpoint(checkpoint_idx)
        unique_witnesses = sorted({s.witness_id for s in signatures})
        return {
            "checkpoint": {
                "idx": cp.idx,
                "epoch": cp.epoch,
                "jwks_root_hash": cp.jwks_root_hash,
                "prev_hash": cp.prev_hash,
                "entry_hash": cp.entry_hash,
                "created_at": cp.created_at,
            },
            "signed_payload": {
                "checkpoint_idx": cp.idx,
                "epoch": cp.epoch,
                "log_root_hash": checkpoint_log_root,
            },
            "witness_signatures": [
                {
                    "witness_id": s.witness_id,
                    "checkpoint_idx": s.checkpoint_idx,
                    "epoch": s.epoch,
                    "log_root_hash": s.log_root_hash,
                    "signature": s.signature,
                    "observed_at": s.observed_at,
                }
                for s in signatures
            ],
            "witness_count": len(unique_witnesses),
            "witnesses": unique_witnesses,
            "min_signatures": min_signatures,
            "quorum_met": len(unique_witnesses) >= min_signatures,
        }

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

    def _build_bloom_snapshot(self, active_keys: List[Any]) -> Dict[str, Any]:
        key_count = len(active_keys)
        metrics = self._get_bloom_metrics()

        kid_allowed_total = metrics.get("kid_cache_hits_total", 0) + metrics.get("kid_hits_after_rebuild_total", 0)
        kid_rejected_total = (
            metrics.get("kid_definite_miss_total", 0)
            + metrics.get("kid_negative_cache_hits_total", 0)
            + metrics.get("kid_confirmed_missing_total", 0)
        )
        jkt_allowed_total = metrics.get("jkt_cache_hits_total", 0)
        jkt_rejected_total = (
            metrics.get("jkt_definite_miss_total", 0)
            + metrics.get("jkt_negative_cache_hits_total", 0)
            + metrics.get("jkt_confirmed_missing_total", 0)
        )

        return {
            "enabled": self.bloom_enabled,
            "m_bits": self._bloom_bits,
            "k_hashes": self._bloom_hashes,
            "indexed_kids": key_count,
            "indexed_jkts": key_count,
            "indexed_items": key_count * 2,
            "miss_semantics": "If the Bloom filter says no, the key is definitely not in the current active set.",
            "hit_semantics": "If the Bloom filter says maybe, P2 continues to Redis and proof lookup because false positives are possible.",
            "metrics": metrics,
            "kid_request_summary": {
                "total_queries": metrics.get("kid_queries_total", 0),
                "allowed_total": kid_allowed_total,
                "rejected_total": kid_rejected_total,
                "allow_rate": (kid_allowed_total / metrics["kid_queries_total"]) if metrics.get("kid_queries_total") else 0.0,
                "reject_rate": (kid_rejected_total / metrics["kid_queries_total"]) if metrics.get("kid_queries_total") else 0.0,
                "allowed_breakdown": {
                    "cache_hits": metrics.get("kid_cache_hits_total", 0),
                    "hits_after_rebuild": metrics.get("kid_hits_after_rebuild_total", 0),
                },
                "rejected_breakdown": {
                    "definite_miss": metrics.get("kid_definite_miss_total", 0),
                    "negative_cache_hits": metrics.get("kid_negative_cache_hits_total", 0),
                    "confirmed_missing_after_lookup": metrics.get("kid_confirmed_missing_total", 0),
                },
            },
            "jkt_request_summary": {
                "total_queries": metrics.get("jkt_queries_total", 0),
                "allowed_total": jkt_allowed_total,
                "rejected_total": jkt_rejected_total,
                "allow_rate": (jkt_allowed_total / metrics["jkt_queries_total"]) if metrics.get("jkt_queries_total") else 0.0,
                "reject_rate": (jkt_rejected_total / metrics["jkt_queries_total"]) if metrics.get("jkt_queries_total") else 0.0,
            },
        }

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
            "bloom_filter": self._build_bloom_snapshot(active_keys),
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
