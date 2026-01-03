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
from .utils import jwk_thumbprint

class EJWKSService:
    def __init__(
        self,
        store: KeyStore,
        redis: Redis,
        root_signer: RootSigner,
        log_signer: RootSigner,
        bloom_bits: int,
        bloom_hashes: int,
    ) -> None:
        self.store = store
        self.redis = redis
        self.root_signer = root_signer
        self.log_signer = log_signer
        self._bloom_bits = bloom_bits
        self._bloom_hashes = bloom_hashes
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
        jkt = jwk_thumbprint(jwk)
        self.store.upsert_key(kid=kid, jkt=jkt, jwk=jwk)
        self.rebuild_tree()
        return {"kid": kid, "jkt": jkt}

    # ---------------- Root bundles ----------------
    def get_jwks_root_bundle(self) -> Optional[Dict[str, Any]]:
        raw = self.redis.get("root:jwks_bundle")
        return json.loads(raw) if raw else None

    def get_log_bundle(self) -> Optional[Dict[str, Any]]:
        raw = self.redis.get("log:bundle")
        return json.loads(raw) if raw else None

    # ---------------- Key+Proof ----------------
    def get_key_and_proof_by_kid(self, kid: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, str]], str]]:
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

        self.redis.set(f"neg:kid:{kid}", "1", ex=60)
        return None

    def get_key_and_proof_by_jkt(self, jkt: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, str]], str]]:
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
