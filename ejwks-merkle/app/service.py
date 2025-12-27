from __future__ import annotations
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from redis import Redis
from .bloom import BloomFilter
from .merkle import MerkleTree
from .signer import RootSigner, sign_root_bundle
from .storage import KeyStore
from .utils import jwk_thumbprint

class EJWKSService:
    """
    - SQLite: durable key storage
    - Merkle tree: root + proofs
    - Redis: cache root bundle + proofs/paths + negative cache
    - Bloom filter: quick reject for random kids (DoS shield)
    """
    def __init__(self, store: KeyStore, redis: Redis, root_signer: RootSigner, bloom_bits: int, bloom_hashes: int) -> None:
        self.store = store
        self.redis = redis
        self.root_signer = root_signer
        self._bloom_bits = bloom_bits
        self._bloom_hashes = bloom_hashes
        self.bloom = BloomFilter(m_bits=bloom_bits, k_hashes=bloom_hashes)

    def rebuild_tree(self) -> Dict[str, Any]:
        keys = self.store.list_all()
        id_to_jwk = {k.kid: k.jwk for k in keys}
        tree = MerkleTree.build(id_to_jwk)
        root_b64 = tree.root_b64()
        epoch = int(time.time())

        # rebuild bloom (kid + jkt)
        self.bloom = BloomFilter(m_bits=self._bloom_bits, k_hashes=self._bloom_hashes)
        for rec in keys:
            self.bloom.add(rec.kid)
            self.bloom.add(rec.jkt)

        bundle = sign_root_bundle(self.root_signer, root_b64=root_b64, epoch=epoch)
        self.redis.set("root:bundle", json.dumps(bundle), ex=24 * 3600)

        pipe = self.redis.pipeline()
        for rec in keys:
            proof_items = [item.__dict__ for item in tree.proof_for_id(rec.kid)]
            pipe.set(f"key:kid:{rec.kid}", json.dumps(rec.jwk), ex=24 * 3600)
            pipe.set(f"proof:kid:{rec.kid}", json.dumps(proof_items), ex=24 * 3600)
            pipe.set(f"kid_by_jkt:{rec.jkt}", rec.kid, ex=24 * 3600)
        pipe.execute()

        return bundle

    def import_key(self, jwk: Dict[str, Any]) -> Dict[str, Any]:
        kid = jwk["kid"]
        jkt = jwk_thumbprint(jwk)
        self.store.upsert_key(kid=kid, jkt=jkt, jwk=jwk)
        self.rebuild_tree()
        return {"kid": kid, "jkt": jkt}

    def get_root_bundle(self) -> Optional[Dict[str, Any]]:
        raw = self.redis.get("root:bundle")
        if not raw:
            return None
        return json.loads(raw)

    def get_key_and_proof_by_kid(self, kid: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, str]]]]:
        if kid not in self.bloom:
            self.redis.set(f"neg:kid:{kid}", "1", ex=60)
            return None

        if self.redis.get(f"neg:kid:{kid}"):
            return None

        raw_key = self.redis.get(f"key:kid:{kid}")
        raw_proof = self.redis.get(f"proof:kid:{kid}")
        if raw_key and raw_proof:
            return json.loads(raw_key), json.loads(raw_proof)

        # One rebuild attempt on cache miss
        self.rebuild_tree()
        raw_key = self.redis.get(f"key:kid:{kid}")
        raw_proof = self.redis.get(f"proof:kid:{kid}")
        if raw_key and raw_proof:
            return json.loads(raw_key), json.loads(raw_proof)

        self.redis.set(f"neg:kid:{kid}", "1", ex=60)
        return None

    def get_key_and_proof_by_jkt(self, jkt: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, str]]]]:
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
