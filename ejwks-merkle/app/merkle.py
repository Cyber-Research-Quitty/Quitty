from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any
from .utils import sha256, b64url_encode, b64url_decode, canonical_json, public_jwk

def leaf_hash(jwk: Dict[str, Any]) -> bytes:
    # MUST stay stable across server & client.
    # Domain separation: prefix with 0x00 for leaf nodes
    jwk_public = public_jwk(jwk)
    return sha256(b"\x00" + canonical_json(jwk_public))

def parent_hash(left: bytes, right: bytes) -> bytes:
    # Domain separation: prefix with 0x01 for parent nodes to prevent second preimage attacks
    return sha256(b"\x01" + left + right)

@dataclass
class MerkleProofItem:
    position: str  # "left" or "right" (position of the sibling)
    hash: str      # base64url

@dataclass
class MerkleTree:
    leaf_ids: List[str]
    levels: List[List[bytes]]  # levels[0] are leaves
    leaf_index: Dict[str, int]

    @classmethod
    def build(cls, id_to_jwk: Dict[str, Dict[str, Any]]) -> "MerkleTree":
        leaf_ids = sorted(id_to_jwk.keys())
        leaves = [leaf_hash(id_to_jwk[_id]) for _id in leaf_ids]

        if not leaves:
            levels = [[sha256(b"\x00")]]  # empty-tree root with domain separation
            return cls(leaf_ids=[], levels=levels, leaf_index={})

        levels: List[List[bytes]] = [leaves]
        cur = leaves
        while len(cur) > 1:
            nxt: List[bytes] = []
            i = 0
            while i < len(cur):
                left = cur[i]
                # For odd number of nodes, use a special placeholder instead of duplication
                if i + 1 < len(cur):
                    right = cur[i + 1]
                    i += 2
                else:
                    # Odd node: hash with itself but with domain separation
                    right = left
                    i += 1
                nxt.append(parent_hash(left, right))
            levels.append(nxt)
            cur = nxt

        leaf_index = {leaf_ids[i]: i for i in range(len(leaf_ids))}
        return cls(leaf_ids=leaf_ids, levels=levels, leaf_index=leaf_index)

    def root(self) -> bytes:
        return self.levels[-1][0]

    def root_b64(self) -> str:
        return b64url_encode(self.root())

    def proof_for_id(self, leaf_id: str) -> List[MerkleProofItem]:
        if leaf_id not in self.leaf_index:
            raise KeyError(f"unknown leaf id: {leaf_id}")

        idx = self.leaf_index[leaf_id]
        proof: List[MerkleProofItem] = []
        for level in range(len(self.levels) - 1):
            nodes = self.levels[level]
            sib = idx ^ 1
            if sib >= len(nodes):
                sib = idx  # duplicated last
            sibling_hash = nodes[sib]
            position = "left" if sib < idx else "right"
            proof.append(MerkleProofItem(position=position, hash=b64url_encode(sibling_hash)))
            idx //= 2
        return proof

def verify_proof(jwk: Dict[str, Any], proof: List[dict], expected_root_b64: str) -> bool:
    h = leaf_hash(jwk)
    for item in proof:
        sib = b64url_decode(item["hash"])
        if item["position"] == "left":
            h = parent_hash(sib, h)
        elif item["position"] == "right":
            h = parent_hash(h, sib)
        else:
            raise ValueError("position must be left|right")
    return b64url_encode(h) == expected_root_b64
