from __future__ import annotations
from dataclasses import dataclass
from typing import List

from .utils import sha256, b64url_encode, b64url_decode

def parent_hash(left: bytes, right: bytes) -> bytes:
    return sha256(left + right)

@dataclass
class ProofItem:
    position: str  # "left" or "right" (position of sibling)
    hash: str      # base64url

@dataclass
class LogMerkleTree:
    levels: List[List[bytes]]

    @classmethod
    def build_from_entry_hashes(cls, entry_hashes_b64: List[str]) -> "LogMerkleTree":
        leaves = [b64url_decode(h) for h in entry_hashes_b64]
        if not leaves:
            return cls(levels=[[sha256(b"")]])

        levels: List[List[bytes]] = [leaves]
        cur = leaves
        while len(cur) > 1:
            nxt: List[bytes] = []
            i = 0
            while i < len(cur):
                left = cur[i]
                right = cur[i + 1] if i + 1 < len(cur) else cur[i]
                nxt.append(parent_hash(left, right))
                i += 2
            levels.append(nxt)
            cur = nxt
        return cls(levels=levels)

    def root_b64(self) -> str:
        return b64url_encode(self.levels[-1][0])

    def proof_for_index(self, zero_based_idx: int) -> List[ProofItem]:
        idx = zero_based_idx
        proof: List[ProofItem] = []
        for level in range(len(self.levels) - 1):
            nodes = self.levels[level]
            sib = idx ^ 1
            if sib >= len(nodes):
                sib = idx
            sibling_hash = nodes[sib]
            position = "left" if sib < idx else "right"
            proof.append(ProofItem(position=position, hash=b64url_encode(sibling_hash)))
            idx //= 2
        return proof

def verify_log_inclusion(entry_hash_b64: str, proof: List[dict], expected_root_b64: str) -> bool:
    h = b64url_decode(entry_hash_b64)
    for item in proof:
        sib = b64url_decode(item["hash"])
        if item["position"] == "left":
            h = parent_hash(sib, h)
        elif item["position"] == "right":
            h = parent_hash(h, sib)
        else:
            raise ValueError("position must be left|right")
    return b64url_encode(h) == expected_root_b64
