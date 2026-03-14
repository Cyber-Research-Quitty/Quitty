from __future__ import annotations

from functools import lru_cache
from typing import List

from .utils import b64url_decode, b64url_encode, sha256


def _largest_power_of_two_less_than(n: int) -> int:
    if n < 2:
        return 0
    return 1 << ((n - 1).bit_length() - 1)


def _leaf_hash(leaf: bytes) -> bytes:
    return sha256(b"\x00" + leaf)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


class RFC6962Tree:
    def __init__(self, leaves: List[bytes]) -> None:
        self._leaves = leaves

    def size(self) -> int:
        return len(self._leaves)

    @lru_cache(maxsize=None)
    def _mth(self, start: int, end: int) -> bytes:
        n = end - start
        if n == 0:
            return sha256(b"")
        if n == 1:
            return _leaf_hash(self._leaves[start])

        k = _largest_power_of_two_less_than(n)
        left = self._mth(start, start + k)
        right = self._mth(start + k, end)
        return _node_hash(left, right)

    def root_hash(self, size: int | None = None) -> bytes:
        n = self.size() if size is None else size
        if n < 0 or n > self.size():
            raise ValueError("invalid tree size")
        return self._mth(0, n)

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> List[bytes]:
        n = self.size() if new_size is None else new_size
        m = old_size
        if m < 0 or n < 0 or m > n or n > self.size():
            raise ValueError("invalid consistency range")
        if m == n:
            return []
        if m == 0:
            return []
        return self._subproof(m, 0, n)

    def _subproof(self, m: int, start: int, end: int) -> List[bytes]:
        n = end - start
        if m == n:
            return []

        k = _largest_power_of_two_less_than(n)
        if m <= k:
            proof = self._subproof(m, start, start + k)
            proof.append(self._mth(start + k, end))
            return proof

        proof = self._subproof(m - k, start + k, end)
        proof.append(self._mth(start, start + k))
        return proof


def verify_consistency_proof(
    old_size: int,
    new_size: int,
    old_root_b64: str,
    new_root_b64: str,
    proof_b64: List[str],
) -> bool:
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return old_root_b64 == new_root_b64 and len(proof_b64) == 0
    if old_size == 0:
        return True

    old_root = b64url_decode(old_root_b64)
    new_root = b64url_decode(new_root_b64)
    proof = [b64url_decode(p) for p in proof_b64]

    fn = old_size - 1
    sn = new_size - 1
    fr = old_root
    sr = old_root
    idx = 0

    while fn & 1:
        fn >>= 1
        sn >>= 1

    while fn:
        if idx >= len(proof):
            return False
        p = proof[idx]
        if fn & 1:
            fr = _node_hash(p, fr)
            sr = _node_hash(p, sr)
            idx += 1
        elif fn < sn:
            sr = _node_hash(sr, p)
            idx += 1
        fn >>= 1
        sn >>= 1

    while sn:
        if idx >= len(proof):
            return False
        sr = _node_hash(sr, proof[idx])
        idx += 1
        sn >>= 1

    return idx == len(proof) and fr == old_root and sr == new_root


def proof_to_b64(proof: List[bytes]) -> List[str]:
    return [b64url_encode(p) for p in proof]
