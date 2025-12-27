from __future__ import annotations
import hashlib
from dataclasses import dataclass

def _hash_i(item: bytes, i: int) -> int:
    # Derive multiple hashes from sha256(item || i)
    h = hashlib.sha256(item + i.to_bytes(4, "big")).digest()
    return int.from_bytes(h[:8], "big", signed=False)

@dataclass
class BloomFilter:
    """
    Pure-Python Bloom filter (DoS shield / fast reject).
    False positives possible; false negatives shouldn't happen if built correctly.
    """
    m_bits: int
    k_hashes: int

    def __post_init__(self) -> None:
        if self.m_bits % 8 != 0:
            raise ValueError("m_bits must be multiple of 8")
        self._bytes = bytearray(self.m_bits // 8)

    def add(self, item: str) -> None:
        b = item.encode("utf-8")
        for i in range(self.k_hashes):
            bit = _hash_i(b, i) % self.m_bits
            self._bytes[bit // 8] |= (1 << (bit % 8))

    def __contains__(self, item: str) -> bool:
        b = item.encode("utf-8")
        for i in range(self.k_hashes):
            bit = _hash_i(b, i) % self.m_bits
            if not (self._bytes[bit // 8] & (1 << (bit % 8))):
                return False
        return True
