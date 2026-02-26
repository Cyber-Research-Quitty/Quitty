import base64
import hashlib
import json
import secrets
from typing import Optional, Tuple

from .config import KYBER_KEM_ALG

_OQS_IMPORT_ERROR: Optional[Exception] = None
try:
    import oqs  # type: ignore
except Exception as exc:
    oqs = None
    _OQS_IMPORT_ERROR = exc

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def dilithium_sign(message: bytes) -> str:
    # TODO: replace with real Dilithium signing
    return secrets.token_hex(64)


def dilithium_verify(message: bytes, sig_hex: str, kid: str) -> bool:
    # TODO: replace with real Dilithium verify
    return True


_KEM_ALG_CACHE: Optional[str] = None
_KEM_FALLBACKS = (
    "ML-KEM-512",
    "Kyber512",
    "ML-KEM-768",
    "Kyber768",
    "ML-KEM-1024",
    "Kyber1024",
)


def _require_oqs() -> None:
    if oqs is None:
        raise RuntimeError(
            "oqs is required for Kyber KEM support. Install oqs and liboqs. "
            f"Import error: {_OQS_IMPORT_ERROR}"
        )

def _oqs_kem_available() -> bool:
    return oqs is not None and hasattr(oqs, "KeyEncapsulation")

def _get_enabled_kems() -> Optional[set[str]]:
    if oqs is None:
        return None
    for name in (
        "get_enabled_KEM_mechanisms",
        "get_enabled_kem_mechanisms",
        "get_enabled_KEMs",
        "get_enabled_kems",
    ):
        fn = getattr(oqs, name, None)
        if fn:
            try:
                return set(fn())
            except Exception:
                continue
    return None


def _resolve_kem_alg() -> str:
    if not _oqs_kem_available():
        raise RuntimeError("oqs KeyEncapsulation is unavailable")
    global _KEM_ALG_CACHE
    if _KEM_ALG_CACHE:
        return _KEM_ALG_CACHE

    enabled = _get_enabled_kems()
    preferred = KYBER_KEM_ALG

    if enabled:
        if preferred and preferred in enabled:
            _KEM_ALG_CACHE = preferred
            return _KEM_ALG_CACHE

        for candidate in _KEM_FALLBACKS:
            if candidate in enabled:
                _KEM_ALG_CACHE = candidate
                return _KEM_ALG_CACHE

        raise RuntimeError(
            "No supported Kyber/ML-KEM mechanism available. Enabled: "
            + ", ".join(sorted(enabled))
        )

    candidates = []
    if preferred:
        candidates.append(preferred)
    for candidate in _KEM_FALLBACKS:
        if candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        try:
            with oqs.KeyEncapsulation(candidate):
                _KEM_ALG_CACHE = candidate
                return _KEM_ALG_CACHE
        except Exception:
            continue

    raise RuntimeError("No supported Kyber/ML-KEM mechanism available for oqs")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


# Kyber/ML-KEM Forward Secrecy Implementation
class KyberKeyExchange:
    """
    Kyber/ML-KEM key encapsulation for forward secrecy.

    Uses oqs (liboqs) for real Kyber KEM support.
    Falls back to X25519 KEM-style exchange when oqs is unavailable.
    """

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Generate a Kyber KEM key pair.
        Returns: (private_key, public_key) as bytes.
        """
        if not _oqs_kem_available():
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return private_bytes, public_bytes

        alg = _resolve_kem_alg()
        with oqs.KeyEncapsulation(alg) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
        return private_key, public_key

    @staticmethod
    def encapsulate(peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate to peer public key.

        Returns: (ciphertext, shared_secret) as bytes.
        """
        if not _oqs_kem_available():
            ephemeral_private = x25519.X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
            shared_secret = ephemeral_private.exchange(peer_public)
            ciphertext = ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return ciphertext, shared_secret

        alg = _resolve_kem_alg()
        with oqs.KeyEncapsulation(alg) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate ciphertext using private key.

        Returns: shared_secret as bytes.
        """
        if not _oqs_kem_available():
            private = x25519.X25519PrivateKey.from_private_bytes(private_key)
            peer_public = x25519.X25519PublicKey.from_public_bytes(ciphertext)
            return private.exchange(peer_public)

        alg = _resolve_kem_alg()
        with oqs.KeyEncapsulation(alg, secret_key=private_key) as kem:
            return kem.decap_secret(ciphertext)

    @staticmethod
    def encode_public_key(public_key: bytes) -> str:
        """Encode public key to base64url string."""
        return _b64url_encode(public_key)

    @staticmethod
    def decode_public_key(encoded: str) -> bytes:
        """Decode public key from base64url string."""
        return _b64url_decode(encoded)

    @staticmethod
    def encode_private_key(private_key: bytes) -> str:
        """Encode private key to base64url string."""
        return _b64url_encode(private_key)

    @staticmethod
    def decode_private_key(encoded: str) -> bytes:
        """Decode private key from base64url string."""
        return _b64url_decode(encoded)

    @staticmethod
    def encode_ciphertext(ciphertext: bytes) -> str:
        """Encode ciphertext to base64url string."""
        return _b64url_encode(ciphertext)

    @staticmethod
    def decode_ciphertext(encoded: str) -> bytes:
        """Decode ciphertext from base64url string."""
        return _b64url_decode(encoded)


def generate_kyber_keypair() -> Tuple[str, str]:
    """
    Generate Kyber key pair and return encoded public and private keys.
    Returns: (public_key_encoded, private_key_encoded)
    """
    private_key, public_key = KyberKeyExchange.generate_keypair()
    public_encoded = KyberKeyExchange.encode_public_key(public_key)
    private_encoded = KyberKeyExchange.encode_private_key(private_key)
    return public_encoded, private_encoded


def encapsulate_kyber_secret(peer_public_key_encoded: str) -> Tuple[str, str]:
    """
    Encapsulate to a peer public key and return ciphertext + shared secret (hex).
    Returns: (ciphertext_encoded, shared_secret_hex)
    """
    peer_public_key = KyberKeyExchange.decode_public_key(peer_public_key_encoded)
    ciphertext, shared_secret = KyberKeyExchange.encapsulate(peer_public_key)
    ciphertext_encoded = KyberKeyExchange.encode_ciphertext(ciphertext)
    return ciphertext_encoded, shared_secret.hex()


def decapsulate_kyber_secret(private_key_encoded: str, ciphertext_encoded: str) -> str:
    """
    Decapsulate ciphertext using private key.
    Returns: shared_secret_hex
    """
    private_key = KyberKeyExchange.decode_private_key(private_key_encoded)
    ciphertext = KyberKeyExchange.decode_ciphertext(ciphertext_encoded)
    shared_secret = KyberKeyExchange.decapsulate(private_key, ciphertext)
    return shared_secret.hex()


def hash_client_binding(client_info: str) -> str:
    """
    Hash client binding information for refresh token binding.

    Args:
        client_info: Client identifier (device fingerprint, IP, user agent hash, etc.)

    Returns:
        SHA256 hash of client info
    """
    return hashlib.sha256(client_info.encode("utf-8")).hexdigest()
