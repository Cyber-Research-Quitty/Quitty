import base64
import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Optional, Tuple

from .config import (
    KYBER_KEM_ALG,
    PQC_KEYRING_PATH,
    PQC_SIGNING_ALG,
    PQC_SIGNING_KEY_ID,
)

_OQS_IMPORT_ERROR: Optional[Exception] = None
try:
    import oqs  # type: ignore
except Exception as exc:
    oqs = None
    _OQS_IMPORT_ERROR = exc

_PQ44_IMPORT_ERROR: Optional[Exception] = None
_PQ65_IMPORT_ERROR: Optional[Exception] = None
try:
    from pqcrypto.sign import ml_dsa_44 as _pq_mldsa_44  # type: ignore
except Exception as exc:
    _pq_mldsa_44 = None
    _PQ44_IMPORT_ERROR = exc

try:
    from pqcrypto.sign import ml_dsa_65 as _pq_mldsa_65  # type: ignore
except Exception as exc:
    _pq_mldsa_65 = None
    _PQ65_IMPORT_ERROR = exc

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


_KEM_ALG_CACHE: Optional[str] = None
_SIG_ALG_CACHE: Optional[str] = None
_KEM_FALLBACKS = (
    "ML-KEM-512",
    "Kyber512",
    "ML-KEM-768",
    "Kyber768",
    "ML-KEM-1024",
    "Kyber1024",
)
_SIG_FALLBACKS = (
    "ML-DSA-44",
    "Dilithium2",
)
_PQ_SIG_ALG_44 = "pqcrypto-ml-dsa-44"
_PQ_SIG_ALG_65 = "pqcrypto-ml-dsa-65"
_KEYRING_LOCK = threading.Lock()


def _require_oqs() -> None:
    if oqs is None:
        raise RuntimeError(
            "oqs is required for post-quantum cryptography support. Install oqs and liboqs. "
            f"Import error: {_OQS_IMPORT_ERROR}"
        )


def _oqs_sig_available() -> bool:
    return oqs is not None and hasattr(oqs, "Signature")


def _pqcrypto_sig_available() -> bool:
    return _pq_mldsa_44 is not None or _pq_mldsa_65 is not None


def _pqcrypto_module_for_alg(alg: str):
    if alg == _PQ_SIG_ALG_65 and _pq_mldsa_65 is not None:
        return _pq_mldsa_65
    if alg == _PQ_SIG_ALG_44 and _pq_mldsa_44 is not None:
        return _pq_mldsa_44
    if _pq_mldsa_44 is not None:
        return _pq_mldsa_44
    if _pq_mldsa_65 is not None:
        return _pq_mldsa_65
    return None


def _resolve_pqcrypto_sig_alg() -> str:
    preferred = (PQC_SIGNING_ALG or "").lower().replace("_", "-")
    if "65" in preferred and _pq_mldsa_65 is not None:
        return _PQ_SIG_ALG_65
    if "44" in preferred and _pq_mldsa_44 is not None:
        return _PQ_SIG_ALG_44
    if "dilithium2" in preferred and _pq_mldsa_44 is not None:
        return _PQ_SIG_ALG_44
    if _pq_mldsa_44 is not None:
        return _PQ_SIG_ALG_44
    if _pq_mldsa_65 is not None:
        return _PQ_SIG_ALG_65
    raise RuntimeError(
        "No pqcrypto ML-DSA backend available. "
        f"ml_dsa_44 import error: {_PQ44_IMPORT_ERROR}; ml_dsa_65 import error: {_PQ65_IMPORT_ERROR}"
    )


def _generate_pqcrypto_keypair(alg: str) -> tuple[bytes, bytes]:
    mod = _pqcrypto_module_for_alg(alg)
    if mod is None:
        raise RuntimeError("pqcrypto signature backend is unavailable")

    a, b = mod.generate_keypair()
    msg = b"p4-pqcrypto-selftest"
    try:
        _ = mod.sign(b, msg)
        pub, sec = a, b
    except Exception:
        _ = mod.sign(a, msg)
        pub, sec = b, a
    return pub, sec


def _sign_pqcrypto(alg: str, private_key: bytes, message: bytes) -> bytes:
    mod = _pqcrypto_module_for_alg(alg)
    if mod is None:
        raise RuntimeError("pqcrypto signature backend is unavailable")
    return mod.sign(private_key, message)


def _verify_pqcrypto(alg: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    mod = _pqcrypto_module_for_alg(alg)
    if mod is None:
        return False
    try:
        return bool(mod.verify(public_key, message, signature))
    except Exception:
        try:
            return bool(mod.verify(message, signature, public_key))
        except Exception:
            return False


def _get_enabled_signatures() -> Optional[set[str]]:
    if oqs is None:
        return None

    for name in (
        "get_enabled_sig_mechanisms",
        "get_enabled_signature_mechanisms",
        "get_enabled_SIG_mechanisms",
    ):
        fn = getattr(oqs, name, None)
        if fn:
            try:
                return set(fn())
            except Exception:
                continue
    return None


def _resolve_sig_alg() -> str:
    if not _oqs_sig_available():
        raise RuntimeError("oqs Signature is unavailable")

    global _SIG_ALG_CACHE
    if _SIG_ALG_CACHE:
        return _SIG_ALG_CACHE

    enabled = _get_enabled_signatures()
    preferred = PQC_SIGNING_ALG

    if enabled:
        if preferred and preferred in enabled:
            _SIG_ALG_CACHE = preferred
            return _SIG_ALG_CACHE
        for candidate in _SIG_FALLBACKS:
            if candidate in enabled:
                _SIG_ALG_CACHE = candidate
                return _SIG_ALG_CACHE
        raise RuntimeError(
            "No supported signature mechanism available. Enabled: "
            + ", ".join(sorted(enabled))
        )

    candidates = []
    if preferred:
        candidates.append(preferred)
    for candidate in _SIG_FALLBACKS:
        if candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        try:
            with oqs.Signature(candidate):
                _SIG_ALG_CACHE = candidate
                return _SIG_ALG_CACHE
        except Exception:
            continue

    raise RuntimeError("No supported ML-DSA/Dilithium mechanism available for oqs")


def _keyring_path() -> Path:
    return Path(PQC_KEYRING_PATH)


def _default_keyring() -> dict[str, Any]:
    return {
        "version": 1,
        "default_alg": PQC_SIGNING_ALG,
        "keys": {},
    }


def _read_keyring() -> dict[str, Any]:
    path = _keyring_path()
    if not path.exists():
        return _default_keyring()

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if "keys" not in data or not isinstance(data["keys"], dict):
        data["keys"] = {}

    if "default_alg" not in data or not isinstance(data["default_alg"], str):
        data["default_alg"] = PQC_SIGNING_ALG

    return data


def _write_keyring(data: dict[str, Any]) -> None:
    path = _keyring_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)


def _ensure_signing_key() -> dict[str, str]:
    with _KEYRING_LOCK:
        keyring = _read_keyring()
        keys = keyring.setdefault("keys", {})

        rec = keys.get(PQC_SIGNING_KEY_ID)
        if rec:
            if rec.get("alg") and rec.get("private_key") and rec.get("public_key"):
                return rec
            raise RuntimeError(f"Invalid key entry for kid={PQC_SIGNING_KEY_ID}")

        if _oqs_sig_available():
            alg = _resolve_sig_alg()
            with oqs.Signature(alg) as sig:
                public_key = sig.generate_keypair()
                private_key = sig.export_secret_key()
        elif _pqcrypto_sig_available():
            alg = _resolve_pqcrypto_sig_alg()
            public_key, private_key = _generate_pqcrypto_keypair(alg)
        else:
            raise RuntimeError(
                "No signature backend available. "
                f"oqs import error: {_OQS_IMPORT_ERROR}; "
                f"pq44 import error: {_PQ44_IMPORT_ERROR}; "
                f"pq65 import error: {_PQ65_IMPORT_ERROR}"
            )

        rec = {
            "kid": PQC_SIGNING_KEY_ID,
            "alg": alg,
            "private_key": _b64url_encode(private_key),
            "public_key": _b64url_encode(public_key),
        }
        keys[PQC_SIGNING_KEY_ID] = rec
        keyring["default_alg"] = alg
        _write_keyring(keyring)
        return rec


def _load_public_key_record(kid: str) -> Optional[dict[str, str]]:
    path = _keyring_path()
    if not path.exists():
        return None

    with _KEYRING_LOCK:
        keyring = _read_keyring()
        rec = keyring.get("keys", {}).get(kid)
        if not rec:
            return None
        if not rec.get("alg") or not rec.get("public_key"):
            return None
        return rec


def dilithium_sign(message: bytes) -> str:
    rec = _ensure_signing_key()
    private_key = _b64url_decode(rec["private_key"])
    alg = rec["alg"]

    if alg.startswith("pqcrypto-"):
        signature = _sign_pqcrypto(alg, private_key, message)
    else:
        if not _oqs_sig_available():
            raise RuntimeError("oqs Signature backend unavailable for configured key")
        with oqs.Signature(alg, secret_key=private_key) as sig:
            signature = sig.sign(message)
    return _b64url_encode(signature)


def dilithium_verify(message: bytes, sig_b64u: str, kid: str) -> bool:
    if not sig_b64u or not kid:
        return False

    rec = _load_public_key_record(kid)
    if not rec:
        return False

    try:
        signature = _b64url_decode(sig_b64u)
        public_key = _b64url_decode(rec["public_key"])
    except Exception:
        return False

    alg = rec["alg"]
    if alg.startswith("pqcrypto-"):
        return _verify_pqcrypto(alg, public_key, message, signature)

    if not _oqs_sig_available():
        return False
    try:
        with oqs.Signature(alg) as sig:
            return bool(sig.verify(message, signature, public_key))
    except Exception:
        return False


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
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
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
                format=serialization.PublicFormat.Raw,
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
