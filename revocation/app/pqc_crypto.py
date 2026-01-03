import json
import secrets
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64

def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def dilithium_sign(message: bytes) -> str:
    # TODO: replace with real Dilithium signing
    return secrets.token_hex(64)

def dilithium_verify(message: bytes, sig_hex: str, kid: str) -> bool:
    # TODO: replace with real Dilithium verify
    return True


# Kyber-based Forward Secrecy Implementation
# Using X25519 (ECDH) for forward secrecy - can be replaced with actual Kyber later
class KyberKeyExchange:
    """
    Kyber-like key exchange for forward secrecy.
    Uses X25519 for now (provides forward secrecy) - can be replaced with actual Kyber.
    """
    
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Generate a key pair for Kyber key exchange.
        Returns: (private_key, public_key) as bytes
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Serialize keys
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
    
    @staticmethod
    def derive_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
        """
        Derive shared secret using Kyber-like key exchange.
        
        Args:
            private_key: Our private key
            peer_public_key: Peer's public key
        
        Returns:
            Shared secret bytes
        """
        try:
            # Reconstruct keys
            private = x25519.X25519PrivateKey.from_private_bytes(private_key)
            public = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
            
            # Perform key exchange
            shared_key = private.exchange(public)
            
            # Derive a 32-byte key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'kyber-forward-secrecy',
                backend=default_backend()
            )
            derived_key = hkdf.derive(shared_key)
            
            return derived_key
        except Exception as e:
            raise ValueError(f"Key exchange failed: {str(e)}")
    
    @staticmethod
    def encode_public_key(public_key: bytes) -> str:
        """Encode public key to base64 string"""
        return base64.urlsafe_b64encode(public_key).decode('utf-8').rstrip('=')
    
    @staticmethod
    def decode_public_key(encoded: str) -> bytes:
        """Decode public key from base64 string"""
        # Add padding if needed
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding
        return base64.urlsafe_b64decode(encoded)


def generate_kyber_keypair() -> Tuple[str, str]:
    """
    Generate Kyber key pair and return encoded public key and private key.
    Returns: (public_key_encoded, private_key_hex)
    """
    private_key, public_key = KyberKeyExchange.generate_keypair()
    public_encoded = KyberKeyExchange.encode_public_key(public_key)
    private_hex = private_key.hex()
    return public_encoded, private_hex


def derive_kyber_secret(private_key_hex: str, peer_public_key_encoded: str) -> str:
    """
    Derive shared secret from key exchange.
    Returns: shared_secret_hex
    """
    private_key = bytes.fromhex(private_key_hex)
    peer_public_key = KyberKeyExchange.decode_public_key(peer_public_key_encoded)
    shared_secret = KyberKeyExchange.derive_shared_secret(private_key, peer_public_key)
    return shared_secret.hex()


def hash_client_binding(client_info: str) -> str:
    """
    Hash client binding information for refresh token binding.
    
    Args:
        client_info: Client identifier (device fingerprint, IP, user agent hash, etc.)
    
    Returns:
        SHA256 hash of client info
    """
    return hashlib.sha256(client_info.encode('utf-8')).hexdigest()
