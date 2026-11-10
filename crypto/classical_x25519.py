"""
Classical Elliptic-Curve Diffie-Hellman Key Agreement using Curve25519 (X25519 - RFC 7748).
Provides 128-bit classical security against non-quantum adversaries.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


class X25519KeyExchange:
    """Manages ephemeral X25519 key generation and Diffie-Hellman secret derivation."""

    PUBLIC_KEY_SIZE = 32
    SHARED_SECRET_SIZE = 32

    @staticmethod
    def generate_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
        """
        Generates a new ephemeral X25519 private key and raw public key bytes.
        
        Returns:
            Tuple of (private_key_obj, raw_public_key_32_bytes)
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_key, public_bytes

    @staticmethod
    def compute_shared_secret(private_key: x25519.X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
        """
        Computes 32-byte raw Diffie-Hellman shared secret with peer's public key.
        
        Args:
            private_key: Own X25519PrivateKey
            peer_public_bytes: 32 bytes raw public key from peer
            
        Returns:
            32-byte shared secret
        """
        if len(peer_public_bytes) != X25519KeyExchange.PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid X25519 public key size: expected {X25519KeyExchange.PUBLIC_KEY_SIZE}, got {len(peer_public_bytes)}")
        
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret

