"""
Post-Quantum Key Encapsulation Mechanism using ML-KEM-768 (NIST FIPS 203).
Provides Category 3 security (equivalent to AES-192, lattice-based IND-CCA2 security).
"""

from typing import Tuple
import mlkem


class MLKEM768KeyExchange:
    """Manages ML-KEM-768 key generation, encapsulation, and decapsulation."""

    ENCAPS_KEY_SIZE = 1184
    DECAPS_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32

    def __init__(self):
        self._kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generates ML-KEM-768 encapsulation (public) key and decapsulation (private) key.
        
        Returns:
            Tuple of (decaps_key_bytes: 2400B, encaps_key_bytes: 1184B)
        """
        ek, dk = self._kem.key_gen()
        return dk.to_bytes(), ek.to_bytes()

    def encapsulate(self, peer_encaps_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulates a fresh 32-byte shared secret using peer's encapsulation key.
        
        Args:
            peer_encaps_key_bytes: 1184 bytes raw encapsulation key
            
        Returns:
            Tuple of (shared_secret: 32B, ciphertext: 1088B)
        """
        if len(peer_encaps_key_bytes) != self.ENCAPS_KEY_SIZE:
            raise ValueError(f"Invalid ML-KEM-768 encapsulation key size: expected {self.ENCAPS_KEY_SIZE}, got {len(peer_encaps_key_bytes)}")
        
        ek = mlkem.EncapsKey.from_bytes(peer_encaps_key_bytes)
        shared_secret, ciphertext = self._kem.encaps(ek)
        return shared_secret, ciphertext

    def decapsulate(self, decaps_key_bytes: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulates the shared secret using private decapsulation key and peer ciphertext.
        
        Args:
            decaps_key_bytes: 2400 bytes raw decapsulation key
            ciphertext: 1088 bytes ciphertext
            
        Returns:
            32-byte shared secret
        """
        if len(decaps_key_bytes) != self.DECAPS_KEY_SIZE:
            raise ValueError(f"Invalid ML-KEM-768 decapsulation key size: expected {self.DECAPS_KEY_SIZE}, got {len(decaps_key_bytes)}")
        if len(ciphertext) != self.CIPHERTEXT_SIZE:
            raise ValueError(f"Invalid ML-KEM-768 ciphertext size: expected {self.CIPHERTEXT_SIZE}, got {len(ciphertext)}")

        dk = mlkem.DecapsKey.from_bytes(decaps_key_bytes)
        shared_secret = self._kem.decaps(dk, ciphertext)
        return shared_secret

