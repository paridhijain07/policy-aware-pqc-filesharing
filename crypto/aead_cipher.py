"""
Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM.
Enforces chunk-level integrity, prevents reordering, truncation, and splicing attacks.
"""

import struct
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class CryptographicIntegrityError(Exception):
    """Raised when ciphertext or authentication tag verification fails."""
    pass


class ChunkedAEADCipher:
    """Manages chunked AES-256-GCM encryption and decryption with monotonic nonces and AAD."""

    CHUNK_SIZE = 64 * 1024  # 64 KB chunks
    NONCE_SIZE = 12         # 96 bits for AES-GCM
    TAG_SIZE = 16           # 128 bits GCM tag

    def __init__(self, enc_key: bytes, iv_salt: bytes, session_id: bytes):
        if len(enc_key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        if len(iv_salt) != 8:
            raise ValueError("Base IV salt must be 8 bytes")
        if len(session_id) != 16:
            raise ValueError("Session ID must be 16 bytes")

        self.enc_key = enc_key
        self.iv_salt = iv_salt
        self.session_id = session_id
        self._aesgcm = AESGCM(enc_key)

    def _derive_chunk_nonce(self, chunk_index: int) -> bytes:
        """Derives a deterministic 12-byte IV for the chunk: salt (8B) || chunk_index (4B)."""
        return self.iv_salt + struct.pack(">I", chunk_index)

    def _construct_aad(self, file_id: bytes, chunk_index: int, total_chunks: int, is_final: bool) -> bytes:
        """
        Constructs authenticated additional data binding session, file, chunk index, and boundary.
        AAD: session_id (16B) || file_id (16B) || chunk_index (4B) || total_chunks (4B) || is_final (1B)
        """
        if len(file_id) != 16:
            raise ValueError("File ID must be 16 bytes")
        return struct.pack(">16s 16s I I B", self.session_id, file_id, chunk_index, total_chunks, 1 if is_final else 0)

    def encrypt_chunk(
        self,
        file_id: bytes,
        chunk_index: int,
        total_chunks: int,
        plaintext: bytes,
        is_final: bool = False
    ) -> Tuple[bytes, bytes]:
        """
        Encrypts a plaintext chunk using AES-256-GCM with deterministic nonce and bound AAD.

        Returns:
            Tuple of (nonce: 12B, ciphertext_with_tag: bytes)
        """
        nonce = self._derive_chunk_nonce(chunk_index)
        aad = self._construct_aad(file_id, chunk_index, total_chunks, is_final)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt_chunk(
        self,
        file_id: bytes,
        chunk_index: int,
        total_chunks: int,
        ciphertext: bytes,
        is_final: bool = False
    ) -> bytes:
        """
        Decrypts and authenticates a chunk.
        
        Raises:
            CryptographicIntegrityError: If ciphertext, tag, or AAD has been tampered with.
        """
        nonce = self._derive_chunk_nonce(chunk_index)
        aad = self._construct_aad(file_id, chunk_index, total_chunks, is_final)
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext
        except InvalidTag as e:
            raise CryptographicIntegrityError(
                f"Tampering detected! AES-GCM tag mismatch on chunk {chunk_index}/{total_chunks}."
            ) from e

