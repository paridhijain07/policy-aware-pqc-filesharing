"""
Unit tests for Cryptographic Primitives, Dual-PRF Hybrid Combiner, and AEAD Chunk Cipher.
"""

import os
import pytest
from crypto.classical_x25519 import X25519KeyExchange
from crypto.pqc_mlkem import MLKEM768KeyExchange
from crypto.hybrid_combiner import HybridKeyDerivation, SessionKeys
from crypto.aead_cipher import ChunkedAEADCipher, CryptographicIntegrityError


def test_x25519_key_exchange():
    """Verify classical ECDH key generation and mutual shared secret agreement."""
    priv_a, pub_a = X25519KeyExchange.generate_keypair()
    priv_b, pub_b = X25519KeyExchange.generate_keypair()

    ss_ab = X25519KeyExchange.compute_shared_secret(priv_a, pub_b)
    ss_ba = X25519KeyExchange.compute_shared_secret(priv_b, pub_a)

    assert len(ss_ab) == 32
    assert ss_ab == ss_ba
    assert len(pub_a) == 32
    assert len(pub_b) == 32


def test_mlkem768_key_exchange():
    """Verify NIST FIPS 203 ML-KEM-768 keygen, encapsulation, and decapsulation."""
    kem = MLKEM768KeyExchange()
    dk_server, ek_server = kem.generate_keypair()

    assert len(ek_server) == 1184
    assert len(dk_server) == 2400

    ss_client, ct = kem.encapsulate(ek_server)
    assert len(ss_client) == 32
    assert len(ct) == 1088

    ss_server = kem.decapsulate(dk_server, ct)
    assert len(ss_server) == 32
    assert ss_client == ss_server


def test_hybrid_combiner_derivation():
    """Verify Dual-PRF HKDF key derivation consistency between client and server."""
    # 1. Classical exchange
    priv_c, pub_c = X25519KeyExchange.generate_keypair()
    priv_s, pub_s = X25519KeyExchange.generate_keypair()
    ss_c_classical = X25519KeyExchange.compute_shared_secret(priv_c, pub_s)
    ss_s_classical = X25519KeyExchange.compute_shared_secret(priv_s, pub_c)

    # 2. PQC exchange
    kem = MLKEM768KeyExchange()
    dk_s, ek_s = kem.generate_keypair()
    ss_c_pqc, ct = kem.encapsulate(ek_s)
    ss_s_pqc = kem.decapsulate(dk_s, ct)

    # 3. Hybrid derivation parameters
    session_id = os.urandom(16)
    client_nonce = os.urandom(32)
    server_nonce = os.urandom(32)
    salt = client_nonce + server_nonce
    transcript_hash = os.urandom(32)

    client_keys = HybridKeyDerivation.derive_keys(
        mode="HYBRID",
        session_id=session_id,
        salt=salt,
        transcript_hash=transcript_hash,
        ss_classical=ss_c_classical,
        ss_pqc=ss_c_pqc
    )

    server_keys = HybridKeyDerivation.derive_keys(
        mode="HYBRID",
        session_id=session_id,
        salt=salt,
        transcript_hash=transcript_hash,
        ss_classical=ss_s_classical,
        ss_pqc=ss_s_pqc
    )

    assert client_keys.enc_key == server_keys.enc_key
    assert client_keys.mac_key == server_keys.mac_key
    assert client_keys.iv_salt == server_keys.iv_salt
    assert len(client_keys.enc_key) == 32
    assert len(client_keys.mac_key) == 32
    assert len(client_keys.iv_salt) == 8

    # Finished HMAC tag verification
    client_fin_tag = HybridKeyDerivation.compute_finished_tag(client_keys.mac_key, "CLIENT", transcript_hash)
    assert HybridKeyDerivation.verify_finished_tag(server_keys.mac_key, "CLIENT", transcript_hash, client_fin_tag)

    # Negative test: Tampered transcript
    bad_transcript = os.urandom(32)
    assert not HybridKeyDerivation.verify_finished_tag(server_keys.mac_key, "CLIENT", bad_transcript, client_fin_tag)


def test_chunked_aead_cipher_integrity():
    """Verify AES-256-GCM chunk encryption, decryption, and tamper detection."""
    enc_key = os.urandom(32)
    iv_salt = os.urandom(8)
    session_id = os.urandom(16)
    file_id = os.urandom(16)

    cipher_sender = ChunkedAEADCipher(enc_key, iv_salt, session_id)
    cipher_receiver = ChunkedAEADCipher(enc_key, iv_salt, session_id)

    chunk_plaintext = b"PQC-Secure-File-Sharing-Data-Block-Payload-Test-Bytes"
    chunk_index = 0
    total_chunks = 1

    nonce, ciphertext = cipher_sender.encrypt_chunk(
        file_id=file_id,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        plaintext=chunk_plaintext,
        is_final=True
    )

    # Valid decryption
    decrypted = cipher_receiver.decrypt_chunk(
        file_id=file_id,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        ciphertext=ciphertext,
        is_final=True
    )
    assert decrypted == chunk_plaintext

    # Tamper test 1: Bit flip in ciphertext
    corrupted_ct = bytearray(ciphertext)
    corrupted_ct[5] ^= 0xFF
    with pytest.raises(CryptographicIntegrityError):
        cipher_receiver.decrypt_chunk(
            file_id=file_id,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            ciphertext=bytes(corrupted_ct),
            is_final=True
        )

    # Tamper test 2: Chunk reordering (wrong chunk index in AAD)
    with pytest.raises(CryptographicIntegrityError):
        cipher_receiver.decrypt_chunk(
            file_id=file_id,
            chunk_index=chunk_index + 1,  # Reordered!
            total_chunks=total_chunks,
            ciphertext=ciphertext,
            is_final=True
        )

    # Tamper test 3: Cross-session splicing (wrong session_id in receiver)
    wrong_receiver = ChunkedAEADCipher(enc_key, iv_salt, os.urandom(16))
    with pytest.raises(CryptographicIntegrityError):
        wrong_receiver.decrypt_chunk(
            file_id=file_id,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            ciphertext=ciphertext,
            is_final=True
        )

