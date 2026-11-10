"""
Microbenchmarking Cryptographic Primitives: X25519 vs ML-KEM-768 vs Dual-PRF Hybrid.
Measures execution time, wire overhead, and symmetric AEAD throughput.
"""

import os
import sys
import time
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.classical_x25519 import X25519KeyExchange
from crypto.pqc_mlkem import MLKEM768KeyExchange
from crypto.hybrid_combiner import HybridKeyDerivation
from crypto.aead_cipher import ChunkedAEADCipher


def benchmark_primitives(iterations: int = 100) -> pd.DataFrame:
    """Executes benchmark iterations across classical, PQC, and hybrid operations."""
    results = []

    # 1. Classical X25519
    t0 = time.perf_counter()
    for _ in range(iterations):
        priv_c, pub_c = X25519KeyExchange.generate_keypair()
        priv_s, pub_s = X25519KeyExchange.generate_keypair()
        ss_c = X25519KeyExchange.compute_shared_secret(priv_c, pub_s)
        ss_s = X25519KeyExchange.compute_shared_secret(priv_s, pub_c)
    t1 = time.perf_counter()
    avg_x25519_ms = ((t1 - t0) / iterations) * 1000

    results.append({
        "Primitive": "X25519 (Classical)",
        "Type": "Key Exchange",
        "Avg Time (ms)": round(avg_x25519_ms, 3),
        "Public Key Size (Bytes)": 32,
        "Ciphertext / Exchange Size (Bytes)": 32,
        "Shared Secret Size (Bytes)": 32,
        "Post-Quantum Hardness": "No (Broken by Shor's Algo)"
    })

    # 2. ML-KEM-768 (FIPS 203)
    kem = MLKEM768KeyExchange()
    t0 = time.perf_counter()
    for _ in range(iterations):
        dk, ek = kem.generate_keypair()
        ss_c, ct = kem.encapsulate(ek)
        ss_s = kem.decapsulate(dk, ct)
    t1 = time.perf_counter()
    avg_mlkem_ms = ((t1 - t0) / iterations) * 1000

    results.append({
        "Primitive": "ML-KEM-768 (NIST FIPS 203)",
        "Type": "Key Encapsulation",
        "Avg Time (ms)": round(avg_mlkem_ms, 3),
        "Public Key Size (Bytes)": 1184,
        "Ciphertext / Exchange Size (Bytes)": 1088,
        "Shared Secret Size (Bytes)": 32,
        "Post-Quantum Hardness": "Yes (Category 3 Lattice)"
    })

    # 3. Hybrid Dual-PRF Combiner (X25519 + ML-KEM-768 + HKDF-SHA256)
    priv_c, pub_c = X25519KeyExchange.generate_keypair()
    priv_s, pub_s = X25519KeyExchange.generate_keypair()
    ss_classical = X25519KeyExchange.compute_shared_secret(priv_c, pub_s)
    dk, ek = kem.generate_keypair()
    ss_pqc, ct = kem.encapsulate(ek)

    salt = os.urandom(64)
    session_id = os.urandom(16)
    transcript_hash = os.urandom(32)

    t0 = time.perf_counter()
    for _ in range(iterations):
        # Full hybrid combined derivation
        keys = HybridKeyDerivation.derive_keys(
            mode="HYBRID",
            session_id=session_id,
            salt=salt,
            transcript_hash=transcript_hash,
            ss_classical=ss_classical,
            ss_pqc=ss_pqc
        )
        tag = HybridKeyDerivation.compute_finished_tag(keys.mac_key, "CLIENT", transcript_hash)
        HybridKeyDerivation.verify_finished_tag(keys.mac_key, "CLIENT", transcript_hash, tag)
    t1 = time.perf_counter()
    avg_hybrid_ms = ((t1 - t0) / iterations) * 1000

    results.append({
        "Primitive": "Hybrid (X25519 + ML-KEM + HKDF)",
        "Type": "Complete Dual-PRF Handshake",
        "Avg Time (ms)": round(avg_x25519_ms + avg_mlkem_ms + avg_hybrid_ms, 3),
        "Public Key Size (Bytes)": 32 + 1184,
        "Ciphertext / Exchange Size (Bytes)": 32 + 1088,
        "Shared Secret Size (Bytes)": 64,
        "Post-Quantum Hardness": "Yes (Dual-PRF Guaranteed)"
    })

    # 4. AES-256-GCM AEAD Throughput
    enc_key = os.urandom(32)
    iv_salt = os.urandom(8)
    cipher = ChunkedAEADCipher(enc_key, iv_salt, session_id)
    payload_64k = os.urandom(64 * 1024)
    file_id = os.urandom(16)

    t0 = time.perf_counter()
    enc_iters = 500
    for i in range(enc_iters):
        nonce, ct = cipher.encrypt_chunk(file_id, i, enc_iters, payload_64k)
        cipher.decrypt_chunk(file_id, i, enc_iters, ct)
    t1 = time.perf_counter()
    total_bytes = enc_iters * len(payload_64k) * 2  # Encrypt + Decrypt
    throughput_mb_s = (total_bytes / (1024 * 1024)) / (t1 - t0)

    results.append({
        "Primitive": "AES-256-GCM AEAD (64KB Chunks)",
        "Type": "Symmetric Encryption/Auth",
        "Avg Time (ms)": round(((t1 - t0) / enc_iters) * 1000, 3),
        "Public Key Size (Bytes)": 32,
        "Ciphertext / Exchange Size (Bytes)": 64 * 1024 + 16,
        "Shared Secret Size (Bytes)": 32,
        "Post-Quantum Hardness": f"Throughput: {round(throughput_mb_s, 1)} MB/s"
    })

    df = pd.DataFrame(results)
    os.makedirs("results", exist_ok=True)
    df.to_csv("results/crypto_benchmark_results.csv", index=False)
    return df


if __name__ == "__main__":
    print("\n=== Running Cryptographic Primitives Benchmark ===")
    df = benchmark_primitives(iterations=100)
    print(df.to_string(index=False))
