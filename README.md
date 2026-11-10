# Policy-Aware Post-Quantum Secure File Sharing Under Network Failures

An end-to-end implementation and experimental evaluation of a **policy-aware post-quantum file sharing protocol** resilient against network failures, timeouts, and man-in-the-middle downgrade attacks.

Combines **Classical X25519 (RFC 7748)** and **Post-Quantum ML-KEM-768 (NIST FIPS 203 Category 3)** through a standardized **Dual-PRF HKDF-SHA256 Combiner (RFC 9954)**, authenticated via **AES-256-GCM chunked AEAD** and cryptographic transcript binding.

---

## 🌟 Key Features

1. **Cryptographic Primitives & Combiner:**
   - **Classical:** X25519 Elliptic Curve Diffie-Hellman (ECDH).
   - **Post-Quantum:** NIST FIPS 203 ML-KEM-768 (Kyber-768, lattice-based IND-CCA2 hardness).
   - **Hybrid Combiner:** Standardized Dual-PRF HKDF-Extract-and-Expand with transcript hash binding.
   - **Data Confidentiality & Authenticity:** AES-256-GCM chunked AEAD with monotonic IV nonces and bound AAD (session ID, file ID, chunk sequence, total chunks).
2. **Policy Enforcement Engine:**
   - Enforces the cryptographic invariant: *Network interruptions, timeouts, and retries must NEVER authorize a reduction in cryptographic security.*
   - Rejects silent classical-only fallbacks when `STRICT_HYBRID` or `STRICT_PQC` is required.
3. **Active Network Failure & Attack Simulator:**
   - Transparent TCP proxy capable of injecting real-world faults:
     - **ML-KEM Packet Dropping:** Induces PQC timeout to trigger fallback.
     - **Negotiation Stripping:** MiTM tampering of ClientHello/ServerHello.
     - **Connection Severance:** Abrupt TCP connection drops mid-transfer to evaluate resumption.
     - **Ciphertext Corruption:** In-flight bit flips to verify AEAD authentication tags.
     - **Handshake Replay:** Replaying captured session messages.
4. **Resilient Stateful Resumption:**
   - Reconnects with fresh ephemeral key establishment (Perfect Forward Secrecy).
   - Queries server for chunk offset and resumes streaming remaining blocks without restarting from scratch or weakening security.
5. **Interactive Web Dashboard:**
   - Real-time animated cryptographic handshake step visualizer.
   - Attack switchboard with single-click fault injection.
   - Live side-by-side demonstration: Baseline (vulnerable fallback alert) vs. Policy-Aware (green shield protection).
   - Embedded experimental research charts and performance scorecards.

---

## 🏗️ Architecture

```
+-----------------------------------------------------------------------------------------+
|                                      CLIENT APPLICATION                                 |
|  [ File Manager ] <---> [ Chunked AEAD Cipher ] <---> [ Cryptographic Policy Engine ]   |
+-----------------------------------------------------------------------------------------+
                                          |
                                          v  (TCP Connection)
+-----------------------------------------------------------------------------------------+
|                         NETWORK ADVERSARY & FAULT PROXY                                 |
|   - Packet Dropper (ML-KEM)    - Negotiation Stripper     - Mid-Transfer Severance       |
+-----------------------------------------------------------------------------------------+
                                          |
                                          v  (TCP Connection)
+-----------------------------------------------------------------------------------------+
|                                    FILE SHARING SERVER                                  |
|  [ Transcript Authenticator ] <-> [ Dual-PRF HKDF ] <-> [ Atomic Disk Assembly ]        |
+-----------------------------------------------------------------------------------------+
```

---

## 🚀 Quick Start

### 1. Requirements & Installation
Ensure Python 3.11+ is installed. Dependencies:
```bash
pip install -r requirements.txt
```

### 2. Launch the Interactive Web Dashboard
```bash
python main.py --ui
```
Open your browser and navigate to: **`http://localhost:8000`**

### 3. Run Automated Unit & Attack Tests
```bash
python main.py --test
# Or directly:
pytest tests/ -v
```

### 4. Run Benchmarks & Generate Research Graphs
```bash
python main.py --benchmark
```
Generated high-resolution figures are saved directly to `results/plots/`:
- `downgrade_prevention_rate.png`
- `crypto_latency_benchmark.png`
- `wire_overhead_comparison.png`
- `recovery_time_analysis.png`

---

## 📊 Summary of Experimental Findings

| Metric | Baseline Architecture (Naive Fallback) | Proposed Policy-Aware Architecture |
| :--- | :--- | :--- |
| **Unauthorized Downgrade Rate** | **100% (Vulnerable to SNDL)** | **0% (Inviolable Guard)** |
| **ML-KEM Keygen / Encapsulation** | ~0.167 ms | ~0.167 ms |
| **Classical X25519 Keygen / ECDH** | ~0.264 ms | ~0.264 ms |
| **Total Hybrid Handshake Compute** | ~0.446 ms | ~0.446 ms |
| **Symmetric AEAD Throughput** | ~3,300 MB/s (AES-256-GCM) | ~3,300 MB/s (AES-256-GCM) |
| **Midway Resumption Time** | Full restart required | **< 5 ms (resumes at chunk offset)** |

---

## 📂 Project Organization

```
├── crypto/                     # Cryptographic Primitives & Combiners
│   ├── classical_x25519.py     # X25519 ECDH (RFC 7748)
│   ├── pqc_mlkem.py            # ML-KEM-768 FIPS 203
│   ├── hybrid_combiner.py      # Dual-PRF HKDF-SHA256 (RFC 9954)
│   └── aead_cipher.py          # AES-256-GCM Chunked AEAD
├── policy/                     # Security Policy Enforcement
│   ├── modes.py                # SecurityMode & PolicyLevel Enums
│   └── engine.py               # Invariant Guard & Audit Log
├── protocol/                   # Wire Serialization & Handshake Transcript
│   ├── messages.py             # Wire Message Formats & Framing
│   └── transcript.py           # Rolling SHA-256 Transcript Binding
├── core/                       # Client & Server Implementations
│   ├── server.py               # File Sharing Server
│   ├── client_policy.py        # Policy-Aware Resilient Client
│   ├── client_baseline.py      # Vulnerable Baseline Client
│   ├── transport.py            # AsyncIO Transport Framing
│   └── file_manager.py         # Chunked File Reader/Writer
├── simulator/                  # Network Fault & Attack Simulator Proxy
│   ├── proxy.py                # Intercepting TCP Proxy
│   └── attack_rules.py         # Fault Model Configurations
├── ui/                         # Interactive Web Dashboard
│   ├── app.py                  # FastAPI + WebSockets Backend
│   └── templates/index.html    # Modern Dark-Mode Dashboard
├── evaluation/                 # Benchmark & Plotting Scripts
│   ├── benchmark_crypto.py     # Microbenchmarking primitives
│   ├── run_experiments.py      # Batch trial runs
│   └── plot_results.py         # Matplotlib chart generator
├── tests/                      # Pytest Test Suite
│   ├── test_crypto.py
│   ├── test_policy_protocol.py
│   ├── test_transfer.py
│   └── test_attacks.py
├── results/                    # CSV Datasets & Generated Plots
├── main.py                     # Unified CLI Entrypoint
└── requirements.txt            # Python Dependencies
```

