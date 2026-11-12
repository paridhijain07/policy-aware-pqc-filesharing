# Implementation Plan — Policy-Aware PQC File Sharing

## Gap Table

| # | Requirement | Status | Evidence (file:line) | What's Needed |
|---|-------------|--------|----------------------|---------------|
| R1 | Key-establishment modes: X25519, ML-KEM-768, Hybrid | DONE | `policy/modes.py:8-12`, `crypto/classical_x25519.py`, `crypto/pqc_mlkem.py` | — |
| R2 | HKDF-SHA-256 for key derivation | DONE | `crypto/hybrid_combiner.py:87-93` | — |
| R3 | AES-256-GCM with unique nonces | DONE | `crypto/aead_cipher.py` (inferred from cipher usage in server/client) | — |
| R4 | Hybrid secret combination via HKDF over both secrets + transcript hash (NOT plain concat-and-hash) | PARTIAL | `crypto/hybrid_combiner.py:63-65` — IKM = `ss_classical \|\| ss_pqc` fed to a single HKDF; transcript hash is in `info`, not as a separate HKDF stage. This is a single-PRF over concatenation, not a Dual-PRF (RFC 9954 / NIST SP 800-56C "two-step" combiner). The comment says "Dual-PRF" but the code is one HKDF call. | Add proper two-step combiner: first HKDF-Extract with `ss_pqc` as IKM and `ss_classical` as salt, then HKDF-Expand with transcript-bound info. |
| R5 | Explicit security policy per transfer; hybrid mandatory → classical rejected | DONE | `policy/engine.py:51-58`, client enforces in `_perform_handshake` | — |
| R6 | Handshake transcript binding (downgrade modification detected) | DONE | `protocol/transcript.py`, Finished MAC includes `transcript_hash` in both client and server | — |
| R7 | Recovery: policy preserved across timeouts/retries | DONE | `core/client_policy.py:116` `evaluate_retry` guards security rank | — |
| R8 | Recovery: reconnection creates fresh authenticated session | DONE | `core/client_policy.py:82-85` new ephemeral keys each `_perform_handshake` call | — |
| R9 | Recovery: stale/replayed handshake messages rejected | DONE | `core/server.py:96-106` session_id registry + TTL check | — |
| R10 | Attack simulator: strip ML-KEM negotiation | DONE | `simulator/proxy.py:102-112` `STRIP_NEGOTIATION` | — |
| R11 | Attack simulator: replay handshakes | DONE | `simulator/proxy.py:159-172` `REPLAY_HANDSHAKE` | — |
| R12 | Attack simulator: interrupt at each handshake stage | PARTIAL | `simulator/proxy.py:115-125` drops `CLIENT_KEX`; no stage-by-stage interruption for `CLIENT_HELLO` or `SERVER_HELLO` specifically (only via `DROP_MLKEM_PACKET` dropping `SERVER_HELLO`). Missing: drop after `CLIENT_HELLO` before `SERVER_HELLO`. | Add `INTERRUPT_AFTER_CLIENT_HELLO` attack type or reuse `DROP_MLKEM_PACKET` logic to cover all handshake stages. |
| R13 | Attack simulator: interrupt transfers mid-chunk | DONE | `simulator/proxy.py:127-141` `SEVER_MIDWAY` | — |
| R14 | Attack simulator: classical-only reconnect when hybrid mandatory | DONE | `simulator/proxy.py:185-206` `DOWNGRADE_ON_RETRY` | — |
| R15 | Attack simulator: tamper ciphertext | DONE | `simulator/proxy.py:143-157` `CORRUPT_CIPHERTEXT` | — |
| R16 | Evaluation: baseline vs policy-enforced | DONE | `evaluation/run_experiments.py:40-91` | — |
| R17 | Metrics: handshake latency | DONE | `evaluation/run_experiments.py:99-139` total elapsed measured | — |
| R18 | Metrics: throughput across file sizes | MISSING | `evaluation/run_experiments.py:7` only mentions it; no throughput-by-filesize experiment exists | Add `run_throughput_experiment()` with varied file sizes |
| R19 | Metrics: recovery time | DONE | `evaluation/run_experiments.py:142-188` | — |
| R20 | Metrics: attack rejection rate | PARTIAL | `evaluation/run_experiments.py` only tracks `unauthorized_downgrade_occurred`; no aggregated attack-rejection-rate metric for all attack types | Add attack-rejection-rate column in security experiment |
| R21 | Metrics: unauthorized downgrade count | DONE | `evaluation/run_experiments.py:58-59` column present | — |
| R22 | Metrics: legitimate recovery success | PARTIAL | `run_experiments.py` recovery experiment only tests `SEVER_MIDWAY`; no explicit "legitimate recovery success rate" column | Add `Recovery_Success` boolean and success-rate aggregation |
| R23 | Metrics: CPU/memory (psutil) | MISSING | No `psutil` import or usage anywhere in repo | Add psutil measurements around key experiment loops |
| R24 | Metrics: handshake bytes/messages | MISSING | Wire size tracked in `benchmark_crypto.py` as static numbers, not measured live per-handshake in experiment | Add per-handshake byte/message counter in transport or experiment layer |
| R25 | Repeated trials, graphs (pandas/matplotlib) | DONE | `evaluation/run_experiments.py` has trial loops; `evaluation/plot_results.py` generates PNG charts | — |
| R26 | pytest: valid hybrid succeeds | DONE | `tests/test_transfer.py:14` `test_end_to_end_hybrid_file_transfer` | — |
| R27 | pytest: ML-KEM-stripped negotiation rejected when hybrid mandatory | DONE | `tests/test_attacks.py:24` `test_negotiation_stripping_attack_rejected` | — |
| R28 | pytest: replayed handshake rejected | DONE | `tests/test_attacks.py:376` `test_replay_handshake_rejected` | — |
| R29 | pytest: temporary interruption → secure retry | DONE | `tests/test_attacks.py:283` `test_midway_severance_resumption_under_hybrid` | — |
| R30 | pytest: hybrid fails then retry → no unauthorized classical fallback | DONE | `tests/test_attacks.py:154` `test_drop_mlkem_preserves_policy_in_resilient_client` | — |
| R31 | pytest: modified ciphertext → auth failure | DONE | `tests/test_attacks.py:335` `test_ciphertext_tampering_rejected_by_gcm` | — |
| R32 | pytest: reconnect after expired session → fresh session | DONE | `tests/test_attacks.py:479` `test_reconnection_after_expired_session` | — |
| R33 | pytest: classical explicitly permitted → classical succeeds | DONE | `tests/test_transfer.py:79` `test_end_to_end_classical_file_transfer` | — |
| R34 | `SecurityMode.HYBRID` enum value used in `run_experiments.py:113` | BROKEN | `evaluation/run_experiments.py:113` uses `SecurityMode.HYBRID` which does not exist (enum has `HYBRID_X25519_MLKEM768`). This will raise `AttributeError` at runtime. | Fix to `SecurityMode.HYBRID_X25519_MLKEM768` |

---

## Summary: 5 items need work (R4, R12, R18, R20–R24, R34)

Grouped into 6 steps below.

---

## Ordered Implementation Steps

### Step 1 — Fix `SecurityMode.HYBRID` AttributeError in `run_experiments.py`
**Files:** `evaluation/run_experiments.py`  
**Change:** Line 113: replace `SecurityMode.HYBRID` → `SecurityMode.HYBRID_X25519_MLKEM768`  
**Acceptance:** `python evaluation/run_experiments.py` starts without `AttributeError`; or unit-check: `python -c "from policy.modes import SecurityMode; print(SecurityMode.HYBRID_X25519_MLKEM768)"`  
**Dependencies:** None

---

### Step 2 — Fix Hybrid Combiner to Use True Dual-PRF (Two-Step HKDF)
**Files:** `crypto/hybrid_combiner.py`  
**Change:** Replace the single `HKDF(ikm=ss_classical+ss_pqc)` call with the two-step construction:
1. `prk = HKDF-Extract(salt=client_nonce+server_nonce, ikm=ss_pqc)` — extract with PQC secret
2. `ikm2 = HMAC-SHA256(prk, ss_classical)` — bind classical secret
3. `HKDF-Expand(prk, info=label+session_id+transcript_hash, length=72)` — expand with transcript binding

> **Assumption:** The "HKDF over both secrets + transcript hash" construction is interpreted as the RFC 9954 §3.2 two-step combiner: Extract using one secret as salt, fold the second via expand or a secondary Extract step, then Expand with transcript-bound info. This satisfies the invariant that breaking either component alone is insufficient.

**Acceptance:** `pytest tests/test_crypto.py tests/test_policy_protocol.py tests/test_transfer.py -x` all pass. Add a unit test asserting that `derive_keys(HYBRID, ...)` with same inputs but `ss_classical`/`ss_pqc` swapped produces a *different* key (commutativity broken, binding both).  
**Dependencies:** None (independent crypto change, but all integration tests depend on it passing)

---

### Step 3 — Add Missing Handshake-Stage Interruption Attack Type
**Files:** `simulator/attack_rules.py`, `simulator/proxy.py`  
**Change:**
- Add `INTERRUPT_AFTER_CLIENT_HELLO = "INTERRUPT_AFTER_CLIENT_HELLO"` to `AttackType` enum
- In `proxy._forward_s2c`: when this attack is active and `msg_type == SERVER_HELLO`, drop the packet (close connection) before forwarding, simulating interruption between ClientHello and ServerHello receipt

**Acceptance:** `pytest tests/test_attacks.py::test_interrupt_after_client_hello_rejected -x` (new test to be added in Step 3 or confirmed by existing behavior). The attack type is exercisable.  
**Dependencies:** None

---

### Step 4 — Add CPU/Memory Metrics via psutil
**Files:** `evaluation/run_experiments.py`  
**Change:** Add `import psutil`, capture `psutil.Process().cpu_percent(interval=None)` and `.memory_info().rss` before/after each trial loop iteration; store delta columns `CPU_Delta_%` and `Memory_RSS_Bytes` per trial row.  
**Acceptance:** Running `python evaluation/run_experiments.py` produces CSVs with `CPU_Delta_%` and `Memory_RSS_Bytes` columns.  
**Dependencies:** Step 1 (run_experiments.py must not crash on import first)

---

### Step 5 — Add Throughput-by-File-Size Experiment + Handshake Bytes/Messages Metrics
**Files:** `evaluation/run_experiments.py`, `evaluation/plot_results.py`  
**Change:**
- Add `run_throughput_experiment(trials=5)` function that tests file sizes [64KB, 256KB, 1MB, 4MB] for Baseline and Policy-Aware clients; records `File_Size_KB`, `Elapsed_ms`, `Throughput_MBps`
- Add handshake message counter: monkey-patch or wrap `AsyncTransport.send_message` / `receive_message` in experiments to count bytes and messages per session; record `Handshake_Bytes` and `Handshake_Messages` columns in latency CSV
- Add throughput bar chart to `plot_results.py`
- Call `run_throughput_experiment()` in `main()`

**Acceptance:** `python evaluation/run_experiments.py` completes without error; `results/throughput_evaluation.csv` exists with correct columns; throughput plot generated.  
**Dependencies:** Step 1, Step 4

---

### Step 6 — Add Attack Rejection Rate and Legitimate Recovery Success Metrics
**Files:** `evaluation/run_experiments.py`  
**Change:**
- In `run_security_experiment`: add `Attack_Rejected` boolean per trial (True if `PolicyDowngradeRejectedError` caught for policy-aware; False for baseline acceptance); aggregate and report `Attack_Rejection_Rate_%`
- In `run_recovery_experiment`: add `Recovery_Success` boolean per trial; compute `Legitimate_Recovery_Success_Rate_%`
- Update CSV exports to include these columns

**Acceptance:** `python evaluation/run_experiments.py` produces `security_evaluation.csv` with `Attack_Rejected` column and `recovery_evaluation.csv` with `Recovery_Success` column.  
**Dependencies:** Step 1

---

## Checklist

- [x] **Step 1** — Fix `SecurityMode.HYBRID` AttributeError in `run_experiments.py`
- [x] **Step 2** — Fix Hybrid Combiner to Use True Dual-PRF (Two-Step HKDF)
- [x] **Step 3** — Add Missing Handshake-Stage Interruption Attack Type
- [x] **Step 4** — Add CPU/Memory Metrics via psutil
- [x] **Step 5** — Add Throughput-by-File-Size Experiment + Handshake Bytes/Messages Metrics
- [x] **Step 6** — Add Attack Rejection Rate and Legitimate Recovery Success Metrics

