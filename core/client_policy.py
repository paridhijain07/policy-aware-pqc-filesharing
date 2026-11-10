"""
Policy-Aware Resilient Client Implementation.
Enforces invariant: Connection failures, timeouts, and retries CANNOT reduce cryptographic security.
Performs fresh ephemeral handshakes upon reconnection and resumes file streams securely.
"""

import os
import asyncio
import logging
from typing import Dict, Optional, Callable
from protocol.messages import (
    MessageType,
    ClientHello,
    ServerHello,
    ClientKex,
    ServerFinished,
    FileMetadata,
    FileChunk,
    ResumeRequest,
    ErrorMessage,
)
from protocol.transcript import HandshakeTranscript
from policy.modes import SecurityMode, PolicyLevel
from policy.engine import PolicyEngine, PolicyDowngradeRejectedError
from crypto.classical_x25519 import X25519KeyExchange
from crypto.pqc_mlkem import MLKEM768KeyExchange
from crypto.hybrid_combiner import HybridKeyDerivation, SessionKeys
from crypto.aead_cipher import ChunkedAEADCipher
from .transport import AsyncTransport, ConnectionClosedError, ProtocolTimeoutError
from .file_manager import FileManager

logger = logging.getLogger("PolicyClient")


class PolicyAwareClient:
    """Policy-enforced client that rejects downgrades across network failures and retries."""

    def __init__(
        self,
        server_host: str = "127.0.0.1",
        server_port: int = 8765,
        policy: PolicyLevel = PolicyLevel.STRICT_HYBRID,
        max_retries: int = 3,
        retry_delay_sec: float = 1.0,
        event_callback: Optional[Callable[[str, Dict], None]] = None
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.policy = policy
        self.max_retries = max_retries
        self.retry_delay_sec = retry_delay_sec
        self.event_callback = event_callback
        self.policy_engine = PolicyEngine(self.policy)

    def _emit(self, event_type: str, data: Dict):
        if self.event_callback:
            try:
                self.event_callback(event_type, data)
            except Exception as e:
                logger.error(f"Client event callback error: {e}")

    async def transfer_file(self, file_path: str, job_id: Optional[str] = None) -> Dict:
        """
        Executes policy-governed file transfer with automatic failure recovery and downgrade resistance.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File to transfer does not exist: {file_path}")

        job_id = job_id or f"job-{os.urandom(8).hex()}"
        file_size, total_chunks, sha256_hash = FileManager.get_file_info(file_path)
        file_name = os.path.basename(file_path)

        current_chunk_offset = 0
        attempt = 0
        last_negotiated_mode = None
        transfer_completed = False

        self._emit("TRANSFER_INITIATED", {
            "job_id": job_id,
            "file_name": file_name,
            "file_size": file_size,
            "policy": self.policy.value,
        })

        while attempt < self.max_retries and not transfer_completed:
            attempt += 1
            writer = None
            try:
                self._emit("CONNECTION_ATTEMPT", {
                    "attempt": attempt,
                    "max_retries": self.max_retries,
                    "resume_chunk": current_chunk_offset,
                })

                reader, writer = await asyncio.open_connection(self.server_host, self.server_port)

                # 1. Prepare ephemeral keys
                client_nonce = os.urandom(32)
                session_id = os.urandom(16)
                priv_x25519, pub_x25519 = X25519KeyExchange.generate_keypair()

                # Offered modes based on policy (Never offering classical when STRICT_HYBRID is requested)
                offered_modes = [SecurityMode.HYBRID_X25519_MLKEM768.value]
                if self.policy == PolicyLevel.COMPAT_CLASSICAL:
                    offered_modes.append(SecurityMode.CLASSICAL_X25519.value)

                client_hello = ClientHello(
                    client_nonce=client_nonce,
                    session_id=session_id,
                    transfer_job_id=job_id,
                    offered_modes=offered_modes,
                    client_policy=self.policy.value,
                    client_x25519_pk=pub_x25519,
                )

                transcript = HandshakeTranscript()
                c_hello_dict = client_hello.to_dict()
                await AsyncTransport.send_message(writer, c_hello_dict)
                transcript.update(c_hello_dict)

                # 2. Receive ServerHello
                s_hello_dict = await AsyncTransport.receive_message(reader, timeout=5.0)
                if s_hello_dict.get("type") == MessageType.ERROR.value:
                    raise RuntimeError(f"Server error during hello: {s_hello_dict.get('description')}")
                if s_hello_dict.get("type") != MessageType.SERVER_HELLO.value:
                    raise ValueError("Expected SERVER_HELLO")

                server_hello = ServerHello.from_dict(s_hello_dict)
                transcript.update(s_hello_dict)

                negotiated_mode = SecurityMode(server_hello.selected_mode)

                # 3. CRUCIAL POLICY ENFORCEMENT GUARD:
                # Validates invariant: negotiation must strictly satisfy transfer policy
                if last_negotiated_mode:
                    self.policy_engine.evaluate_retry(last_negotiated_mode, negotiated_mode, attempt)
                else:
                    self.policy_engine.evaluate_negotiation(negotiated_mode)

                last_negotiated_mode = negotiated_mode
                self._emit("POLICY_VERIFIED", {
                    "negotiated_mode": negotiated_mode.value,
                    "policy": self.policy.value,
                    "status": "APPROVED",
                })

                # 4. Perform Key Agreement
                ss_classical = None
                if negotiated_mode in (SecurityMode.HYBRID_X25519_MLKEM768, SecurityMode.CLASSICAL_X25519):
                    if not server_hello.server_x25519_pk:
                        raise ValueError("Missing server X25519 public key")
                    ss_classical = X25519KeyExchange.compute_shared_secret(priv_x25519, server_hello.server_x25519_pk)

                ss_pqc = None
                mlkem_ct = None
                if negotiated_mode in (SecurityMode.HYBRID_X25519_MLKEM768, SecurityMode.PQC_MLKEM768):
                    if not server_hello.server_mlkem_pk:
                        raise ValueError("Missing server ML-KEM public key")
                    kem = MLKEM768KeyExchange()
                    ss_pqc, mlkem_ct = kem.encapsulate(server_hello.server_mlkem_pk)

                # 5. Derive keys & send ClientKex
                salt = client_nonce + server_hello.server_nonce
                # Update transcript with ClientKex (without MAC) before computing MAC
                kex_template = ClientKex(
                    session_id=session_id,
                    mlkem_ciphertext=mlkem_ct,
                    client_finished_mac=b""
                )
                kex_dict_for_transcript = kex_template.to_dict()
                kex_dict_for_transcript.pop("client_finished_mac", None)
                transcript.update(kex_dict_for_transcript)
                transcript_hash = transcript.current_digest()

                session_keys = HybridKeyDerivation.derive_keys(
                    mode=negotiated_mode.value,
                    session_id=session_id,
                    salt=salt,
                    transcript_hash=transcript_hash,
                    ss_classical=ss_classical,
                    ss_pqc=ss_pqc
                )

                client_fin_tag = HybridKeyDerivation.compute_finished_tag(
                    session_keys.mac_key, "CLIENT", transcript_hash
                )
                client_kex = ClientKex(
                    session_id=session_id,
                    mlkem_ciphertext=mlkem_ct,
                    client_finished_mac=client_fin_tag
                )
                await AsyncTransport.send_message(writer, client_kex.to_dict())

                # 6. Receive ServerFinished
                fin_dict = await AsyncTransport.receive_message(reader, timeout=5.0)
                if fin_dict.get("type") == MessageType.ERROR.value:
                    raise RuntimeError(f"Handshake rejected: {fin_dict.get('description')}")
                if fin_dict.get("type") != MessageType.SERVER_FINISHED.value:
                    raise ValueError("Expected SERVER_FINISHED")

                server_fin = ServerFinished.from_dict(fin_dict)
                is_fin_valid = HybridKeyDerivation.verify_finished_tag(
                    session_keys.mac_key, "SERVER", transcript_hash, server_fin.server_finished_mac
                )
                if not is_fin_valid:
                    raise RuntimeError("Server Finished MAC verification failed! Server handshake compromised.")

                self._emit("HANDSHAKE_ESTABLISHED", {
                    "mode": negotiated_mode.value,
                    "attempt": attempt,
                    "session_id": session_id.hex(),
                })

                # 7. Initialize AEAD Cipher
                cipher = ChunkedAEADCipher(
                    enc_key=session_keys.enc_key,
                    iv_salt=session_keys.iv_salt,
                    session_id=session_keys.session_id
                )

                # 8. Check for Resumption on retry
                file_id = os.urandom(16)
                if attempt > 1:
                    resume_req = ResumeRequest(
                        session_id=session_id,
                        file_id=file_id,
                        transfer_job_id=job_id,
                        last_received_chunk=current_chunk_offset
                    )
                    await AsyncTransport.send_message(writer, resume_req.to_dict())
                    res_dict = await AsyncTransport.receive_message(reader, timeout=5.0)
                    current_chunk_offset = res_dict.get("resume_chunk_offset", 0)
                    self._emit("STREAM_RESUMED", {"chunk_offset": current_chunk_offset})

                # 9. Send Metadata
                meta = FileMetadata(
                    session_id=session_id,
                    file_id=file_id,
                    file_name=file_name,
                    file_size=file_size,
                    total_chunks=total_chunks,
                    sha256_hash=sha256_hash
                )
                await AsyncTransport.send_message(writer, meta.to_dict())

                # 10. Send Chunks starting at current offset
                for index, chunk_data, is_final in FileManager.read_chunks(file_path, start_chunk=current_chunk_offset):
                    nonce, ct = cipher.encrypt_chunk(
                        file_id=file_id,
                        chunk_index=index,
                        total_chunks=total_chunks,
                        plaintext=chunk_data,
                        is_final=is_final
                    )
                    chunk_msg = FileChunk(
                        session_id=session_id,
                        file_id=file_id,
                        chunk_index=index,
                        total_chunks=total_chunks,
                        is_final=is_final,
                        nonce=nonce,
                        ciphertext=ct
                    )
                    await AsyncTransport.send_message(writer, chunk_msg.to_dict())
                    self._emit("CHUNK_SENT", {
                        "chunk_index": index,
                        "total_chunks": total_chunks,
                        "pct": round(((index + 1) / total_chunks) * 100, 1)
                    })

                # 11. Wait for completion ACK
                ack_dict = await AsyncTransport.receive_message(reader, timeout=10.0)
                if ack_dict.get("status") == "COMPLETED_VERIFIED":
                    transfer_completed = True
                    self._emit("TRANSFER_SUCCESS", {
                        "job_id": job_id,
                        "verified_sha256": sha256_hash,
                        "attempts_used": attempt,
                    })
                    return {
                        "status": "SUCCESS",
                        "job_id": job_id,
                        "verified_sha256": sha256_hash,
                        "attempts": attempt,
                        "mode": negotiated_mode.value,
                        "downgrades_prevented": self.policy_engine.total_downgrades_rejected,
                    }

            except PolicyDowngradeRejectedError as e:
                logger.error(f"[SHIELD ACTIVE] Policy Engine rejected downgrade: {e}")
                self._emit("POLICY_DOWNGRADE_BLOCKED", {"reason": str(e), "attempt": attempt})
                raise

            except (ConnectionClosedError, ProtocolTimeoutError, OSError) as e:
                logger.warning(f"Connection failure on attempt {attempt}: {e}")
                self._emit("NETWORK_FAILURE_DETECTED", {"reason": str(e), "next_action": "Retrying with Strict Policy"})
                if attempt >= self.max_retries:
                    raise RuntimeError(f"Transfer failed after {self.max_retries} attempts: {e}") from e
                await asyncio.sleep(self.retry_delay_sec)

            finally:
                if writer:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        raise RuntimeError(f"Transfer incomplete after {attempt} attempts")
