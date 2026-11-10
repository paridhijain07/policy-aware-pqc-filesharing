"""
Baseline (Vulnerable) Client Implementation.
Simulates standard legacy application behavior:
When hybrid post-quantum handshake fails or times out, silently falls back to classical ECDH.
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
)
from protocol.transcript import HandshakeTranscript
from policy.modes import SecurityMode, PolicyLevel
from policy.engine import PolicyEngine
from crypto.classical_x25519 import X25519KeyExchange
from crypto.pqc_mlkem import MLKEM768KeyExchange
from crypto.hybrid_combiner import HybridKeyDerivation
from crypto.aead_cipher import ChunkedAEADCipher
from .transport import AsyncTransport, ConnectionClosedError, ProtocolTimeoutError
from .file_manager import FileManager

logger = logging.getLogger("BaselineClient")


class BaselineClient:
    """
    Vulnerable Baseline Client.
    Prioritizes connection completion over cryptographic invariants.
    Silently downgrades to Classical X25519 if Hybrid post-quantum fails.
    """

    def __init__(
        self,
        server_host: str = "127.0.0.1",
        server_port: int = 8765,
        max_retries: int = 3,
        retry_delay_sec: float = 1.0,
        event_callback: Optional[Callable[[str, Dict], None]] = None
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.max_retries = max_retries
        self.retry_delay_sec = retry_delay_sec
        self.event_callback = event_callback
        self.policy_engine = PolicyEngine(PolicyLevel.ALLOW_FALLBACK)
        self.unauthorized_downgrade_occurred = False

    def _emit(self, event_type: str, data: Dict):
        if self.event_callback:
            try:
                self.event_callback(event_type, data)
            except Exception as e:
                logger.error(f"Baseline client event error: {e}")

    async def transfer_file(self, file_path: str, job_id: Optional[str] = None) -> Dict:
        """Attempts transfer using Hybrid; falls back to Classical if an error occurs."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        job_id = job_id or f"base-{os.urandom(8).hex()}"
        file_size, total_chunks, sha256_hash = FileManager.get_file_info(file_path)
        file_name = os.path.basename(file_path)

        current_mode = SecurityMode.HYBRID_X25519_MLKEM768

        for attempt in range(1, self.max_retries + 1):
            writer = None
            try:
                self._emit("BASELINE_ATTEMPT", {
                    "attempt": attempt,
                    "mode_attempted": current_mode.value,
                    "is_downgraded": (current_mode == SecurityMode.CLASSICAL_X25519)
                })

                reader, writer = await asyncio.open_connection(self.server_host, self.server_port)

                client_nonce = os.urandom(32)
                session_id = os.urandom(16)
                priv_x25519, pub_x25519 = X25519KeyExchange.generate_keypair()

                offered = [current_mode.value]
                # Also offer classical if already downgraded
                if current_mode == SecurityMode.CLASSICAL_X25519:
                    offered = [SecurityMode.CLASSICAL_X25519.value]

                client_hello = ClientHello(
                    client_nonce=client_nonce,
                    session_id=session_id,
                    transfer_job_id=job_id,
                    offered_modes=offered,
                    client_policy=PolicyLevel.ALLOW_FALLBACK.value,
                    client_x25519_pk=pub_x25519,
                )

                transcript = HandshakeTranscript()
                c_dict = client_hello.to_dict()
                await AsyncTransport.send_message(writer, c_dict)
                transcript.update(c_dict)

                s_dict = await AsyncTransport.receive_message(reader, timeout=4.0)
                if s_dict.get("type") != MessageType.SERVER_HELLO.value:
                    raise RuntimeError("Failed to receive valid SERVER_HELLO")

                server_hello = ServerHello.from_dict(s_dict)
                transcript.update(s_dict)

                negotiated_mode = SecurityMode(server_hello.selected_mode)
                self.policy_engine.evaluate_negotiation(negotiated_mode)

                # Key Exchange
                ss_classical = X25519KeyExchange.compute_shared_secret(priv_x25519, server_hello.server_x25519_pk)
                ss_pqc = None
                mlkem_ct = None

                if negotiated_mode == SecurityMode.HYBRID_X25519_MLKEM768:
                    kem = MLKEM768KeyExchange()
                    ss_pqc, mlkem_ct = kem.encapsulate(server_hello.server_mlkem_pk)

                salt = client_nonce + server_hello.server_nonce
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

                fin_tag = HybridKeyDerivation.compute_finished_tag(session_keys.mac_key, "CLIENT", transcript_hash)
                client_kex = ClientKex(
                    session_id=session_id,
                    mlkem_ciphertext=mlkem_ct,
                    client_finished_mac=fin_tag
                )
                await AsyncTransport.send_message(writer, client_kex.to_dict())

                fin_dict = await AsyncTransport.receive_message(reader, timeout=4.0)
                if fin_dict.get("type") != MessageType.SERVER_FINISHED.value:
                    raise RuntimeError("Handshake failed at finished step")

                # Transmit file
                cipher = ChunkedAEADCipher(session_keys.enc_key, session_keys.iv_salt, session_keys.session_id)
                file_id = os.urandom(16)
                meta = FileMetadata(session_id, file_id, file_name, file_size, total_chunks, sha256_hash)
                await AsyncTransport.send_message(writer, meta.to_dict())

                for index, chunk_data, is_final in FileManager.read_chunks(file_path):
                    nonce, ct = cipher.encrypt_chunk(file_id, index, total_chunks, chunk_data, is_final)
                    chunk_msg = FileChunk(session_id, file_id, index, total_chunks, is_final, nonce, ct)
                    await AsyncTransport.send_message(writer, chunk_msg.to_dict())

                ack = await AsyncTransport.receive_message(reader, timeout=10.0)
                if ack.get("status") == "COMPLETED_VERIFIED":
                    if self.unauthorized_downgrade_occurred:
                        self._emit("BASELINE_VULNERABILITY_CONFIRMED", {
                            "warning": "Transfer succeeded under classical-only encryption after silent downgrade!",
                            "negotiated_mode": negotiated_mode.value
                        })
                    return {
                        "status": "SUCCESS",
                        "job_id": job_id,
                        "mode": negotiated_mode.value,
                        "unauthorized_downgrade_occurred": self.unauthorized_downgrade_occurred,
                    }

            except Exception as e:
                logger.warning(f"Baseline attempt {attempt} failed with error: {e}")
                # VULNERABILITY ANTI-PATTERN: On failure, downgrade from Hybrid to Classical
                if current_mode == SecurityMode.HYBRID_X25519_MLKEM768:
                    self.unauthorized_downgrade_occurred = True
                    current_mode = SecurityMode.CLASSICAL_X25519
                    self._emit("BASELINE_SILENT_DOWNGRADE", {
                        "reason": f"Hybrid handshake failed ({e}); falling back to Classical X25519 to make retry succeed.",
                        "new_mode": current_mode.value
                    })
                await asyncio.sleep(self.retry_delay_sec)
            finally:
                if writer:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        raise RuntimeError("Baseline transfer failed after all attempts")
