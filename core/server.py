"""
Secure File-Sharing Server Implementation.
Implements the policy-enforcing post-quantum handshake state machine, chunked AEAD decryption,
and resilient resume handling.
"""

import os
import time
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
    DownloadRequest,
    DownloadResponse,
)
from protocol.transcript import HandshakeTranscript
from policy.modes import SecurityMode
from crypto.classical_x25519 import X25519KeyExchange
from crypto.pqc_mlkem import MLKEM768KeyExchange
from crypto.hybrid_combiner import HybridKeyDerivation, SessionKeys
from crypto.aead_cipher import ChunkedAEADCipher, CryptographicIntegrityError
from .transport import AsyncTransport, ConnectionClosedError, ProtocolTimeoutError
from .file_manager import FileManager

logger = logging.getLogger("Server")


class FileSharingServer:
    """AsyncIO Secure File Sharing Server supporting Classical, PQC, and Hybrid handshakes."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        storage_dir: str = "storage/server",
        session_ttl_sec: float = 300.0,
        event_callback: Optional[Callable[[str, Dict], None]] = None
    ):
        self.host = host
        self.port = port
        self.storage_dir = storage_dir
        self.session_ttl_sec = session_ttl_sec
        self.event_callback = event_callback
        self._server = None
        self._active_sessions: Dict[bytes, Dict] = {}
        self.received_chunks_tracker: Dict[str, int] = {}  # transfer_job_id -> count of chunks received
        os.makedirs(self.storage_dir, exist_ok=True)

    def _emit(self, event_type: str, data: Dict):
        if self.event_callback:
            try:
                self.event_callback(event_type, data)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    async def start(self):
        """Starts the server."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logger.info(f"File Sharing Server listening on {self.host}:{self.port}")
        self._emit("SERVER_STARTED", {"host": self.host, "port": self.port})

    async def stop(self):
        """Stops the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("File Sharing Server stopped.")
            self._emit("SERVER_STOPPED", {})

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info("peername")
        logger.info(f"Incoming connection from {client_addr}")

        transcript = HandshakeTranscript()
        session_keys: Optional[SessionKeys] = None
        cipher: Optional[ChunkedAEADCipher] = None

        try:
            # 1. Receive ClientHello
            msg_dict = await AsyncTransport.receive_message(reader)
            if msg_dict.get("type") != MessageType.CLIENT_HELLO.value:
                raise ValueError("Expected CLIENT_HELLO message")

            client_hello = ClientHello.from_dict(msg_dict)

            # Replay and Stale Session Detection
            if client_hello.session_id in self._active_sessions:
                s_info = self._active_sessions[client_hello.session_id]
                if time.time() - s_info.get("created_at", 0) > self.session_ttl_sec:
                    logger.warning(f"Handshake references expired session_id {client_hello.session_id.hex()}")
                    err = ErrorMessage(code="SESSION_EXPIRED", description="Handshake references an expired session", is_fatal=True)
                else:
                    logger.warning(f"Replay detected: duplicate session_id {client_hello.session_id.hex()}")
                    err = ErrorMessage(code="SESSION_REPLAY_DETECTED", description="Replay of existing session_id detected", is_fatal=True)
                await AsyncTransport.send_message(writer, err.to_dict())
                self._emit("REPLAY_DETECTED", {"session_id": client_hello.session_id.hex(), "code": err.code})
                return

            transcript.update(msg_dict)
            self._emit("CLIENT_HELLO_RECEIVED", {
                "transfer_job_id": client_hello.transfer_job_id,
                "offered_modes": client_hello.offered_modes,
                "client_policy": client_hello.client_policy,
            })

            # 2. Negotiate Mode
            selected_mode = None
            if SecurityMode.HYBRID_X25519_MLKEM768.value in client_hello.offered_modes:
                selected_mode = SecurityMode.HYBRID_X25519_MLKEM768
            elif SecurityMode.PQC_MLKEM768.value in client_hello.offered_modes:
                selected_mode = SecurityMode.PQC_MLKEM768
            elif SecurityMode.CLASSICAL_X25519.value in client_hello.offered_modes:
                selected_mode = SecurityMode.CLASSICAL_X25519
            else:
                err = ErrorMessage(code="NO_SUPPORTED_MODE", description="No mutually agreeable security mode", is_fatal=True)
                await AsyncTransport.send_message(writer, err.to_dict())
                return

            # 3. Generate Ephemeral Server Keys
            server_nonce = os.urandom(32)
            priv_x25519, pub_x25519 = X25519KeyExchange.generate_keypair()

            server_mlkem_pk = None
            dk_mlkem = None
            if selected_mode in (SecurityMode.HYBRID_X25519_MLKEM768, SecurityMode.PQC_MLKEM768):
                kem = MLKEM768KeyExchange()
                dk_mlkem, ek_mlkem = kem.generate_keypair()
                server_mlkem_pk = ek_mlkem

            # 4. Send ServerHello
            server_hello = ServerHello(
                server_nonce=server_nonce,
                session_id=client_hello.session_id,
                selected_mode=selected_mode.value,
                server_x25519_pk=pub_x25519 if selected_mode != SecurityMode.PQC_MLKEM768 else None,
                server_mlkem_pk=server_mlkem_pk,
            )
            s_hello_dict = server_hello.to_dict()
            await AsyncTransport.send_message(writer, s_hello_dict)
            transcript.update(s_hello_dict)
            self._emit("SERVER_HELLO_SENT", {"selected_mode": selected_mode.value})

            # 5. Receive ClientKex
            kex_dict = await AsyncTransport.receive_message(reader)
            if kex_dict.get("type") != MessageType.CLIENT_KEX.value:
                raise ValueError("Expected CLIENT_KEX message")

            client_kex = ClientKex.from_dict(kex_dict)

            # Record message before Finished verification
            kex_dict_for_transcript = dict(kex_dict)
            kex_dict_for_transcript.pop("client_finished_mac", None)
            transcript.update(kex_dict_for_transcript)

            # Compute shared secrets
            ss_classical = None
            if selected_mode in (SecurityMode.HYBRID_X25519_MLKEM768, SecurityMode.CLASSICAL_X25519):
                ss_classical = X25519KeyExchange.compute_shared_secret(priv_x25519, client_hello.client_x25519_pk)

            ss_pqc = None
            if selected_mode in (SecurityMode.HYBRID_X25519_MLKEM768, SecurityMode.PQC_MLKEM768):
                if not client_kex.mlkem_ciphertext or not dk_mlkem:
                    raise ValueError("Missing ML-KEM ciphertext or decapsulation key")
                kem = MLKEM768KeyExchange()
                ss_pqc = kem.decapsulate(dk_mlkem, client_kex.mlkem_ciphertext)

            # 6. Derive Session Keys & Verify Finished Tag
            salt = client_hello.client_nonce + server_nonce
            transcript_hash = transcript.current_digest()

            session_keys = HybridKeyDerivation.derive_keys(
                mode=selected_mode.value,
                session_id=client_hello.session_id,
                salt=salt,
                transcript_hash=transcript_hash,
                ss_classical=ss_classical,
                ss_pqc=ss_pqc
            )

            # Constant-time verification of Client Finished tag
            is_valid = HybridKeyDerivation.verify_finished_tag(
                session_keys.mac_key, "CLIENT", transcript_hash, client_kex.client_finished_mac
            )
            if not is_valid:
                logger.error("CLIENT FINISHED MAC VERIFICATION FAILED! Handshake tampering detected.")
                err = ErrorMessage(code="HANDSHAKE_INTEGRITY_FAIL", description="Finished MAC verification failure", is_fatal=True)
                await AsyncTransport.send_message(writer, err.to_dict())
                self._emit("HANDSHAKE_FAILED", {"reason": "Transcript MAC verification failed (tampered handshake)"})
                return

            # 7. Send ServerFinished
            server_fin_tag = HybridKeyDerivation.compute_finished_tag(session_keys.mac_key, "SERVER", transcript_hash)
            server_finished = ServerFinished(
                session_id=client_hello.session_id,
                server_finished_mac=server_fin_tag,
                status="HANDSHAKE_COMPLETE"
            )
            await AsyncTransport.send_message(writer, server_finished.to_dict())
            self._emit("HANDSHAKE_SUCCESS", {
                "session_id": client_hello.session_id.hex(),
                "mode": selected_mode.value,
            })
            self._active_sessions[client_hello.session_id] = {
                "transfer_job_id": client_hello.transfer_job_id,
                "mode": selected_mode.value,
                "created_at": time.time(),
                "status": "ESTABLISHED",
                "client_addr": client_addr
            }

            # 8. Initialize AEAD Cipher for data transmission
            cipher = ChunkedAEADCipher(
                enc_key=session_keys.enc_key,
                iv_salt=session_keys.iv_salt,
                session_id=session_keys.session_id
            )

            # 9. Handle File Transfer or Resumption Loop
            await self._process_data_stream(reader, writer, cipher, client_hello.transfer_job_id, client_hello.session_id)

        except (ConnectionClosedError, ProtocolTimeoutError) as e:
            logger.warning(f"Connection ended prematurely: {e}")
            self._emit("CONNECTION_DROPPED", {"reason": str(e)})
        except CryptographicIntegrityError as e:
            logger.error(f"Cryptographic integrity error: {e}")
            self._emit("INTEGRITY_ALERT", {"reason": str(e)})
        except Exception as e:
            logger.error(f"Server session error: {e}", exc_info=True)
            self._emit("SESSION_ERROR", {"reason": str(e)})
        finally:
            writer.close()
            await writer.wait_closed()

    async def _process_data_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        cipher: ChunkedAEADCipher,
        transfer_job_id: str,
        session_id: bytes
    ):
        file_meta: Optional[FileMetadata] = None

        while True:
            msg_dict = await AsyncTransport.receive_message(reader, timeout=15.0)
            msg_type = msg_dict.get("type")

            if msg_type == MessageType.DOWNLOAD_REQUEST.value:
                req = DownloadRequest.from_dict(msg_dict)
                file_path = os.path.join(self.storage_dir, req.file_name)
                if not os.path.exists(file_path):
                    err = ErrorMessage(
                        code="FILE_NOT_FOUND",
                        description=f"Requested file '{req.file_name}' not found",
                        is_fatal=True
                    )
                    await AsyncTransport.send_message(writer, err.to_dict())
                    return

                f_size, t_chunks, f_hash = FileManager.get_file_info(file_path)
                file_id = os.urandom(16)
                resp = DownloadResponse(
                    session_id=session_id,
                    file_id=file_id,
                    file_name=req.file_name,
                    file_size=f_size,
                    total_chunks=t_chunks,
                    sha256_hash=f_hash,
                    status="READY"
                )
                await AsyncTransport.send_message(writer, resp.to_dict())

                for index, chunk_data, is_final in FileManager.read_chunks(file_path):
                    nonce, ct = cipher.encrypt_chunk(
                        file_id=file_id,
                        chunk_index=index,
                        total_chunks=t_chunks,
                        plaintext=chunk_data,
                        is_final=is_final
                    )
                    chunk_msg = FileChunk(
                        session_id=session_id,
                        file_id=file_id,
                        chunk_index=index,
                        total_chunks=t_chunks,
                        is_final=is_final,
                        nonce=nonce,
                        ciphertext=ct
                    )
                    await AsyncTransport.send_message(writer, chunk_msg.to_dict())

                ack = await AsyncTransport.receive_message(reader, timeout=10.0)
                if ack.get("status") == "COMPLETED_VERIFIED":
                    self._emit("DOWNLOAD_COMPLETE", {
                        "file_name": req.file_name,
                        "verified_sha256": f_hash
                    })
                break

            elif msg_type == MessageType.RESUME_REQUEST.value:
                req = ResumeRequest.from_dict(msg_dict)
                last_received = self.received_chunks_tracker.get(req.transfer_job_id, 0)
                ack = {
                    "type": MessageType.RESUME_RESPONSE.value,
                    "session_id": msg_dict["session_id"],
                    "file_id": msg_dict["file_id"],
                    "resume_chunk_offset": last_received,
                }
                await AsyncTransport.send_message(writer, ack)
                self._emit("RESUME_ACK_SENT", {"transfer_job_id": req.transfer_job_id, "resume_offset": last_received})

            elif msg_type == MessageType.FILE_METADATA.value:
                file_meta = FileMetadata.from_dict(msg_dict)
                self._emit("FILE_METADATA_RECEIVED", {
                    "file_name": file_meta.file_name,
                    "file_size": file_meta.file_size,
                    "total_chunks": file_meta.total_chunks,
                    "expected_sha256": file_meta.sha256_hash,
                })

            elif msg_type == MessageType.FILE_CHUNK.value:
                if not file_meta:
                    raise ValueError("Received chunk before file metadata")

                chunk = FileChunk.from_dict(msg_dict)
                # Decrypt chunk with AEAD
                decrypted_bytes = cipher.decrypt_chunk(
                    file_id=chunk.file_id,
                    chunk_index=chunk.chunk_index,
                    total_chunks=chunk.total_chunks,
                    ciphertext=chunk.ciphertext,
                    is_final=chunk.is_final
                )

                # Write to disk
                FileManager.write_partial_chunk(
                    storage_dir=self.storage_dir,
                    file_name=file_meta.file_name,
                    chunk_index=chunk.chunk_index,
                    chunk_data=decrypted_bytes
                )

                # Update progress tracker
                self.received_chunks_tracker[transfer_job_id] = chunk.chunk_index + 1
                self._emit("CHUNK_RECEIVED", {
                    "chunk_index": chunk.chunk_index,
                    "total_chunks": chunk.total_chunks,
                    "progress_pct": round(((chunk.chunk_index + 1) / chunk.total_chunks) * 100, 1),
                })

                if chunk.is_final:
                    final_path = FileManager.finalize_file(
                        storage_dir=self.storage_dir,
                        file_name=file_meta.file_name,
                        expected_sha256=file_meta.sha256_hash
                    )
                    ack = {
                        "type": MessageType.TRANSFER_ACK.value,
                        "session_id": msg_dict["session_id"],
                        "file_id": msg_dict["file_id"],
                        "status": "COMPLETED_VERIFIED",
                        "final_path": final_path,
                    }
                    await AsyncTransport.send_message(writer, ack)
                    self._emit("TRANSFER_COMPLETE", {
                        "file_name": file_meta.file_name,
                        "verified_sha256": file_meta.sha256_hash,
                    })
                    break

