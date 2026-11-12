"""
Asynchronous Man-In-The-Middle Network Fault and Attack Proxy.
Intercepts, inspects, tampers with, or drops messages between Client and Server.
"""

import asyncio
import logging
from typing import Dict, Optional, Callable
from protocol.messages import MessageType, ProtocolSerializer, b64e, b64d
from core.transport import AsyncTransport, ConnectionClosedError, ProtocolTimeoutError
from .attack_rules import AttackType, AttackConfig

logger = logging.getLogger("AttackProxy")


class NetworkAttackProxy:
    """Configurable TCP Proxy for injecting post-quantum downgrade and network fault attacks."""

    def __init__(
        self,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 9090,
        target_host: str = "127.0.0.1",
        target_port: int = 8765,
        attack_config: Optional[AttackConfig] = None,
        event_callback: Optional[Callable[[str, Dict], None]] = None
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.target_host = target_host
        self.target_port = target_port
        self.config = attack_config or AttackConfig()
        self.event_callback = event_callback
        self._server = None
        self.captured_kex: Optional[Dict] = None
        self.attack_injected_count = 0
        self.connection_count = 0

    def _emit(self, event_type: str, data: Dict):
        if self.event_callback:
            try:
                self.event_callback(event_type, data)
            except Exception as e:
                logger.error(f"Proxy event callback error: {e}")

    def set_attack(self, attack_type: AttackType, **kwargs):
        """Dynamically updates active attack parameters."""
        self.config = AttackConfig(attack_type=attack_type, **kwargs)
        self._emit("ATTACK_CONFIG_CHANGED", {"attack_type": attack_type.value, "params": kwargs})

    async def start(self):
        """Starts the proxy server."""
        self._server = await asyncio.start_server(self._handle_client, self.proxy_host, self.proxy_port)
        logger.info(f"Attack Simulator Proxy listening on {self.proxy_host}:{self.proxy_port} -> {self.target_host}:{self.target_port}")
        self._emit("PROXY_STARTED", {"port": self.proxy_port, "target_port": self.target_port})

    async def stop(self):
        """Stops the proxy."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._emit("PROXY_STOPPED", {})

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        self.connection_count += 1
        conn_id = self.connection_count

        server_writer = None
        try:
            server_reader, server_writer = await asyncio.open_connection(self.target_host, self.target_port)

            # Bidirectional forwarding with fault injection hooks
            task_c2s = asyncio.create_task(self._forward_c2s(client_reader, server_writer, client_writer, conn_id))
            task_s2c = asyncio.create_task(self._forward_s2c(server_reader, client_writer, conn_id))

            done, pending = await asyncio.wait([task_c2s, task_s2c], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()

        except Exception as e:
            logger.debug(f"Proxy connection #{conn_id} ended: {e}")
        finally:
            client_writer.close()
            if server_writer:
                server_writer.close()

    async def _forward_c2s(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
        conn_id: int
    ):
        """Client to Server stream handler."""
        chunks_seen = 0

        try:
            while True:
                msg = await AsyncTransport.receive_message(reader, timeout=30.0)
                msg_type = msg.get("type")

                # --- ATTACK 1: Strip ML-KEM Negotiation (Tamper ClientHello) ---
                if self.config.active and self.config.attack_type == AttackType.STRIP_NEGOTIATION:
                    if msg_type == MessageType.CLIENT_HELLO.value:
                        self.attack_injected_count += 1
                        logger.warning("[ATTACK] Tampering CLIENT_HELLO: Stripping Hybrid/ML-KEM suites to force Classical!")
                        # Replace offered modes with Classical only
                        msg["offered_modes"] = ["CLASSICAL_X25519"]
                        self._emit("ATTACK_INJECTED", {
                            "attack": AttackType.STRIP_NEGOTIATION.value,
                            "details": "Stripped HYBRID from ClientHello offered modes"
                        })

                # --- ATTACK 2: Drop ML-KEM Packet (ClientKex with ciphertext) ---
                elif self.config.active and self.config.attack_type == AttackType.DROP_MLKEM_PACKET:
                    if msg_type == MessageType.CLIENT_KEX.value:
                        if self.config.drop_on_attempt is None or self.connection_count == self.config.drop_on_attempt:
                            self.attack_injected_count += 1
                            logger.warning("[ATTACK] Dropping CLIENT_KEX packet to induce timeout/failure!")
                            self._emit("ATTACK_INJECTED", {
                                "attack": AttackType.DROP_MLKEM_PACKET.value,
                                "details": "Dropped ClientKex packet containing ML-KEM ciphertext"
                            })
                            client_writer.close()
                            return

                # --- ATTACK 3: Sever Connection Midway ---
                elif self.config.active and self.config.attack_type == AttackType.SEVER_MIDWAY:
                    if msg_type == MessageType.FILE_CHUNK.value:
                        chunks_seen += 1
                        if chunks_seen >= self.config.sever_at_chunk_index:
                            self.attack_injected_count += 1
                            logger.warning(f"[ATTACK] Severing connection abruptly after chunk {chunks_seen}!")
                            self._emit("ATTACK_INJECTED", {
                                "attack": AttackType.SEVER_MIDWAY.value,
                                "details": f"Connection severed abruptly after forwarding chunk #{chunks_seen}"
                            })
                            # Disarm attack so subsequent retry can succeed
                            self.config.active = False
                            client_writer.close()
                            return

                # --- ATTACK 4: Corrupt Chunk Ciphertext ---
                elif self.config.active and self.config.attack_type == AttackType.CORRUPT_CIPHERTEXT:
                    if msg_type == MessageType.FILE_CHUNK.value and msg.get("chunk_index") == self.config.corrupt_chunk_index:
                        self.attack_injected_count += 1
                        logger.warning(f"[ATTACK] Tampering ciphertext of chunk {self.config.corrupt_chunk_index}!")
                        raw_ct = b64d(msg["ciphertext"])
                        corrupted = bytearray(raw_ct)
                        corrupted[8] ^= 0xAA  # Flip bits
                        msg["ciphertext"] = b64e(bytes(corrupted))
                        self._emit("ATTACK_INJECTED", {
                            "attack": AttackType.CORRUPT_CIPHERTEXT.value,
                            "details": f"Flipped bits in chunk #{self.config.corrupt_chunk_index} ciphertext"
                        })
                        # Disarm so only one chunk is corrupted
                        self.config.active = False

                # --- ATTACK 5: Replay Old Handshake ---
                elif self.config.active and self.config.attack_type == AttackType.REPLAY_HANDSHAKE:
                    if msg_type == MessageType.CLIENT_KEX.value:
                        if self.captured_kex is not None:
                            self.attack_injected_count += 1
                            logger.warning("[ATTACK] Injecting captured ClientKex from previous session!")
                            msg = dict(self.captured_kex)
                            self._emit("ATTACK_INJECTED", {
                                "attack": AttackType.REPLAY_HANDSHAKE.value,
                                "details": "Replaced ClientKex with captured stale packet"
                            })
                            self.config.active = False
                        else:
                            self.captured_kex = dict(msg)

                # --- ATTACK 6: Inject Latency ---
                elif self.config.active and self.config.attack_type == AttackType.INJECT_LATENCY:
                    self.attack_injected_count += 1
                    logger.warning(f"[ATTACK] Injecting {self.config.latency_delay_sec}s delay into stream!")
                    self._emit("ATTACK_INJECTED", {
                        "attack": AttackType.INJECT_LATENCY.value,
                        "details": f"Injected {self.config.latency_delay_sec}s latency delay"
                    })
                    await asyncio.sleep(self.config.latency_delay_sec)
                    self.config.active = False

                # --- ATTACK 7: Downgrade on Retry (Drop attempt 1, strip on attempt 2) ---
                elif self.config.active and self.config.attack_type == AttackType.DOWNGRADE_ON_RETRY:
                    if self.connection_count == 1:
                        if msg_type == MessageType.CLIENT_KEX.value:
                            self.attack_injected_count += 1
                            logger.warning("[ATTACK] Inducing failure on attempt 1 for DOWNGRADE_ON_RETRY!")
                            self._emit("ATTACK_INJECTED", {
                                "attack": AttackType.DOWNGRADE_ON_RETRY.value,
                                "details": "Dropped ClientKex on attempt 1 to trigger retry"
                            })
                            client_writer.close()
                            return
                    elif self.connection_count >= 2:
                        if msg_type == MessageType.CLIENT_HELLO.value:
                            self.attack_injected_count += 1
                            logger.warning("[ATTACK] Tampering CLIENT_HELLO on retry to force Classical!")
                            msg["offered_modes"] = ["CLASSICAL_X25519"]
                            self._emit("ATTACK_INJECTED", {
                                "attack": AttackType.DOWNGRADE_ON_RETRY.value,
                                "details": "Stripped post-quantum modes from retry ClientHello"
                            })
                            self.config.active = False

                await AsyncTransport.send_message(writer, msg)
        except (ConnectionClosedError, ProtocolTimeoutError, asyncio.CancelledError):
            pass

    async def _forward_s2c(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, conn_id: int):
        """Server to Client stream handler."""
        try:
            while True:
                msg = await AsyncTransport.receive_message(reader, timeout=30.0)
                msg_type = msg.get("type")

                # Drop ML-KEM in ServerHello if configured
                if self.config.active and self.config.attack_type == AttackType.DROP_MLKEM_PACKET:
                    if msg_type == MessageType.SERVER_HELLO.value:
                        if self.config.drop_on_attempt is None or self.connection_count == self.config.drop_on_attempt:
                            self.attack_injected_count += 1
                            logger.warning("[ATTACK] Dropping SERVER_HELLO with ML-KEM public key!")
                            self._emit("ATTACK_INJECTED", {
                                "attack": AttackType.DROP_MLKEM_PACKET.value,
                                "details": "Dropped ServerHello containing ML-KEM public key"
                            })
                            writer.close()
                            return

                # --- ATTACK 8: Downgrade ServerHello (Tamper selected_mode to Classical) ---
                elif self.config.active and self.config.attack_type == AttackType.DOWNGRADE_SERVER_HELLO:
                    if msg_type == MessageType.SERVER_HELLO.value:
                        self.attack_injected_count += 1
                        logger.warning("[ATTACK] Tampering SERVER_HELLO: Overwriting selected_mode to CLASSICAL_X25519!")
                        msg["selected_mode"] = "CLASSICAL_X25519"
                        msg["server_mlkem_pk"] = None
                        self._emit("ATTACK_INJECTED", {
                            "attack": AttackType.DOWNGRADE_SERVER_HELLO.value,
                            "details": "Tampered ServerHello to force Classical mode"
                        })
                        self.config.active = False

                # --- ATTACK 9: Interrupt After ClientHello (drop ServerHello before client receives it) ---
                elif self.config.active and self.config.attack_type == AttackType.INTERRUPT_AFTER_CLIENT_HELLO:
                    if msg_type == MessageType.SERVER_HELLO.value:
                        self.attack_injected_count += 1
                        logger.warning("[ATTACK] Severing connection: dropping SERVER_HELLO to interrupt after ClientHello!")
                        self._emit("ATTACK_INJECTED", {
                            "attack": AttackType.INTERRUPT_AFTER_CLIENT_HELLO.value,
                            "details": "Dropped ServerHello to simulate interruption between ClientHello and ServerHello"
                        })
                        self.config.active = False
                        writer.close()
                        return

                await AsyncTransport.send_message(writer, msg)
        except (ConnectionClosedError, ProtocolTimeoutError, asyncio.CancelledError):
            pass

