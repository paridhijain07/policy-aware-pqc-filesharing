"""
Asynchronous Network Transport Framing.
Encapsulates 4-byte length prefix framing over asyncio streams with timeout controls.
"""

import asyncio
import struct
from typing import Dict, Any, Optional
from protocol.messages import ProtocolSerializer


class TransportError(Exception):
    """Base transport error."""
    pass


class ConnectionClosedError(TransportError):
    """Raised when peer unexpectedly closes connection."""
    pass


class ProtocolTimeoutError(TransportError):
    """Raised when reading from socket exceeds the configured timeout."""
    pass


class AsyncTransport:
    """Async framing reader and writer."""

    @staticmethod
    async def send_message(writer: asyncio.StreamWriter, message: Dict[str, Any]) -> None:
        """Packs and transmits framed message."""
        try:
            wire_bytes = ProtocolSerializer.pack(message)
            writer.write(wire_bytes)
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            raise ConnectionClosedError("Failed to write to stream: connection closed") from e

    @staticmethod
    async def receive_message(reader: asyncio.StreamReader, timeout: float = 10.0) -> Dict[str, Any]:
        """Reads framed message with strict timeout."""
        try:
            header_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
            length = struct.unpack(">I", header_bytes)[0]
            payload_bytes = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
            return ProtocolSerializer.unpack_payload(payload_bytes)
        except asyncio.TimeoutError as e:
            raise ProtocolTimeoutError(f"Socket read timed out after {timeout:.1f}s") from e
        except asyncio.IncompleteReadError as e:
            raise ConnectionClosedError("Peer closed stream prematurely") from e
        except (ConnectionResetError, BrokenPipeError) as e:
            raise ConnectionClosedError("Connection reset by peer") from e

