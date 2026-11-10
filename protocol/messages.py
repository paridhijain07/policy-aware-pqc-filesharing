"""
Protocol Message Formats, Enums, and Framing.
Uses JSON payloads with base64 encoded binary fields, framed with a 4-byte length prefix.
"""

import json
import base64
import struct
from enum import Enum
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any


class MessageType(str, Enum):
    CLIENT_HELLO = "CLIENT_HELLO"
    SERVER_HELLO = "SERVER_HELLO"
    CLIENT_KEX = "CLIENT_KEX"
    SERVER_FINISHED = "SERVER_FINISHED"
    FILE_METADATA = "FILE_METADATA"
    FILE_CHUNK = "FILE_CHUNK"
    TRANSFER_ACK = "TRANSFER_ACK"
    RESUME_REQUEST = "RESUME_REQUEST"
    RESUME_RESPONSE = "RESUME_RESPONSE"
    ERROR = "ERROR"


def b64e(data: Optional[bytes]) -> Optional[str]:
    """Encodes bytes to base64 string."""
    return base64.b64encode(data).decode("ascii") if data is not None else None


def b64d(data: Optional[str]) -> Optional[bytes]:
    """Decodes base64 string to bytes."""
    return base64.b64decode(data.encode("ascii")) if data is not None else None


class ProtocolSerializer:
    """Handles wire framing and serialization with 4-byte big-endian length prefix."""

    @staticmethod
    def pack(msg_dict: Dict[str, Any]) -> bytes:
        """Serializes dictionary to length-prefixed JSON wire bytes."""
        payload = json.dumps(msg_dict, separators=(",", ":")).encode("utf-8")
        prefix = struct.pack(">I", len(payload))
        return prefix + payload

    @staticmethod
    def unpack_payload(raw_json_bytes: bytes) -> Dict[str, Any]:
        """Parses raw JSON wire payload."""
        return json.loads(raw_json_bytes.decode("utf-8"))


# --- Specific Protocol Messages ---

@dataclass
class ClientHello:
    client_nonce: bytes
    session_id: bytes
    transfer_job_id: str
    offered_modes: List[str]
    client_policy: str
    client_x25519_pk: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.CLIENT_HELLO.value,
            "client_nonce": b64e(self.client_nonce),
            "session_id": b64e(self.session_id),
            "transfer_job_id": self.transfer_job_id,
            "offered_modes": self.offered_modes,
            "client_policy": self.client_policy,
            "client_x25519_pk": b64e(self.client_x25519_pk),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ClientHello":
        return cls(
            client_nonce=b64d(d["client_nonce"]),
            session_id=b64d(d["session_id"]),
            transfer_job_id=d["transfer_job_id"],
            offered_modes=d["offered_modes"],
            client_policy=d["client_policy"],
            client_x25519_pk=b64d(d["client_x25519_pk"]),
        )


@dataclass
class ServerHello:
    server_nonce: bytes
    session_id: bytes
    selected_mode: str
    server_x25519_pk: Optional[bytes]
    server_mlkem_pk: Optional[bytes]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.SERVER_HELLO.value,
            "server_nonce": b64e(self.server_nonce),
            "session_id": b64e(self.session_id),
            "selected_mode": self.selected_mode,
            "server_x25519_pk": b64e(self.server_x25519_pk),
            "server_mlkem_pk": b64e(self.server_mlkem_pk),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServerHello":
        return cls(
            server_nonce=b64d(d["server_nonce"]),
            session_id=b64d(d["session_id"]),
            selected_mode=d["selected_mode"],
            server_x25519_pk=b64d(d.get("server_x25519_pk")),
            server_mlkem_pk=b64d(d.get("server_mlkem_pk")),
        )


@dataclass
class ClientKex:
    session_id: bytes
    mlkem_ciphertext: Optional[bytes]
    client_finished_mac: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.CLIENT_KEX.value,
            "session_id": b64e(self.session_id),
            "mlkem_ciphertext": b64e(self.mlkem_ciphertext),
            "client_finished_mac": b64e(self.client_finished_mac),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ClientKex":
        return cls(
            session_id=b64d(d["session_id"]),
            mlkem_ciphertext=b64d(d.get("mlkem_ciphertext")),
            client_finished_mac=b64d(d["client_finished_mac"]),
        )


@dataclass
class ServerFinished:
    session_id: bytes
    server_finished_mac: bytes
    status: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.SERVER_FINISHED.value,
            "session_id": b64e(self.session_id),
            "server_finished_mac": b64e(self.server_finished_mac),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServerFinished":
        return cls(
            session_id=b64d(d["session_id"]),
            server_finished_mac=b64d(d["server_finished_mac"]),
            status=d["status"],
        )


@dataclass
class FileMetadata:
    session_id: bytes
    file_id: bytes
    file_name: str
    file_size: int
    total_chunks: int
    sha256_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.FILE_METADATA.value,
            "session_id": b64e(self.session_id),
            "file_id": b64e(self.file_id),
            "file_name": self.file_name,
            "file_size": self.file_size,
            "total_chunks": self.total_chunks,
            "sha256_hash": self.sha256_hash,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FileMetadata":
        return cls(
            session_id=b64d(d["session_id"]),
            file_id=b64d(d["file_id"]),
            file_name=d["file_name"],
            file_size=d["file_size"],
            total_chunks=d["total_chunks"],
            sha256_hash=d["sha256_hash"],
        )


@dataclass
class FileChunk:
    session_id: bytes
    file_id: bytes
    chunk_index: int
    total_chunks: int
    is_final: bool
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.FILE_CHUNK.value,
            "session_id": b64e(self.session_id),
            "file_id": b64e(self.file_id),
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks,
            "is_final": self.is_final,
            "nonce": b64e(self.nonce),
            "ciphertext": b64e(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FileChunk":
        return cls(
            session_id=b64d(d["session_id"]),
            file_id=b64d(d["file_id"]),
            chunk_index=d["chunk_index"],
            total_chunks=d["total_chunks"],
            is_final=d["is_final"],
            nonce=b64d(d["nonce"]),
            ciphertext=b64d(d["ciphertext"]),
        )


@dataclass
class ResumeRequest:
    session_id: bytes
    file_id: bytes
    transfer_job_id: str
    last_received_chunk: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.RESUME_REQUEST.value,
            "session_id": b64e(self.session_id),
            "file_id": b64e(self.file_id),
            "transfer_job_id": self.transfer_job_id,
            "last_received_chunk": self.last_received_chunk,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ResumeRequest":
        return cls(
            session_id=b64d(d["session_id"]),
            file_id=b64d(d["file_id"]),
            transfer_job_id=d["transfer_job_id"],
            last_received_chunk=d["last_received_chunk"],
        )


@dataclass
class ErrorMessage:
    code: str
    description: str
    is_fatal: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MessageType.ERROR.value,
            "code": self.code,
            "description": self.description,
            "is_fatal": self.is_fatal,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ErrorMessage":
        return cls(
            code=d["code"],
            description=d["description"],
            is_fatal=d.get("is_fatal", True),
        )

