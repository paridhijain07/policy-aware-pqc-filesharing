"""
Attack and Network Failure Simulation Rule Definitions.
Defines fault models and adversary capabilities for security testing.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


class AttackType(str, Enum):
    NONE = "NONE"                                   # Normal pass-through
    DROP_MLKEM_PACKET = "DROP_MLKEM_PACKET"         # Drops ML-KEM packet to induce timeout
    STRIP_NEGOTIATION = "STRIP_NEGOTIATION"         # MiTM alters offered modes to Classical only
    SEVER_MIDWAY = "SEVER_MIDWAY"                   # Closes TCP stream mid-transfer
    CORRUPT_CIPHERTEXT = "CORRUPT_CIPHERTEXT"       # Bit-flips encrypted chunk
    REPLAY_HANDSHAKE = "REPLAY_HANDSHAKE"           # Injects captured previous session keys
    INJECT_LATENCY = "INJECT_LATENCY"               # Injects delay exceeding socket timeout


@dataclass
class AttackConfig:
    """Configures active attack and fault injection behavior."""
    attack_type: AttackType = AttackType.NONE
    sever_at_chunk_index: int = 1                  # Sever after transferring this chunk
    latency_delay_sec: float = 6.0                 # Seconds to delay packet
    corrupt_chunk_index: int = 0                   # Index of chunk to corrupt
    drop_on_attempt: Optional[int] = None          # If set, drop only on this attempt number
    active: bool = True

