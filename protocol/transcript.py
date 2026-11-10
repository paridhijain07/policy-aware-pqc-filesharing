"""
Rolling Handshake Transcript Hashing.
Cryptographically binds all handshake messages to the session keys and Finished authenticators.
"""

import hashlib
import json
from typing import Dict, Any


class HandshakeTranscript:
    """Accumulates canonical handshake messages and produces rolling SHA-256 digests."""

    def __init__(self):
        self._sha256 = hashlib.sha256()
        self._history = []

    def update(self, message_dict: Dict[str, Any]) -> None:
        """
        Updates the transcript with a canonical JSON representation of a handshake message.
        Sorts keys to ensure deterministic byte representation across client and server.
        """
        canonical_bytes = json.dumps(message_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._sha256.update(canonical_bytes)
        self._history.append(message_dict)

    def current_digest(self) -> bytes:
        """Returns the current 32-byte SHA-256 digest of the handshake transcript."""
        return self._sha256.copy().digest()

    def clone(self) -> "HandshakeTranscript":
        """Creates a clone of the transcript at the current point in time."""
        cloned = HandshakeTranscript()
        cloned._sha256 = self._sha256.copy()
        cloned._history = list(self._history)
        return cloned

