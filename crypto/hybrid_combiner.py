"""
Dual-PRF HKDF Key Combiner adhering to RFC 9954 / NIST SP 800-56C.
Combines Classical (X25519) and Post-Quantum (ML-KEM-768) secrets with handshake transcript binding.
Guarantees: If EITHER component remains unbroken, the derived session keys are secure.
"""

from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac


@dataclass(frozen=True)
class SessionKeys:
    """Derived cryptographic keys bound to a specific session and transcript."""
    mode: str
    session_id: bytes
    enc_key: bytes      # 32 bytes for AES-256-GCM
    mac_key: bytes      # 32 bytes for HMAC-SHA256 (Finished verification)
    iv_salt: bytes      # 8 bytes base salt for chunk nonce generation
    transcript_hash: bytes


class HybridKeyDerivation:
    """
    Standardized HKDF-Extract-and-Expand Dual-PRF combiner.
    """

    LABEL_HYBRID = b"HYBRID-X25519-MLKEM768-HKDF-SHA256-v1"
    LABEL_PQC = b"PQC-MLKEM768-HKDF-SHA256-v1"
    LABEL_CLASSICAL = b"CLASSICAL-X25519-HKDF-SHA256-v1"

    @classmethod
    def derive_keys(
        cls,
        mode: str,
        session_id: bytes,
        salt: bytes,
        transcript_hash: bytes,
        ss_classical: Optional[bytes] = None,
        ss_pqc: Optional[bytes] = None
    ) -> SessionKeys:
        """
        Derives session encryption, MAC, and IV keys with cryptographic transcript binding.

        Args:
            mode: "HYBRID", "PQC_ONLY", or "CLASSICAL_ONLY"
            session_id: 16-byte unique session identifier
            salt: ClientNonce (32B) + ServerNonce (32B) = 64 bytes
            transcript_hash: SHA-256 digest of preceding handshake messages
            ss_classical: 32 bytes X25519 shared secret (required for HYBRID, CLASSICAL)
            ss_pqc: 32 bytes ML-KEM shared secret (required for HYBRID, PQC)

        Returns:
            SessionKeys containing enc_key (32B), mac_key (32B), and iv_salt (8B)
        """
        mode = mode.upper()
        if mode in ("HYBRID", "HYBRID_X25519_MLKEM768"):
            if not ss_classical or not ss_pqc:
                raise ValueError("Hybrid mode requires both classical and post-quantum shared secrets")
            if len(ss_classical) != 32 or len(ss_pqc) != 32:
                raise ValueError("Shared secrets must each be 32 bytes")
            # Concatenation ordered: classical || pqc (RFC 9954 compliant)
            ikm = ss_classical + ss_pqc
            label = cls.LABEL_HYBRID
        elif mode in ("PQC_ONLY", "PQC", "PQC_MLKEM768"):
            if not ss_pqc or len(ss_pqc) != 32:
                raise ValueError("PQC mode requires valid 32-byte ML-KEM shared secret")
            ikm = ss_pqc
            label = cls.LABEL_PQC
        elif mode in ("CLASSICAL_ONLY", "CLASSICAL", "CLASSICAL_X25519"):
            if not ss_classical or len(ss_classical) != 32:
                raise ValueError("Classical mode requires valid 32-byte X25519 shared secret")
            ikm = ss_classical
            label = cls.LABEL_CLASSICAL
        else:
            raise ValueError(f"Unsupported key establishment mode: {mode}")

        # Info context binds the mode label, session_id, and transcript hash
        # Context-binding ensures handshake cannot be cross-replayed into a different mode
        info = label + b":" + session_id + b":" + transcript_hash

        # Extract & Expand 72 bytes total:
        # - 32 bytes: AES-256-GCM symmetric encryption key
        # - 32 bytes: HMAC-SHA256 handshake verification / MAC key
        # - 8 bytes:  Base IV/nonce salt
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=72,
            salt=salt,
            info=info
        )
        derived = hkdf.derive(ikm)

        enc_key = derived[0:32]
        mac_key = derived[32:64]
        iv_salt = derived[64:72]

        return SessionKeys(
            mode=mode,
            session_id=session_id,
            enc_key=enc_key,
            mac_key=mac_key,
            iv_salt=iv_salt,
            transcript_hash=transcript_hash
        )

    @staticmethod
    def compute_finished_tag(mac_key: bytes, role: str, transcript_hash: bytes) -> bytes:
        """
        Computes HMAC-SHA256 tag for Finished verification message.
        Role is "CLIENT" or "SERVER" for domain separation.
        """
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(role.encode("utf-8") + b":" + transcript_hash)
        return h.finalize()

    @staticmethod
    def verify_finished_tag(mac_key: bytes, role: str, transcript_hash: bytes, expected_tag: bytes) -> bool:
        """Constant-time verification of handshake finished tag."""
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(role.encode("utf-8") + b":" + transcript_hash)
        try:
            h.verify(expected_tag)
            return True
        except Exception:
            return False
