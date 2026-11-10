"""
Cryptographic Security Modes and Policy Levels.
"""

from enum import Enum


class SecurityMode(str, Enum):
    """Supported cryptographic key-establishment modes."""
    HYBRID_X25519_MLKEM768 = "HYBRID_X25519_MLKEM768"
    PQC_MLKEM768 = "PQC_MLKEM768"
    CLASSICAL_X25519 = "CLASSICAL_X25519"

    @property
    def security_rank(self) -> int:
        """
        Rank representing cryptographic hardness:
        3 = Hybrid (Dual classical + post-quantum protection)
        2 = Post-quantum only (NIST FIPS 203 Category 3)
        1 = Classical only (Subject to Shor's algorithm on CRQC)
        """
        ranks = {
            SecurityMode.HYBRID_X25519_MLKEM768: 3,
            SecurityMode.PQC_MLKEM768: 2,
            SecurityMode.CLASSICAL_X25519: 1,
        }
        return ranks[self]


class PolicyLevel(str, Enum):
    """
    Enforcement policy governing allowed key establishment and failure recovery.
    """
    STRICT_HYBRID = "STRICT_HYBRID"         # Mandatory Hybrid (X25519 + ML-KEM). Classical fallback prohibited.
    STRICT_PQC = "STRICT_PQC"               # Mandatory Post-Quantum (Hybrid or PQC). Classical prohibited.
    COMPAT_CLASSICAL = "COMPAT_CLASSICAL"   # Explicitly allows classical-only operation.
    ALLOW_FALLBACK = "ALLOW_FALLBACK"       # VULNERABLE BASELINE: Silently drops to classical on failure.

