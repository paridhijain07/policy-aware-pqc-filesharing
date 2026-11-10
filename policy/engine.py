"""
Security Policy Enforcement Engine.
Enforces invariant: Connection failures and retries MUST NOT authorize a reduction in cryptographic security.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from .modes import SecurityMode, PolicyLevel


class SecurityPolicyException(Exception):
    """Base exception for cryptographic policy violations."""
    pass


class PolicyDowngradeRejectedError(SecurityPolicyException):
    """Raised when an attempt to downgrade cryptographic security level is rejected."""
    pass


@dataclass
class PolicyDecision:
    """Record of a policy decision made during handshake or recovery."""
    timestamp: datetime
    requested_policy: PolicyLevel
    proposed_mode: SecurityMode
    allowed: bool
    is_downgrade: bool
    reason: str


class PolicyEngine:
    """
    Enforces cryptographic policy invariants during handshake negotiation and retry loops.
    Tracks audit trail of allowed/rejected negotiations for experimental metrics.
    """

    def __init__(self, policy: PolicyLevel):
        self.policy = policy
        self.decision_history: List[PolicyDecision] = []

    def evaluate_negotiation(self, proposed_mode: SecurityMode) -> PolicyDecision:
        """
        Validates whether a proposed or negotiated mode satisfies the transfer's security policy.
        """
        allowed = False
        is_downgrade = False
        reason = ""

        if self.policy == PolicyLevel.STRICT_HYBRID:
            if proposed_mode == SecurityMode.HYBRID_X25519_MLKEM768:
                allowed = True
                reason = "Hybrid mode satisfies STRICT_HYBRID requirement."
            else:
                allowed = False
                is_downgrade = True
                reason = f"Mode '{proposed_mode.value}' is a forbidden downgrade from STRICT_HYBRID."

        elif self.policy == PolicyLevel.STRICT_PQC:
            if proposed_mode in (SecurityMode.HYBRID_X25519_MLKEM768, SecurityMode.PQC_MLKEM768):
                allowed = True
                reason = f"Mode '{proposed_mode.value}' satisfies post-quantum requirement."
            else:
                allowed = False
                is_downgrade = True
                reason = "Classical mode rejected under STRICT_PQC policy."

        elif self.policy == PolicyLevel.COMPAT_CLASSICAL:
            allowed = True
            reason = "Classical mode explicitly permitted by user policy."

        elif self.policy == PolicyLevel.ALLOW_FALLBACK:
            # Baseline vulnerable mode: permits any mode, even downgrades
            allowed = True
            is_downgrade = proposed_mode != SecurityMode.HYBRID_X25519_MLKEM768
            reason = "BASELINE VULNERABILITY: Fallback permitted without strict enforcement."

        decision = PolicyDecision(
            timestamp=datetime.now(timezone.utc),
            requested_policy=self.policy,
            proposed_mode=proposed_mode,
            allowed=allowed,
            is_downgrade=is_downgrade,
            reason=reason
        )
        self.decision_history.append(decision)

        if not allowed:
            raise PolicyDowngradeRejectedError(reason)

        return decision

    def evaluate_retry(
        self,
        previous_mode: SecurityMode,
        retry_mode: SecurityMode,
        retry_count: int
    ) -> PolicyDecision:
        """
        Evaluates a retry or reconnection attempt following a network failure.
        Ensures that retry attempts do not silently lower security rank.
        """
        is_lower_rank = retry_mode.security_rank < previous_mode.security_rank

        if self.policy in (PolicyLevel.STRICT_HYBRID, PolicyLevel.STRICT_PQC):
            if is_lower_rank:
                decision = PolicyDecision(
                    timestamp=datetime.now(timezone.utc),
                    requested_policy=self.policy,
                    proposed_mode=retry_mode,
                    allowed=False,
                    is_downgrade=True,
                    reason=(
                        f"RETRY BLOCKED: Network failure cannot authorize downgrade from "
                        f"{previous_mode.value} (rank {previous_mode.security_rank}) to "
                        f"{retry_mode.value} (rank {retry_mode.security_rank}) [Attempt #{retry_count}]."
                    )
                )
                self.decision_history.append(decision)
                raise PolicyDowngradeRejectedError(decision.reason)

        return self.evaluate_negotiation(retry_mode)

    @property
    def total_downgrades_rejected(self) -> int:
        return sum(1 for d in self.decision_history if d.is_downgrade and not d.allowed)

    @property
    def total_unauthorized_downgrades_accepted(self) -> int:
        return sum(1 for d in self.decision_history if d.is_downgrade and d.allowed)
