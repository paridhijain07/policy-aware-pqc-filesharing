"""
Unit tests for Policy Engine, Message Serialization, and Transcript Binding.
"""

import os
import pytest
from policy.modes import SecurityMode, PolicyLevel
from policy.engine import PolicyEngine, PolicyDowngradeRejectedError
from protocol.messages import (
    ClientHello,
    ServerHello,
    ClientKex,
    ServerFinished,
    ProtocolSerializer,
    MessageType,
)
from protocol.transcript import HandshakeTranscript
from crypto.hybrid_combiner import HybridKeyDerivation


def test_policy_engine_strict_hybrid():
    """Verify STRICT_HYBRID accepts only Hybrid and rejects classical downgrades."""
    engine = PolicyEngine(PolicyLevel.STRICT_HYBRID)

    # Hybrid allowed
    decision = engine.evaluate_negotiation(SecurityMode.HYBRID_X25519_MLKEM768)
    assert decision.allowed
    assert not decision.is_downgrade

    # Classical downgrade rejected
    with pytest.raises(PolicyDowngradeRejectedError):
        engine.evaluate_negotiation(SecurityMode.CLASSICAL_X25519)

    # PQC-only downgrade rejected under STRICT_HYBRID
    with pytest.raises(PolicyDowngradeRejectedError):
        engine.evaluate_negotiation(SecurityMode.PQC_MLKEM768)

    assert engine.total_downgrades_rejected == 2
    assert engine.total_unauthorized_downgrades_accepted == 0


def test_policy_engine_retry_invariants():
    """Verify retry policy enforces non-decreasing cryptographic security."""
    engine = PolicyEngine(PolicyLevel.STRICT_HYBRID)

    # Retry with same security level: allowed
    decision = engine.evaluate_retry(
        previous_mode=SecurityMode.HYBRID_X25519_MLKEM768,
        retry_mode=SecurityMode.HYBRID_X25519_MLKEM768,
        retry_count=1
    )
    assert decision.allowed

    # Retry attempting downgrade: forbidden
    with pytest.raises(PolicyDowngradeRejectedError):
        engine.evaluate_retry(
            previous_mode=SecurityMode.HYBRID_X25519_MLKEM768,
            retry_mode=SecurityMode.CLASSICAL_X25519,
            retry_count=2
        )


def test_policy_engine_baseline_vulnerability():
    """Verify ALLOW_FALLBACK mode permits downgrades (simulates naive baseline)."""
    engine = PolicyEngine(PolicyLevel.ALLOW_FALLBACK)

    decision = engine.evaluate_negotiation(SecurityMode.CLASSICAL_X25519)
    assert decision.allowed
    assert decision.is_downgrade
    assert engine.total_unauthorized_downgrades_accepted == 1


def test_protocol_serialization_roundtrip():
    """Verify ClientHello serialization, packing, and parsing."""
    ch = ClientHello(
        client_nonce=os.urandom(32),
        session_id=os.urandom(16),
        transfer_job_id="job-12345",
        offered_modes=[SecurityMode.HYBRID_X25519_MLKEM768.value],
        client_policy=PolicyLevel.STRICT_HYBRID.value,
        client_x25519_pk=os.urandom(32),
    )

    d = ch.to_dict()
    wire_bytes = ProtocolSerializer.pack(d)

    # Unpack prefix
    prefix_len = int.from_bytes(wire_bytes[:4], "big")
    payload = wire_bytes[4:4 + prefix_len]
    parsed_dict = ProtocolSerializer.unpack_payload(payload)

    ch_restored = ClientHello.from_dict(parsed_dict)
    assert ch_restored.client_nonce == ch.client_nonce
    assert ch_restored.session_id == ch.session_id
    assert ch_restored.transfer_job_id == ch.transfer_job_id
    assert ch_restored.offered_modes == ch.offered_modes
    assert ch_restored.client_policy == ch.client_policy
    assert ch_restored.client_x25519_pk == ch.client_x25519_pk


def test_transcript_detects_negotiation_tampering():
    """Verify transcript hash changes if an attacker tampers with offered modes."""
    t_client = HandshakeTranscript()
    t_server = HandshakeTranscript()

    ch = ClientHello(
        client_nonce=b"\x01" * 32,
        session_id=b"\x02" * 16,
        transfer_job_id="job-1",
        offered_modes=[SecurityMode.HYBRID_X25519_MLKEM768.value],
        client_policy=PolicyLevel.STRICT_HYBRID.value,
        client_x25519_pk=b"\x03" * 32,
    )

    # Client records genuine hello
    t_client.update(ch.to_dict())

    # Adversary strips Hybrid and replaces with Classical
    tampered_dict = ch.to_dict()
    tampered_dict["offered_modes"] = [SecurityMode.CLASSICAL_X25519.value]
    t_server.update(tampered_dict)

    # Digest must mismatch
    assert t_client.current_digest() != t_server.current_digest()

