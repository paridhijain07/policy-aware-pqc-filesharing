"""
Automated Security & Fault Injection Attack Tests.
Tests downgrade prevention, network failure resumption, ciphertext tampering, and baseline vulnerability.
"""

import os
import asyncio
import pytest
from core.server import FileSharingServer
from core.client_policy import PolicyAwareClient
from core.client_baseline import BaselineClient
from policy.modes import PolicyLevel, SecurityMode
from policy.engine import PolicyDowngradeRejectedError
from simulator.proxy import NetworkAttackProxy
from simulator.attack_rules import AttackType, AttackConfig


@pytest.mark.asyncio
async def test_negotiation_stripping_attack_rejected(tmp_path):
    """
    Test Case: MiTM attacker strips ML-KEM from ClientHello.
    Expected: Policy-Aware client rejects with PolicyDowngradeRejectedError because
    server is forced into Classical, which violates STRICT_HYBRID.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "confidential.pdf")
    with open(test_file, "wb") as f:
        f.write(b"Strictly confidential research data requiring hybrid protection.")

    server = FileSharingServer(host="127.0.0.1", port=9011, storage_dir=server_dir)
    await server.start()

    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9012,
        target_host="127.0.0.1",
        target_port=9011,
        attack_config=AttackConfig(attack_type=AttackType.STRIP_NEGOTIATION)
    )
    await proxy.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9012,
            policy=PolicyLevel.STRICT_HYBRID,
            max_retries=1
        )
        # Must fail because downgrade to classical is rejected!
        with pytest.raises(PolicyDowngradeRejectedError):
            await client.transfer_file(test_file)

        assert client.policy_engine.total_downgrades_rejected >= 1

    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_drop_mlkem_causes_silent_downgrade_in_baseline(tmp_path):
    """
    Test Case: Attacker drops ML-KEM packets on attempt 1.
    Expected:
    - Baseline client SILENTLY FALLS BACK to Classical X25519 (vulnerability reproduced).
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "vulnerable_doc.txt")
    with open(test_file, "wb") as f:
        f.write(b"Testing baseline naive fallback behavior under ML-KEM packet drop.")

    server = FileSharingServer(host="127.0.0.1", port=9021, storage_dir=server_dir)
    await server.start()

    # Proxy drops ML-KEM packet on attempt 1 only
    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9022,
        target_host="127.0.0.1",
        target_port=9021,
        attack_config=AttackConfig(attack_type=AttackType.DROP_MLKEM_PACKET, drop_on_attempt=1)
    )
    await proxy.start()

    try:
        client = BaselineClient(
            server_host="127.0.0.1",
            server_port=9022,
            max_retries=3,
            retry_delay_sec=0.2
        )
        result = await client.transfer_file(test_file)

        # Baseline client succeeded, but via unauthorized classical downgrade!
        assert result["status"] == "SUCCESS"
        assert result["unauthorized_downgrade_occurred"] is True
        assert result["mode"] == SecurityMode.CLASSICAL_X25519.value

    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_drop_mlkem_preserves_policy_in_resilient_client(tmp_path):
    """
    Test Case: Attacker drops ML-KEM packet on attempt 1, but network heals on attempt 2.
    Expected:
    - Policy-Aware client retries, RETAINS STRICT_HYBRID, does NOT downgrade, and finishes with Hybrid.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "policy_doc.txt")
    with open(test_file, "wb") as f:
        f.write(b"Testing policy-aware resilient retry without classical downgrade.")

    server = FileSharingServer(host="127.0.0.1", port=9031, storage_dir=server_dir)
    await server.start()

    # Drop only on attempt 1
    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9032,
        target_host="127.0.0.1",
        target_port=9031,
        attack_config=AttackConfig(attack_type=AttackType.DROP_MLKEM_PACKET, drop_on_attempt=1)
    )
    await proxy.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9032,
            policy=PolicyLevel.STRICT_HYBRID,
            max_retries=3,
            retry_delay_sec=0.2
        )
        result = await client.transfer_file(test_file)

        # Policy preserved! Completed with Hybrid!
        assert result["status"] == "SUCCESS"
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value
        assert client.policy_engine.total_unauthorized_downgrades_accepted == 0

    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_midway_severance_resumption_under_hybrid(tmp_path):
    """
    Test Case: Network severed midway during chunked transfer (at chunk 1).
    Expected: Policy-Aware client reconnects, establishes fresh ephemeral Hybrid keys,
    and resumes streaming from remaining chunks without restarting from scratch.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    # File large enough for 3 chunks (150 KB)
    test_file = os.path.join(client_dir, "large_dataset.bin")
    content = os.urandom(150 * 1024)
    with open(test_file, "wb") as f:
        f.write(content)

    server = FileSharingServer(host="127.0.0.1", port=9041, storage_dir=server_dir)
    await server.start()

    # Sever after chunk 1
    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9042,
        target_host="127.0.0.1",
        target_port=9041,
        attack_config=AttackConfig(attack_type=AttackType.SEVER_MIDWAY, sever_at_chunk_index=1)
    )
    await proxy.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9042,
            policy=PolicyLevel.STRICT_HYBRID,
            max_retries=3,
            retry_delay_sec=0.2
        )
        result = await client.transfer_file(test_file)

        assert result["status"] == "SUCCESS"
        assert result["attempts"] == 2  # Proves resumption after severance
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value

        # Confirm complete file was verified and intact
        delivered = os.path.join(server_dir, "large_dataset.bin")
        with open(delivered, "rb") as f:
            delivered_content = f.read()
        assert delivered_content == content

    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_ciphertext_tampering_rejected_by_gcm(tmp_path):
    """
    Test Case: Attacker modifies a bit in the encrypted chunk in transit.
    Expected: Server rejects with CryptographicIntegrityError and aborts transfer.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "tamper_doc.bin")
    with open(test_file, "wb") as f:
        f.write(b"Data block to be corrupted by in-flight bit flip.")

    server = FileSharingServer(host="127.0.0.1", port=9051, storage_dir=server_dir)
    await server.start()

    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9052,
        target_host="127.0.0.1",
        target_port=9051,
        attack_config=AttackConfig(attack_type=AttackType.CORRUPT_CIPHERTEXT, corrupt_chunk_index=0)
    )
    await proxy.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9052,
            policy=PolicyLevel.STRICT_HYBRID,
            max_retries=1
        )
        with pytest.raises(Exception):
            await client.transfer_file(test_file)

    finally:
        await proxy.stop()
        await server.stop()
