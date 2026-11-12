"""
Automated Security & Fault Injection Attack Tests.
Tests downgrade prevention, network failure resumption, ciphertext tampering,
replay resistance, session expiration, and baseline vulnerability.
"""

import os
import time
import asyncio
import pytest
from core.server import FileSharingServer
from core.client_policy import PolicyAwareClient
from core.client_baseline import BaselineClient
from core.transport import AsyncTransport
from protocol.messages import ClientHello, MessageType
from crypto.classical_x25519 import X25519KeyExchange
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
        with pytest.raises(PolicyDowngradeRejectedError):
            await client.transfer_file(test_file)

        assert client.policy_engine.total_downgrades_rejected >= 1

    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_negotiation_stripping_causes_silent_downgrade_in_baseline(tmp_path):
    """
    Test Case: MiTM attacker strips ML-KEM from ClientHello.
    Expected: Baseline client accepts silent downgrade to Classical and transfers the file in Classical mode.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "baseline_strip.txt")
    with open(test_file, "wb") as f:
        f.write(b"Baseline data subjected to negotiation stripping attack.")

    server = FileSharingServer(host="127.0.0.1", port=9061, storage_dir=server_dir)
    await server.start()

    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9062,
        target_host="127.0.0.1",
        target_port=9061,
        attack_config=AttackConfig(attack_type=AttackType.STRIP_NEGOTIATION)
    )
    await proxy.start()

    try:
        client = BaselineClient(
            server_host="127.0.0.1",
            server_port=9062,
            max_retries=3,
            retry_delay_sec=0.1
        )
        result = await client.transfer_file(test_file)
        assert result["status"] == "SUCCESS"
        assert result["unauthorized_downgrade_occurred"] is True
        assert result["mode"] == SecurityMode.CLASSICAL_X25519.value
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

        assert result["status"] == "SUCCESS"
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value
        assert client.policy_engine.total_unauthorized_downgrades_accepted == 0

    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_downgrade_server_hello_rejected(tmp_path):
    """
    Test Case: MiTM attacker tampers ServerHello to force Classical mode.
    Expected: Policy-Aware client rejects with PolicyDowngradeRejectedError.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "server_hello_tamper.txt")
    with open(test_file, "wb") as f:
        f.write(b"Data protected against ServerHello downgrade tampering.")

    server = FileSharingServer(host="127.0.0.1", port=9071, storage_dir=server_dir)
    await server.start()

    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9072,
        target_host="127.0.0.1",
        target_port=9071,
        attack_config=AttackConfig(attack_type=AttackType.DOWNGRADE_SERVER_HELLO)
    )
    await proxy.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9072,
            policy=PolicyLevel.STRICT_HYBRID,
            max_retries=1
        )
        with pytest.raises(PolicyDowngradeRejectedError):
            await client.transfer_file(test_file)
        assert client.policy_engine.total_downgrades_rejected >= 1
    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_downgrade_on_retry_rejected_by_policy_client(tmp_path):
    """
    Test Case: Network failure on attempt 1, followed by MiTM stripping on attempt 2 (retry).
    Expected: Policy-Aware client detects retry security rank reduction and rejects downgrade.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "retry_downgrade.txt")
    with open(test_file, "wb") as f:
        f.write(b"Data protected against reconnect / retry downgrade.")

    server = FileSharingServer(host="127.0.0.1", port=9081, storage_dir=server_dir)
    await server.start()

    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9082,
        target_host="127.0.0.1",
        target_port=9081,
        attack_config=AttackConfig(attack_type=AttackType.DOWNGRADE_ON_RETRY)
    )
    await proxy.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9082,
            policy=PolicyLevel.STRICT_HYBRID,
            max_retries=2,
            retry_delay_sec=0.1
        )
        with pytest.raises(PolicyDowngradeRejectedError):
            await client.transfer_file(test_file)
        assert client.policy_engine.total_downgrades_rejected >= 1
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

    test_file = os.path.join(client_dir, "large_dataset.bin")
    content = os.urandom(150 * 1024)
    with open(test_file, "wb") as f:
        f.write(content)

    server = FileSharingServer(host="127.0.0.1", port=9041, storage_dir=server_dir)
    await server.start()

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
        assert result["attempts"] == 2
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value

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


@pytest.mark.asyncio
async def test_replay_handshake_rejected(tmp_path):
    """
    Test Case: Attacker captures ClientKex from Session 1 and injects it into Session 2.
    Expected: Server verifies Finished tag against fresh salt and transcript digest; verification fails and rejects session.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    file1 = os.path.join(client_dir, "legit1.bin")
    file2 = os.path.join(client_dir, "legit2.bin")
    with open(file1, "wb") as f:
        f.write(b"First session legitimate file payload.")
    with open(file2, "wb") as f:
        f.write(b"Second session legitimate file payload.")

    server = FileSharingServer(host="127.0.0.1", port=9091, storage_dir=server_dir)
    await server.start()

    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9092,
        target_host="127.0.0.1",
        target_port=9091,
        attack_config=AttackConfig(attack_type=AttackType.REPLAY_HANDSHAKE)
    )
    await proxy.start()

    try:
        # Session 1: Proxy captures ClientKex
        client1 = PolicyAwareClient(server_host="127.0.0.1", server_port=9092, max_retries=1)
        res1 = await client1.transfer_file(file1)
        assert res1["status"] == "SUCCESS"
        assert proxy.captured_kex is not None

        # Session 2: Proxy injects captured ClientKex into second session
        client2 = PolicyAwareClient(server_host="127.0.0.1", server_port=9092, max_retries=1)
        with pytest.raises(Exception):
            await client2.transfer_file(file2)
    finally:
        await proxy.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_replayed_session_id_rejected(tmp_path):
    """
    Test Case: Attacker attempts to replay an already established session_id in ClientHello.
    Expected: Server detects duplicate session_id in active session registry and rejects with SESSION_REPLAY_DETECTED.
    """
    server_dir = str(tmp_path / "server_storage")
    server = FileSharingServer(host="127.0.0.1", port=9093, storage_dir=server_dir)
    await server.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 9093)
        client_nonce = os.urandom(32)
        session_id = os.urandom(16)
        _, pub = X25519KeyExchange.generate_keypair()

        ch = ClientHello(
            client_nonce=client_nonce,
            session_id=session_id,
            transfer_job_id="job-first",
            offered_modes=[SecurityMode.HYBRID_X25519_MLKEM768.value],
            client_policy=PolicyLevel.STRICT_HYBRID.value,
            client_x25519_pk=pub
        )
        await AsyncTransport.send_message(writer, ch.to_dict())
        s_hello = await AsyncTransport.receive_message(reader)
        assert s_hello.get("type") == MessageType.SERVER_HELLO.value

        # Register session as established in server
        server._active_sessions[session_id] = {
            "transfer_job_id": "job-first",
            "created_at": time.time(),
            "status": "ESTABLISHED"
        }
        writer.close()
        await writer.wait_closed()

        # Attacker tries to initiate a new handshake reusing the exact same session_id
        reader2, writer2 = await asyncio.open_connection("127.0.0.1", 9093)
        ch_replay = ClientHello(
            client_nonce=os.urandom(32),
            session_id=session_id,
            transfer_job_id="job-replay",
            offered_modes=[SecurityMode.HYBRID_X25519_MLKEM768.value],
            client_policy=PolicyLevel.STRICT_HYBRID.value,
            client_x25519_pk=pub
        )
        await AsyncTransport.send_message(writer2, ch_replay.to_dict())
        err = await AsyncTransport.receive_message(reader2)
        assert err.get("type") == MessageType.ERROR.value
        assert err.get("code") == "SESSION_REPLAY_DETECTED"
        writer2.close()
        await writer2.wait_closed()

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_reconnection_after_expired_session(tmp_path):
    """
    Test Case: Session expires after inactivity or timeout.
    Expected: Subsequent reconnection establishes a fresh authenticated session with new session ID and ephemeral keys.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "expiry_doc.bin")
    content = os.urandom(64 * 1024)
    with open(test_file, "wb") as f:
        f.write(content)

    server = FileSharingServer(host="127.0.0.1", port=9095, storage_dir=server_dir, session_ttl_sec=0.2)
    await server.start()

    try:
        # First transfer
        client = PolicyAwareClient(server_host="127.0.0.1", server_port=9095, max_retries=1)
        res1 = await client.transfer_file(test_file, job_id="job-expiry-test")
        assert res1["status"] == "SUCCESS"

        # Wait for session TTL to expire
        await asyncio.sleep(0.3)

        # Reconnection establishes fresh authenticated session and succeeds
        client2 = PolicyAwareClient(server_host="127.0.0.1", server_port=9095, max_retries=1)
        res2 = await client2.transfer_file(test_file, job_id="job-expiry-test-2")
        assert res2["status"] == "SUCCESS"
        assert res2["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_interrupt_after_client_hello_rejected(tmp_path):
    """
    Test Case: Attacker drops SERVER_HELLO immediately after CLIENT_HELLO is forwarded.
    Expected: Policy-Aware client experiences connection failure (timeout/close),
    retries under STRICT_HYBRID, and either succeeds on retry (attack disarmed)
    or raises a network error — but never silently downgrades.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file = os.path.join(client_dir, "interrupt_hello_doc.bin")
    with open(test_file, "wb") as f:
        f.write(b"Data requiring uninterrupted hybrid handshake.")

    server = FileSharingServer(host="127.0.0.1", port=9097, storage_dir=server_dir)
    await server.start()

    proxy = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=9098,
        target_host="127.0.0.1",
        target_port=9097,
        attack_config=AttackConfig(attack_type=AttackType.INTERRUPT_AFTER_CLIENT_HELLO)
    )
    await proxy.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9098,
            policy=PolicyLevel.STRICT_HYBRID,
            max_retries=2,
            retry_delay_sec=0.1
        )
        # Attack fires once then disarms; retry should succeed under STRICT_HYBRID
        result = await client.transfer_file(test_file)
        assert result["status"] == "SUCCESS"
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value
        assert client.policy_engine.total_unauthorized_downgrades_accepted == 0
        assert proxy.attack_injected_count >= 1

    finally:
        await proxy.stop()
        await server.stop()
