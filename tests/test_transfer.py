"""
Integration tests for end-to-end File Transfer, Hybrid Handshake, and Resumption.
"""

import os
import asyncio
import pytest
from core.server import FileSharingServer
from core.client_policy import PolicyAwareClient
from core.client_baseline import BaselineClient
from policy.modes import PolicyLevel, SecurityMode


@pytest.mark.asyncio
async def test_end_to_end_hybrid_file_transfer(tmp_path):
    """Verify complete end-to-end file transfer using Hybrid ML-KEM-768 + X25519."""
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    # Create dummy 250 KB file (spanning ~4 chunks of 64KB)
    test_file_path = os.path.join(client_dir, "test_document.bin")
    file_content = os.urandom(250 * 1024)
    with open(test_file_path, "wb") as f:
        f.write(file_content)

    server = FileSharingServer(host="127.0.0.1", port=9001, storage_dir=server_dir)
    await server.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9001,
            policy=PolicyLevel.STRICT_HYBRID
        )
        result = await client.transfer_file(test_file_path)

        assert result["status"] == "SUCCESS"
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value
        assert result["downgrades_prevented"] == 0

        # Verify delivered file matches byte-for-byte
        delivered_path = os.path.join(server_dir, "test_document.bin")
        assert os.path.exists(delivered_path)
        with open(delivered_path, "rb") as f:
            delivered_content = f.read()
        assert delivered_content == file_content

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_baseline_transfer_succeeds_normally(tmp_path):
    """Verify baseline client transfers file normally when no attack occurs."""
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file_path = os.path.join(client_dir, "baseline_sample.txt")
    with open(test_file_path, "wb") as f:
        f.write(b"Baseline Test File Contents under normal network.")

    server = FileSharingServer(host="127.0.0.1", port=9002, storage_dir=server_dir)
    await server.start()

    try:
        client = BaselineClient(server_host="127.0.0.1", server_port=9002)
        result = await client.transfer_file(test_file_path)

        assert result["status"] == "SUCCESS"
        assert not result["unauthorized_downgrade_occurred"]
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_end_to_end_classical_file_transfer(tmp_path):
    """
    Verify complete file transfer using Classical X25519 when explicitly permitted by policy.
    Essential test case: Classical mode explicitly permitted by policy -> Classical connection succeeds.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file_path = os.path.join(client_dir, "classical_doc.bin")
    file_content = os.urandom(128 * 1024)
    with open(test_file_path, "wb") as f:
        f.write(file_content)

    server = FileSharingServer(host="127.0.0.1", port=9003, storage_dir=server_dir)
    await server.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9003,
            policy=PolicyLevel.COMPAT_CLASSICAL,
            preferred_mode=SecurityMode.CLASSICAL_X25519
        )
        result = await client.transfer_file(test_file_path)

        assert result["status"] == "SUCCESS"
        assert result["mode"] == SecurityMode.CLASSICAL_X25519.value

        delivered_path = os.path.join(server_dir, "classical_doc.bin")
        assert os.path.exists(delivered_path)
        with open(delivered_path, "rb") as f:
            delivered_content = f.read()
        assert delivered_content == file_content

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_end_to_end_pqc_only_file_transfer(tmp_path):
    """
    Verify complete file transfer using pure Post-Quantum ML-KEM-768 (FIPS 203).
    """
    server_dir = str(tmp_path / "server_storage")
    client_dir = str(tmp_path / "client_storage")
    os.makedirs(client_dir, exist_ok=True)

    test_file_path = os.path.join(client_dir, "pqc_doc.bin")
    file_content = os.urandom(128 * 1024)
    with open(test_file_path, "wb") as f:
        f.write(file_content)

    server = FileSharingServer(host="127.0.0.1", port=9004, storage_dir=server_dir)
    await server.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9004,
            policy=PolicyLevel.STRICT_PQC,
            preferred_mode=SecurityMode.PQC_MLKEM768
        )
        result = await client.transfer_file(test_file_path)

        assert result["status"] == "SUCCESS"
        assert result["mode"] == SecurityMode.PQC_MLKEM768.value

        delivered_path = os.path.join(server_dir, "pqc_doc.bin")
        assert os.path.exists(delivered_path)
        with open(delivered_path, "rb") as f:
            delivered_content = f.read()
        assert delivered_content == file_content

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_end_to_end_file_download(tmp_path):
    """
    Verify secure file download from server using Hybrid ML-KEM-768 + X25519.
    Tests Phase 3 file download capability.
    """
    server_dir = str(tmp_path / "server_storage")
    client_dest_dir = str(tmp_path / "client_downloads")
    os.makedirs(server_dir, exist_ok=True)
    os.makedirs(client_dest_dir, exist_ok=True)

    # Place file on server
    file_name = "server_report.pdf"
    file_content = os.urandom(200 * 1024)
    with open(os.path.join(server_dir, file_name), "wb") as f:
        f.write(file_content)

    server = FileSharingServer(host="127.0.0.1", port=9005, storage_dir=server_dir)
    await server.start()

    try:
        client = PolicyAwareClient(
            server_host="127.0.0.1",
            server_port=9005,
            policy=PolicyLevel.STRICT_HYBRID
        )
        result = await client.download_file(file_name=file_name, dest_dir=client_dest_dir)

        assert result["status"] == "SUCCESS"
        assert result["mode"] == SecurityMode.HYBRID_X25519_MLKEM768.value

        downloaded_file = os.path.join(client_dest_dir, file_name)
        assert os.path.exists(downloaded_file)
        with open(downloaded_file, "rb") as f:
            assert f.read() == file_content

    finally:
        await server.stop()


