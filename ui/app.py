"""
Web Dashboard Backend (FastAPI + WebSockets).
Provides real-time visualization of the post-quantum handshake, active attack simulator,
and baseline vs. policy-aware comparative transfers.
"""

import os
import sys
import asyncio
import logging
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.server import FileSharingServer
from core.client_policy import PolicyAwareClient
from core.client_baseline import BaselineClient
from policy.modes import PolicyLevel, SecurityMode
from simulator.proxy import NetworkAttackProxy
from simulator.attack_rules import AttackType, AttackConfig
from evaluation.plot_results import plot_all

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Dashboard")

app = FastAPI(title="Policy-Aware Post-Quantum File Sharing")

# Global instances
server_instance: Optional[FileSharingServer] = None
proxy_instance: Optional[NetworkAttackProxy] = None
active_websockets: List[WebSocket] = []

SERVER_PORT = 8765
PROXY_PORT = 9090
UPLOAD_DIR = "storage/client_uploads"
SERVER_STORAGE = "storage/server_storage"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SERVER_STORAGE, exist_ok=True)
os.makedirs("results/plots", exist_ok=True)


async def broadcast_event(event_type: str, data: Dict[str, Any]):
    """Broadcasts a real-time event to all connected dashboard WebSockets."""
    payload = {"event": event_type, "data": data}
    dead = []
    for ws in active_websockets:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in active_websockets:
            active_websockets.remove(ws)


def on_server_event(event_type: str, data: Dict):
    asyncio.create_task(broadcast_event(f"SERVER_{event_type}", data))


def on_proxy_event(event_type: str, data: Dict):
    asyncio.create_task(broadcast_event(f"PROXY_{event_type}", data))


def on_client_event(event_type: str, data: Dict):
    asyncio.create_task(broadcast_event(f"CLIENT_{event_type}", data))


@app.on_event("startup")
async def startup_services():
    global server_instance, proxy_instance
    # Start File Sharing Server
    server_instance = FileSharingServer(
        host="127.0.0.1",
        port=SERVER_PORT,
        storage_dir=SERVER_STORAGE,
        event_callback=on_server_event
    )
    await server_instance.start()

    # Start Attack Proxy
    proxy_instance = NetworkAttackProxy(
        proxy_host="127.0.0.1",
        proxy_port=PROXY_PORT,
        target_host="127.0.0.1",
        target_port=SERVER_PORT,
        attack_config=AttackConfig(attack_type=AttackType.NONE),
        event_callback=on_proxy_event
    )
    await proxy_instance.start()
    logger.info("Server and Attack Proxy started successfully.")


@app.on_event("shutdown")
async def shutdown_services():
    global server_instance, proxy_instance
    if proxy_instance:
        await proxy_instance.stop()
    if server_instance:
        await server_instance.stop()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    # Send initial status
    await websocket.send_json({
        "event": "SYSTEM_STATUS",
        "data": {
            "server_port": SERVER_PORT,
            "proxy_port": PROXY_PORT,
            "algorithms": ["X25519", "ML-KEM-768", "Dual-PRF HKDF", "AES-256-GCM"],
            "status": "READY"
        }
    })
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_websockets:
            active_websockets.remove(websocket)


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/api/transfer")
async def trigger_transfer(
    file: Optional[UploadFile] = File(None),
    client_type: str = Form("policy"),  # "policy" or "baseline"
    policy: str = Form("STRICT_HYBRID"),
    attack_type: str = Form("NONE"),
    sever_chunk: int = Form(1),
):
    """Handles file upload and initiates a client transfer through the attack proxy."""
    global proxy_instance

    # 1. Prepare target file
    if file and file.filename:
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
    else:
        # Generate default synthetic test file (150 KB)
        file_path = os.path.join(UPLOAD_DIR, "secure_payload.bin")
        if not os.path.exists(file_path):
            with open(file_path, "wb") as f:
                f.write(os.urandom(150 * 1024))

    # 2. Configure Attack Proxy
    att_enum = AttackType(attack_type)
    proxy_instance.config = AttackConfig(
        attack_type=att_enum,
        sever_at_chunk_index=sever_chunk,
        drop_on_attempt=1 if att_enum == AttackType.DROP_MLKEM_PACKET else None,
        active=True
    )

    await broadcast_event("TRANSFER_STARTING", {
        "client_type": client_type,
        "policy": policy,
        "attack_type": attack_type,
        "file_name": os.path.basename(file_path),
        "file_size": os.path.getsize(file_path)
    })

    # 3. Launch Client in background task
    asyncio.create_task(_run_client_transfer(client_type, policy, file_path))

    return {"status": "TRANSFER_INITIATED", "file": os.path.basename(file_path)}


async def _run_client_transfer(client_type: str, policy_str: str, file_path: str):
    """Executes the transfer using selected client implementation."""
    try:
        if client_type == "policy":
            pol_enum = PolicyLevel(policy_str)
            client = PolicyAwareClient(
                server_host="127.0.0.1",
                server_port=PROXY_PORT,
                policy=pol_enum,
                max_retries=3,
                retry_delay_sec=0.5,
                event_callback=on_client_event
            )
            res = await client.transfer_file(file_path)
            await broadcast_event("JOB_COMPLETED", {"result": res, "client_type": "policy"})

        else:
            client = BaselineClient(
                server_host="127.0.0.1",
                server_port=PROXY_PORT,
                max_retries=3,
                retry_delay_sec=0.5,
                event_callback=on_client_event
            )
            res = await client.transfer_file(file_path)
            await broadcast_event("JOB_COMPLETED", {"result": res, "client_type": "baseline"})

    except Exception as e:
        logger.error(f"Client transfer failed: {e}")
        await broadcast_event("JOB_FAILED", {"error": str(e), "client_type": client_type})


@app.get("/api/plots/{plot_name}")
async def get_plot(plot_name: str):
    """Serves generated experimental chart images."""
    file_path = os.path.join("results", "plots", plot_name)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    # If not existing, try generating
    plot_all()
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return {"error": "Plot not found"}

