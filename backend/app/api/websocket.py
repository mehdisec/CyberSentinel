"""WebSocket connection manager for real-time live telemetry and log streaming."""
import asyncio
import json
import logging
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from backend.app.core.config import settings
from backend.app.core.security import is_valid_session

from backend.app.modules.network import (
    bandwidth_tracker,
    get_active_sockets,
    get_top_ip_negotiations,
)
from backend.app.modules.fail2ban import get_fail2ban_status
from backend.app.modules.telemetry import get_cpu_usage, get_memory_usage, compute_threat_score
from backend.app.modules.access import get_failed_logins
from backend.app.modules.logs import query_logs

logger = logging.getLogger("cybersentinel.websocket")
ws_router = APIRouter()


class WebSocketHub:
    """Manages active WebSocket connections and broadcasts telemetry updates."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._broadcast_task: asyncio.Task = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        dead = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                dead.append(connection)

        for d in dead:
            self.disconnect(d)

    async def start_broadcaster(self):
        """Background coroutine that gathers telemetry and streams it to all connected frontends."""
        while True:
            try:
                if self.active_connections:
                    bw = bandwidth_tracker.get_bandwidth()
                    cpu = get_cpu_usage()
                    mem = get_memory_usage()
                    threat = compute_threat_score()
                    sockets_summary = get_active_sockets()["summary"]
                    failed = get_failed_logins(max_entries=3)

                    # Latest 3 logs
                    latest_logs = query_logs(limit=3)["logs"]

                    telemetry_packet = {
                        "type": "telemetry_pulse",
                        "bandwidth": bw,
                        "cpu": cpu,
                        "memory": mem,
                        "threat": threat,
                        "sockets_summary": sockets_summary,
                        "failed_logins_total": failed.get("total_failed_events", 0),
                        "recent_attackers": failed.get("attackers", [])[:3],
                        "latest_logs": latest_logs,
                        "fail2ban": get_fail2ban_status(),
                        "top_negotiations": get_top_ip_negotiations(limit=5),
                    }
                    await self.broadcast(telemetry_packet)
            except Exception as e:
                logger.error(f"Error in telemetry broadcast loop: {e}")

            await asyncio.sleep(1.5)


hub = WebSocketHub()


@ws_router.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for live dashboard data streaming.
    Streams bandwidth sparklines, system metrics, threat score, and logs.
    """
    if settings.auth_enabled:
        token = websocket.query_params.get("token")
        if not token or not (is_valid_session(token) or (settings.admin_token and token == settings.admin_token)):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await hub.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                action = msg.get("action")
                if action == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        hub.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
        hub.disconnect(websocket)
