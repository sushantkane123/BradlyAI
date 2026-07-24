"""FastAPI WebSocket Router for Real-Time Live Telemetry Streams"""
import asyncio
import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("bradlyai.ws")
router = APIRouter(prefix="/ws", tags=["WebSockets"])


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected — {len(self.active_connections)} active")
        await websocket.send_text(json.dumps({"type": "HANDSHAKE", "status": "CONNECTED", "message": "BradlyAI live telemetry channel connected."}))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected — {len(self.active_connections)} active")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


@router.websocket("/stream")
async def live_telemetry_stream(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "HEARTBEAT", "timestamp": "now", "active_connections": len(manager.active_connections)}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except asyncio.CancelledError:
        manager.disconnect(websocket)
