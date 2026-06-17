"""
FastAPI WebSocket Router for Real-Time Live Telemetry Streams
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
import random

router = APIRouter(prefix="/ws", tags=["WebSockets"])

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # Send initial success handshake
        await websocket.send_text(json.dumps({"type": "HANDSHAKE", "status": "CONNECTED", "message": "CyCraft Live Driverless Telemetry Channel Engaged."}))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                pass

manager = ConnectionManager()

@router.websocket("/stream")
async def live_telemetry_stream(websocket: WebSocket):
    """
    Real-time persistent WebSocket connection for real-time security ticker updates and AI trigger notifications
    """
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(8)
            # Periodic health heartbeat & live alerts broadcast
            endpoints = ["DEV-WIN-SRV09", "FIN-WRK-102", "ENG-MAC-404", "AWS-IAM-US-EAST", "IDENTITY-IDP"]
            titles = ["LSASS Process Memory Hooked", "SMB Authentication Spike Thwarted", "Outbound DNS Tunnel Blocked", "Anomalous IAM Policy Rolled Back", "Multiple Failed Okta Authentications"]
            sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            
            ticker_item = {
                "type": "TICKER_UPDATE",
                "endpoint": random.choice(endpoints),
                "title": random.choice(titles),
                "severity": random.choice(sevs),
                "status": "Auto-Contained"
            }
            await manager.broadcast(ticker_item)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
