"""ISOLATED MOCK SWITCH CORE SERVER.

WARNING / DISCLAIMER:
THIS MOCK IS STRICTLY FOR OFFLINE UNIT TESTING AND CI VALIDATION ONLY.
IT IS NEVER SUBSTITUTED FOR THE REAL SWITCH CORE INTEGRATION IN PRODUCTION.
REAL SWITCH CONNECTIVITY RUNS AGAINST THE INSTALLED SWITCH SERVER ON PORT 53450.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket


class MockSwitchCoreServer:
    """Simulates Switch Core 0.31.0 HTTP & WebSocket endpoints for local unit testing."""

    def __init__(self) -> None:
        self.registered_agents: dict[str, dict[str, Any]] = {}
        self.posted_messages: list[dict[str, Any]] = []
        self.active_websockets: list[WebSocket] = []
        self.app = Starlette(
            routes=[
                Route("/agents", self.handle_register, methods=["POST"]),
                Route("/agents/{agent_id}/message", self.handle_send_message, methods=["POST"]),
                WebSocketRoute("/agents/{agent_id}/connection/ws", self.handle_ws),
            ]
        )

    async def handle_register(self, request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"detail": "Invalid authorization header"}, status_code=401)

        data = await request.json()
        agent_id = f"mock-agent-{uuid.uuid4().hex[:8]}"
        api_key = f"mock-key-{uuid.uuid4().hex[:16]}"
        self.registered_agents[agent_id] = {
            "name": data.get("name"),
            "display_name": data.get("display_name"),
            "api_key": api_key
        }
        return JSONResponse({"id": agent_id, "api_key": api_key}, status_code=200)

    async def handle_send_message(self, request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)

        agent_id = request.path_params.get("agent_id")
        data = await request.json()
        event_id = f"evt-{uuid.uuid4().hex[:8]}"
        self.posted_messages.append({
            "agent_id": agent_id,
            "room_id": data.get("room_id"),
            "content": data.get("content"),
            "event_id": event_id
        })
        return JSONResponse({"ok": True, "event_id": event_id}, status_code=200)

    async def handle_ws(self, websocket: WebSocket) -> None:
        auth = websocket.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            await websocket.close(code=4401)
            return

        await websocket.accept()
        self.active_websockets.append(websocket)
        try:
            # 1. Send initial connection_state frame matching Switch Core stream.py
            await websocket.send_json({
                "event": "connection_state",
                "data": {
                    "connection_id": websocket.query_params.get("connection_id", "test-conn"),
                    "generation": 1,
                    "protocol": 9
                }
            })

            while True:
                # Read client frames (pong beats)
                msg = await websocket.receive_text()
                data = json.loads(msg)
                if data.get("type") == "pong":
                    pass  # Beat acknowledged
        except Exception:
            pass
        finally:
            if websocket in self.active_websockets:
                self.active_websockets.remove(websocket)

    async def broadcast_event(self, event_type: str, room_id: str, payload: dict[str, Any]) -> None:
        """Helper to simulate an incoming message in a Switch room."""
        frame = {
            "event": "event",
            "data": {
                "type": event_type,
                "room_id": room_id,
                "payload": payload
            }
        }
        for ws in self.active_websockets:
            await ws.send_json(frame)
