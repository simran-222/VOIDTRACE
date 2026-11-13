import asyncio
import hmac
import logging
import os
import re

import httpx
import websockets
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, Response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("voidtrace-relay")

SWITCH_ORIGIN = "http://127.0.0.1:53450"
SWITCH_WS_ORIGIN = "ws://127.0.0.1:53450"

app = FastAPI(title="VOIDTRACE Authenticated Switch Relay")


def check_secret(provided: str | None) -> bool:
    expected = os.environ.get("VOIDTRACE_RELAY_SECRET", "")
    return bool(
        expected
        and provided
        and hmac.compare_digest(provided, expected)
    )


@app.on_event("startup")
async def verify_configuration():
    if not os.environ.get("VOIDTRACE_RELAY_SECRET"):
        raise RuntimeError("VOIDTRACE_RELAY_SECRET is not configured")
    logger.info("Authenticated relay configuration verified.")


@app.get("/health")
async def relay_health(request: Request):
    if not check_secret(request.headers.get("x-voidtrace-relay-secret")):
        return Response(status_code=401, content="Unauthorized")
    return JSONResponse({"status": "ok"})


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def relay_http(path: str, request: Request):
    if not check_secret(request.headers.get("x-voidtrace-relay-secret")):
        return Response(status_code=401, content="Unauthorized")

    allowed = (
        request.method == "POST"
        and (
            path == "agents"
            or re.fullmatch(r"agents/[A-Za-z0-9_-]+/message", path)
        )
    )
    if not allowed:
        return Response(status_code=404, content="Route not permitted")

    target = f"{SWITCH_ORIGIN}/{path}"
    if request.url.query:
        target += f"?{request.url.query}"

    headers = {}
    for name in ("authorization", "content-type", "accept"):
        value = request.headers.get(name)
        if value:
            headers[name] = value

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream = await client.request(
                method=request.method,
                url=target,
                headers=headers,
                content=await request.body(),
            )

        response_headers = {}
        for name in ("content-type",):
            value = upstream.headers.get(name)
            if value:
                response_headers[name] = value

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=response_headers,
        )
    except httpx.HTTPError:
        logger.warning("Switch HTTP forwarding failed.")
        return Response(status_code=502, content="Switch unavailable")


@app.websocket("/{path:path}")
async def relay_websocket(websocket: WebSocket, path: str):
    if not check_secret(
        websocket.headers.get("x-voidtrace-relay-secret")
    ):
        await websocket.close(code=1008)
        return

    if not re.fullmatch(
        r"agents/[A-Za-z0-9_-]+/connection/ws", path
    ):
        await websocket.close(code=1008)
        return

    query = websocket.url.query
    target = f"{SWITCH_WS_ORIGIN}/{path}"
    if query:
        target += f"?{query}"

    upstream_headers = {}
    authorization = websocket.headers.get("authorization")
    if authorization:
        upstream_headers["Authorization"] = authorization

    try:
        async with websockets.connect(
            target,
            additional_headers=upstream_headers,
            open_timeout=10,
            max_size=None,
        ) as upstream:
            await websocket.accept()

            async def client_to_switch():
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        break
                    if message.get("text") is not None:
                        await upstream.send(message["text"])
                    elif message.get("bytes") is not None:
                        await upstream.send(message["bytes"])

            async def switch_to_client():
                async for message in upstream:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)

            tasks = [
                asyncio.create_task(client_to_switch()),
                asyncio.create_task(switch_to_client()),
            ]
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    except Exception:
        logger.warning("Switch WebSocket forwarding failed.")
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
