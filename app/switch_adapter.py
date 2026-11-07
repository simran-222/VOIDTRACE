"""VOIDTRACE Switch Platform Adapter.


Implements the verified Switch Core Agent Protocol:- Agent Registration via REST (POST /agents)
- WebSocket bidirectional stream (GET /agents/{id}/connection/ws)
- Heartbeat handling (Server ping -> Client pong)
- Event parsing & Mention detection (@voidtrace ping)
- Outgoing message delivery (POST /agents/{id}/message)

Security controls implemented here:
- Self-message suppression: bot never responds to its own output.
- Loop prevention: a message id is handled once, and automated senders get a
  bounded number of replies per room so two agents cannot ping each other
  without end.
- Human and agent pings are answered; the Switch platform and unidentified
  senders are rejected, and only the bot's own messages are dropped.
- Exact ping matching: only the precise "@voidtrace ping" command triggers a response.
- Incoming event validation: missing or malformed fields are rejected early.
- Fail-safe registration: absent token is detected before any network call.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import deque
from datetime import UTC, datetime
from typing import Any, Callable, Optional

import httpx
import websockets
import websockets.exceptions

from app.config import settings
from app.database import (
    get_db_connection,
    record_audit_event,
)

logger = logging.getLogger(__name__)

# The required standard response phrase for the Stage 1 verification test.
# Uses the Unicode em dash U+2014 (—) written as a literal escape to avoid
# any source-encoding ambiguity.
STAGE_1_VERIFICATION_RESPONSE = (
    "VOIDTRACE ONLINE \u2014 Switch connection verified. Backend healthy. SQLite connected."
)

# Valid event types from the verified Switch Core AgentEvent schema.
_VALID_EVENT_TYPES = frozenset({"message", "command", "room_join"})

# Close codes that mean our credentials are no longer accepted. After one of
# these the adapter drops its API key and registers again on the next attempt.
_AUTH_CLOSE_CODES = frozenset({4401, 4403, 4404, 4408, 4409})

_MAX_TRACKED_MESSAGE_IDS = 512
_MAX_TRACKED_OWN_EVENT_IDS = 256
_AUTO_REPLY_WINDOW_SECONDS = 10.0
_MAX_AUTO_REPLIES_PER_ROOM_WINDOW = 3
_AUTOMATED_SENDER_KINDS = frozenset({"agent", "platform"})
_VALID_SENDER_KINDS = frozenset({"user", "agent", "platform"})
# Switch's live message event omits sender_kind for humans and agents, so the
# transport participant id is used as a fallback to tell automated senders from
# people. These prefixes are the Switch Core participant-id conventions.
_AGENT_SENDER_PREFIX = "@switch-agent-"
_PLATFORM_SENDER_PREFIX = "@switch-admin"


class SwitchAdapter:
    """Manages connection, registration, and bidirectional communication with Switch Core."""

    def __init__(self, server_url: Optional[str] = None, ws_url: Optional[str] = None):
        self.server_url = (server_url or settings.SWITCH_SERVER_URL).rstrip("/")
        self.ws_url = (
            (ws_url or settings.SWITCH_WS_URL)
            .rstrip("/")
            .replace("http://", "ws://")
            .replace("https://", "wss://")
        )
        # Credentials are stored in memory only — never persisted to disk.
        self.agent_id: Optional[str] = None
        self.api_key: Optional[str] = None
        self.connection_id: str = str(uuid.uuid4())

        self.status: str = "DISCONNECTED"  # DISCONNECTED, REGISTERING, CONNECTING, CONNECTED, ERROR
        self.last_connected_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self.messages_received: int = 0
        self.messages_sent: int = 0
        # True only after this process completes register + a successful message post.
        self.round_trip_completed: bool = False

        self._client_factory: Optional[Callable[[], Any]] = None
        self._running: bool = False
        self._ws_client: Optional[websockets.WebSocketClientProtocol] = None
        self._loop_task: Optional[asyncio.Task] = None
        self._on_message_callback: Optional[Callable[[dict[str, Any]], Any]] = None

        self._processed_message_ids: deque[str] = deque()
        self._processed_message_id_set: set[str] = set()
        self._own_event_ids: deque[str] = deque()
        self._own_event_id_set: set[str] = set()
        self._auto_reply_times: dict[str, deque[float]] = {}

    @staticmethod
    def _remember_bounded(
        value: str, order: deque[str], seen: set[str], limit: int
    ) -> None:
        """Track value in a bounded FIFO so dedup memory cannot grow forever."""
        if not value or value in seen:
            return
        order.append(value)
        seen.add(value)
        while len(order) > limit:
            seen.discard(order.popleft())

    def _remember_own_event(self, event_id: str) -> None:
        self._remember_bounded(
            event_id,
            self._own_event_ids,
            self._own_event_id_set,
            _MAX_TRACKED_OWN_EVENT_IDS,
        )

    def _remember_processed_message(self, message_id: str) -> None:
        self._remember_bounded(
            message_id,
            self._processed_message_ids,
            self._processed_message_id_set,
            _MAX_TRACKED_MESSAGE_IDS,
        )

    def _is_own_message(
        self, sender: str, sender_name: str, sender_kind: str, message_id: str
    ) -> bool:
        """True when the event is output this adapter already posted.

        Three independent signals are checked: the event id returned when the
        message was posted, the adapter's own Switch agent id, and, as a
        fallback for messages posted before a restart, an agent message signed
        with this agent's own name.
        """
        if message_id and message_id in self._own_event_id_set:
            return True
        if self.agent_id and sender and sender == self.agent_id:
            return True
        if sender_kind == "agent":
            name = (sender_name or "").strip().casefold()
            own_names = {
                settings.AGENT_NAME.strip().casefold(),
                settings.AGENT_DISPLAY_NAME.strip().casefold(),
            }
            if name and name in own_names:
                return True
        return False

    @staticmethod
    def _resolve_sender_kind(sender: str, sender_kind: str | None) -> str:
        """Classify a sender as ``user``, ``agent``, ``platform`` or ``unknown``.

        Switch's live message event sets ``sender_kind`` only for the platform;
        human and agent messages arrive without it. Fall back to the transport
        participant-id convention so loop prevention and the authorized-sender
        guard still apply to live events.
        """
        kind = (sender_kind or "").strip().casefold()
        if kind in _VALID_SENDER_KINDS:
            return kind
        sender_id = (sender or "").strip().casefold()
        if sender_id.startswith(_AGENT_SENDER_PREFIX):
            return "agent"
        if sender_id.startswith(_PLATFORM_SENDER_PREFIX):
            return "platform"
        if sender_id:
            return "user"
        return "unknown"

    def _auto_reply_allowed(self, room_id: str) -> bool:
        """Cap replies to automated senders per room to break agent ping-pong."""
        now = time.monotonic()
        window = self._auto_reply_times.setdefault(room_id, deque())
        while window and now - window[0] > _AUTO_REPLY_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= _MAX_AUTO_REPLIES_PER_ROOM_WINDOW:
            return False
        window.append(now)
        return True

    def set_client_factory(self, factory: Optional[Callable[[], Any]]) -> None:
        """Test hook. Production uses a normal httpx client."""
        self._client_factory = factory

    def _open_client(self) -> Any:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.AsyncClient(timeout=10.0)

    def _redact(self, text: str) -> str:
        """Strip registration tokens and API keys from error text before logging or storage."""
        redacted = text
        token = settings.SWITCH_REGISTRATION_TOKEN
        if token:
            redacted = redacted.replace(token, "[redacted]")
        if self.api_key:
            redacted = redacted.replace(self.api_key, "[redacted]")
        return redacted[:500]

    def set_message_handler(self, handler: Callable[[dict[str, Any]], Any]) -> None:
        """Register custom handler for incoming events."""
        self._on_message_callback = handler

    async def _ensure_registered(self) -> None:
        """Register only when credentials are absent.

        Registration rotates the API key (``overwrite=True``), so it must not
        run on every reconnect: doing so would invalidate the key used by a
        live socket. Credentials are cleared only after an auth rejection.
        """
        if self.agent_id and self.api_key:
            return
        await self.register_agent()

    def _clear_credentials(self) -> None:
        """Drop stale credentials so the next attempt registers again."""
        self.agent_id = None
        self.api_key = None

    async def register_agent(self) -> tuple[str, str]:
        """Register VOIDTRACE with Switch Core using the verified schema.

        Fails fast if no registration token is configured so that the error
        is explicit rather than surfacing as an authentication failure from
        the Switch Core server.
        """
        registration_token = settings.SWITCH_REGISTRATION_TOKEN
        if not registration_token:
            err = (
                "SWITCH_REGISTRATION_TOKEN (or AGENT_REGISTRATION_TOKEN) is not set. "
                "Export it in the environment before attempting Switch registration."
            )
            logger.error(self._redact(err))
            self.status = "ERROR"
            self.last_error = self._redact(err)
            raise RuntimeError(err)

        logger.info("Registering VOIDTRACE agent with Switch Core at %s...", self.server_url)
        self.status = "REGISTERING"

        # Verified RegisterAgentRequest payload
        payload = {
            "name": settings.AGENT_NAME,
            "display_name": settings.AGENT_DISPLAY_NAME,
            "description": settings.AGENT_DESCRIPTION,
            "connector_type": "custom",
            "integration_profile": {
                "connection_model": "always_on",
                "message_exchange": True,
                "pre_invocation_mediation": [],
                "post_invocation_mediation": [],
                "event_reporting": [],
                "command_capabilities": {
                    "reset": "unsupported",
                    "compact": "unsupported",
                    "interrupt": "unsupported",
                },
            },
            "tools": [],
            "models": [],
            "metadata": {"platform": "voidtrace", "stage": "1"},
            "overwrite": True,
        }

        headers = {
            "Authorization": f"Bearer {registration_token}",
            "Content-Type": "application/json",
        }

        async with self._open_client() as client:
            resp = await client.post(f"{self.server_url}/agents", json=payload, headers=headers)
            if resp.status_code not in (200, 201):
                err = self._redact(
                    f"Switch registration failed: HTTP {resp.status_code} - {resp.text}"
                )
                logger.error(err)
                self.status = "ERROR"
                self.last_error = err
                raise RuntimeError(err)

            data = resp.json()
            self.agent_id = data["id"]
            # api_key kept in memory only — never written to SQLite.
            self.api_key = data["api_key"]
            logger.info("VOIDTRACE registered successfully. Agent ID: %s", self.agent_id)
            self.status = "REGISTERED"
            return self.agent_id, self.api_key

    async def send_message(self, room_id: str, content: str) -> str:
        """Send a message into a Switch room using the verified endpoint."""
        if not self.agent_id or not self.api_key:
            raise RuntimeError("Agent not registered. Cannot send message to Switch.")

        endpoint = f"{self.server_url}/agents/{self.agent_id}/message"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "room_id": room_id,
            "content": content,
            "metadata": {"sent_by": "voidtrace-stage1"},
        }

        async with self._open_client() as client:
            resp = await client.post(endpoint, json=payload, headers=headers)
            if resp.status_code != 200:
                err = self._redact(f"Failed to send message: HTTP {resp.status_code} - {resp.text}")
                logger.error(err)
                raise RuntimeError(err)

            res = resp.json()
            event_id = res.get("event_id", "unknown")
            self.messages_sent += 1
            if event_id and event_id != "unknown":
                self._remember_own_event(event_id)

            # Record in audit log
            conn = get_db_connection()
            try:
                with conn:
                    record_audit_event(
                        conn,
                        actor="VOIDTRACE_BOT",
                        action="SWITCH_MESSAGE_SENT",
                        details={"room_id": room_id, "event_id": event_id, "content": content},
                    )
            finally:
                conn.close()

            self.round_trip_completed = True
            logger.info("Message sent to Switch room %s: event_id=%s", room_id, event_id)
            return event_id

    def is_ping_request(self, body: str) -> bool:
        """Return True only when the message is exactly the @voidtrace ping command.

        Accepted forms (case-insensitive, surrounding whitespace ignored):
          @voidtrace ping
          /voidtrace ping
          !voidtrace ping
          voidtrace ping

        Bare "ping" without any voidtrace mention is NOT accepted to avoid
        false positives from general conversation.
        """
        cleaned = body.strip().lower()
        # Strip recognised mention prefixes then check for the bare word "ping"
        for prefix in ("@voidtrace ", "/voidtrace ", "!voidtrace ", "voidtrace "):
            if cleaned.startswith(prefix):
                remainder = cleaned[len(prefix):].strip()
                return remainder == "ping"
        return False

    async def handle_incoming_event(self, event_data: dict[str, Any]) -> None:
        """Process a verified AgentEvent payload and respond to pings.

        Validation steps performed before any action:
        1. event_type must be a known Switch Core event type.
        2. room_id must be non-empty.
        3. The bot's own messages are dropped, and a repeated message id is
           handled once, so it cannot answer itself or a replay.
        4. The Switch platform (unless it carries a person's authority) and
           unidentified senders are rejected before a ping is answered.
        5. Automated senders are rate limited per room to prevent reply loops.
        """
        # --- Validate event structure ---
        event_type = event_data.get("type")
        room_id = event_data.get("room_id")

        if event_type not in _VALID_EVENT_TYPES:
            logger.debug("Ignoring unknown event type: %r", event_type)
            return

        if not room_id:
            logger.warning("Received event with missing room_id; discarding.")
            return

        payload = event_data.get("payload")
        if not isinstance(payload, dict):
            logger.warning("Event payload is not a dict (type=%r); discarding.", type(payload))
            return

        logger.info("Switch event received: type=%s room_id=%s", event_type, room_id)

        if event_type != "message":
            return

        self.messages_received += 1

        body = payload.get("body", "")
        sender_name = payload.get("sender_name", "Unknown")
        sender = payload.get("sender", "")
        sender_kind = payload.get("sender_kind", "")
        message_id = str(payload.get("message_id") or "")
        resolved_kind = self._resolve_sender_kind(sender, sender_kind)
        on_behalf_of = payload.get("on_behalf_of")
        if resolved_kind == "platform" and on_behalf_of:
            # The platform is speaking for a person; judge that person instead.
            resolved_kind = "user"

        if self._is_own_message(sender, sender_name, sender_kind, message_id):
            logger.debug(
                "Ignoring own message: sender_kind=%r sender=%r message_id=%r",
                sender_kind,
                sender,
                message_id,
            )
            return

        if message_id:
            if message_id in self._processed_message_id_set:
                logger.debug("Ignoring duplicate message id: %r", message_id)
                return
            self._remember_processed_message(message_id)

        logger.info("Message in room %s from %s: %s", room_id, sender_name, body)

        # Record audit trace of incoming message
        conn = get_db_connection()
        try:
            with conn:
                record_audit_event(
                    conn,
                    actor=sender_name or sender or "unknown",
                    action="SWITCH_MESSAGE_RECEIVED",
                    details={"room_id": room_id, "body": body},
                )
        finally:
            conn.close()

        # Execute custom callback if registered
        if self._on_message_callback:
            try:
                await self._on_message_callback(event_data)
            except Exception as e:
                logger.exception("Error in user message callback: %s", e)

        # Respond only to the exact @voidtrace ping command
        if not self.is_ping_request(body):
            return

        if resolved_kind == "platform":
            logger.warning(
                "Rejected ping from the Switch platform in room %s: "
                "not an authorized human or agent.",
                room_id,
            )
            return

        if resolved_kind == "unknown":
            logger.warning(
                "Rejected ping from an unidentified sender in room %s.",
                room_id,
            )
            return

        if resolved_kind in _AUTOMATED_SENDER_KINDS and not self._auto_reply_allowed(room_id):
            logger.warning(
                "Suppressed automatic ping reply in room %s to prevent a reply loop.",
                room_id,
            )
            return

        logger.info(
            "Verified @voidtrace ping detected from %s. Dispatching response...",
            sender_name,
        )
        await self.send_message(room_id, STAGE_1_VERIFICATION_RESPONSE)

    async def _handle_ws_frame(self, frame: dict[str, Any], ws: Any) -> bool:
        """Dispatch one decoded WebSocket frame. Returns False to end the stream.

        Switch Core names an event frame after the event type itself
        (`message`, `command`, `room_join`), so those are dispatched directly;
        an `event` wrapper is still accepted for older payload shapes.
        """
        event = frame.get("event")
        data = frame.get("data", {})

        if event == "ping":
            await ws.send(json.dumps({"type": "pong"}))
        elif event == "connection_state":
            logger.info(
                "Switch connection established: generation=%s",
                data.get("generation"),
            )
        elif event in _VALID_EVENT_TYPES or event == "event":
            await self.handle_incoming_event(data)
        elif event == "evicted":
            logger.warning("Connection evicted: %s", data)
            return False
        return True

    async def _run_ws_loop(self) -> None:
        """Maintain persistent WebSocket connection with Switch Core."""
        delay = settings.SWITCH_RECONNECT_INITIAL_DELAY

        while self._running:
            try:
                await self._ensure_registered()
                ws_path = f"{self.ws_url}/agents/{self.agent_id}/connection/ws"
                params = (
                    f"?connection_id={self.connection_id}"
                    "&scope=all&filter=all&start_from=head"
                )
                full_ws_url = f"{ws_path}{params}"
                headers = {"Authorization": f"Bearer {self.api_key}"}

                logger.info(
                    "Opening WebSocket connection to Switch Core: %s",
                    self.ws_url,
                )
                self.status = "CONNECTING"

                async with websockets.connect(
                    full_ws_url,
                    additional_headers=headers,
                ) as ws:
                    self._ws_client = ws
                    self.status = "CONNECTED"
                    self.last_connected_at = datetime.now(UTC).isoformat()
                    self.last_error = None
                    delay = settings.SWITCH_RECONNECT_INITIAL_DELAY

                    logger.info(
                        "VOIDTRACE successfully connected to Switch Core WebSocket."
                    )

                    async for message in ws:
                        if not self._running:
                            break

                        try:
                            frame = json.loads(message)
                        except json.JSONDecodeError:
                            logger.warning("Unparseable frame: %r", message)
                            continue

                        if not await self._handle_ws_frame(frame, ws):
                            break

            except asyncio.CancelledError:
                logger.info("Switch WebSocket loop cancelled.")
                break

            except websockets.exceptions.InvalidStatus as exc:
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                self.status = "ERROR"
                self.last_error = self._redact(
                    f"Switch WebSocket handshake rejected (HTTP {status_code})."
                )
                if status_code in (401, 403, 404):
                    self._clear_credentials()
                logger.warning("%s Retrying in %.1fs...", self.last_error, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, settings.SWITCH_RECONNECT_MAX_DELAY)

            except websockets.exceptions.ConnectionClosed as exc:
                close_code = exc.rcvd.code if exc.rcvd is not None else None
                self.status = "ERROR"
                self.last_error = self._redact(
                    f"Switch WebSocket closed (code {close_code})."
                )
                if close_code in _AUTH_CLOSE_CODES:
                    self._clear_credentials()
                logger.warning("%s Retrying in %.1fs...", self.last_error, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, settings.SWITCH_RECONNECT_MAX_DELAY)

            except Exception as exc:
                self.status = "ERROR"
                self.last_error = self._redact(str(exc))
                logger.warning(
                    "Switch connection attempt failed: %s. Retrying in %.1fs...",
                    self.last_error,
                    delay,
                )
                await asyncio.sleep(delay)
                delay = min(
                    delay * 2,
                    settings.SWITCH_RECONNECT_MAX_DELAY,
                )

            finally:
                self._ws_client = None
                if self.status == "CONNECTED":
                    self.status = "DISCONNECTED"

    async def start(self) -> None:
        """Start the Switch adapter background worker."""
        if self._running:
            return

        if not settings.SWITCH_REGISTRATION_TOKEN:
            self.status = "ERROR"
            self.last_error = (
                "SWITCH_REGISTRATION_TOKEN (or AGENT_REGISTRATION_TOKEN) is not set. "
                "Switch connection is not configured."
            )
            logger.warning(
                "Switch adapter not started: registration token is not configured."
            )
            return

        self._running = True
        self._loop_task = asyncio.create_task(self._run_ws_loop())

    async def stop(self) -> None:
        """Stop the Switch adapter worker gracefully."""
        self._running = False
        if self._ws_client:
            try:
                await self._ws_client.close()
            except Exception:
                pass
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        self.status = "DISCONNECTED"
        logger.info("Switch adapter stopped.")
