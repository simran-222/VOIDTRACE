"""Mock Switch protocol round-trip. This does not prove a live Switch connection."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from app.config import settings
from app.database import init_db
from app.switch_adapter import SwitchAdapter
from tests.mock_switch_server import MockSwitchCoreServer


class TestMockSwitchRoundTrip(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._previous_db = settings.DATABASE_PATH
        self._previous_token = settings.SWITCH_REGISTRATION_TOKEN
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "switch.db"
        settings.DATABASE_PATH = self.db_path
        settings.SWITCH_REGISTRATION_TOKEN = "unit-test-token"
        init_db(self.db_path)
        self.mock = MockSwitchCoreServer()
        self.transport = httpx.ASGITransport(app=self.mock.app)

    async def asyncTearDown(self) -> None:
        settings.DATABASE_PATH = self._previous_db
        settings.SWITCH_REGISTRATION_TOKEN = self._previous_token
        self.temp_dir.cleanup()

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, base_url="http://switch.mock")

    async def test_register_and_message_round_trip_against_mock(self) -> None:
        adapter = SwitchAdapter(server_url="http://switch.mock", ws_url="ws://switch.mock")
        adapter.set_client_factory(self._client)
        agent_id, api_key = await adapter.register_agent()
        self.assertTrue(agent_id.startswith("mock-agent-"))
        self.assertTrue(api_key.startswith("mock-key-"))
        self.assertNotIn(api_key, adapter.last_error or "")
        event_id = await adapter.send_message("room-security", "VOIDTRACE mock round trip")
        self.assertTrue(event_id.startswith("evt-"))
        self.assertEqual(len(self.mock.posted_messages), 1)
        self.assertEqual(self.mock.posted_messages[0]["room_id"], "room-security")
        self.assertTrue(adapter.round_trip_completed)
        self.assertIn("switch.mock", adapter.server_url)

    async def test_redacts_registration_token(self) -> None:
        adapter = SwitchAdapter()
        leaked = adapter._redact(f"failure including {settings.SWITCH_REGISTRATION_TOKEN}")
        self.assertNotIn(settings.SWITCH_REGISTRATION_TOKEN, leaked)
        self.assertIn("[redacted]", leaked)

    async def test_ensure_registered_registers_once(self) -> None:
        adapter = SwitchAdapter(server_url="http://switch.mock", ws_url="ws://switch.mock")
        adapter.set_client_factory(self._client)

        await adapter._ensure_registered()
        first_agent_id = adapter.agent_id
        self.assertTrue(first_agent_id)
        self.assertTrue(adapter.api_key)

        await adapter._ensure_registered()
        self.assertEqual(adapter.agent_id, first_agent_id)
        self.assertEqual(len(self.mock.registered_agents), 1)

    async def test_clear_credentials_forces_reregistration(self) -> None:
        adapter = SwitchAdapter(server_url="http://switch.mock", ws_url="ws://switch.mock")
        adapter.set_client_factory(self._client)

        await adapter._ensure_registered()
        first_agent_id = adapter.agent_id

        adapter._clear_credentials()
        self.assertIsNone(adapter.agent_id)
        self.assertIsNone(adapter.api_key)

        await adapter._ensure_registered()
        self.assertNotEqual(adapter.agent_id, first_agent_id)
        self.assertEqual(len(self.mock.registered_agents), 2)

    async def test_start_registers_before_opening_socket(self) -> None:
        adapter = SwitchAdapter(server_url="http://switch.mock", ws_url="ws://switch.mock")
        adapter.set_client_factory(self._client)

        with patch(
            "app.switch_adapter.websockets.connect",
            side_effect=OSError("socket unavailable in test"),
        ):
            await adapter.start()
            try:
                for _ in range(50):
                    if adapter.agent_id:
                        break
                    await asyncio.sleep(0.01)
            finally:
                await adapter.stop()

        self.assertTrue(adapter.agent_id)
        self.assertEqual(len(self.mock.registered_agents), 1)

    async def test_start_without_token_does_not_register(self) -> None:
        previous = settings.SWITCH_REGISTRATION_TOKEN
        try:
            settings.SWITCH_REGISTRATION_TOKEN = ""
            adapter = SwitchAdapter()
            await adapter.start()
            self.assertFalse(adapter._running)
            self.assertIsNone(adapter._loop_task)
            self.assertEqual(adapter.status, "ERROR")
        finally:
            settings.SWITCH_REGISTRATION_TOKEN = previous


if __name__ == "__main__":
    unittest.main()
