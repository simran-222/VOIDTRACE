"""Integration Tests for FastAPI Health Endpoint and Incident APIs.

These tests call the route handler functions directly (without an HTTP server)
to avoid TestClient/ASGI lifecycle conflicts with background async tasks.
AUTO_CONNECT_SWITCH is forced to False before the app module is imported so
the global SwitchAdapter never starts its connection loop.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Disable Switch auto-connect BEFORE importing app.main so the global
# adapter singleton is never started during testing.
from app.config import settings
settings.AUTO_CONNECT_SWITCH = False

from app.database import init_db
from app.main import (
    IncidentCreateRequest,
    SimulateMessage,
    app,
    build_health,
    create_incident,
    health_check,
    list_incidents,
    simulate_switch_message,
    switch_adapter,
    verify_audit_log,
)


class TestHealthAndAPIs(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db = Path(self.temp_dir.name) / "test_api.db"
        settings.DATABASE_PATH = self.test_db
        settings.AUTO_CONNECT_SWITCH = False
        init_db(self.test_db)

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_health_endpoint(self) -> None:
        """health_check() must return healthy status, WAL mode, and performance stats."""
        data = await health_check()

        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["app"], "VOIDTRACE")
        self.assertIn("switch_core", data)
        self.assertIn("database", data)
        self.assertEqual(data["database"]["connected"], True)
        self.assertEqual(data["database"]["journal_mode"].lower(), "wal")
        self.assertIn("performance", data)
        self.assertGreaterEqual(data["performance"]["current_memory_kb"], 0)

    async def test_incident_lifecycle_api(self) -> None:
        """Incident creation and retrieval must work via the API handler functions."""
        create_payload = IncidentCreateRequest(
            title="Unauthorized Privilege Escalation",
            severity="HIGH",
            switch_room_id="room-secops-402",
        )
        created = await create_incident(create_payload)
        self.assertTrue(created["id"].startswith("INC-"))
        self.assertEqual(created["status"], "INVESTIGATING")

        incidents = await list_incidents()
        self.assertTrue(any(inc["id"] == created["id"] for inc in incidents))

    async def test_audit_verification_api(self) -> None:
        """Audit log integrity verification endpoint must pass on a fresh database."""
        data = await verify_audit_log()
        self.assertTrue(data["verified"], f"Audit log failed: {data['details']}")

    async def test_repeated_simulation_commands_are_not_duplicates(self) -> None:
        request = SimulateMessage(room_id="room-sim", body="@voidtrace status")
        first = await simulate_switch_message(request)
        second = await simulate_switch_message(request)
        self.assertFalse(first.get("duplicate", False))
        self.assertFalse(second.get("duplicate", False))
        self.assertTrue(first.get("handled"))
        self.assertTrue(second.get("handled"))

    async def test_test_ping_route_is_removed(self) -> None:
        paths = {getattr(route, "path", None) for route in app.routes}
        self.assertNotIn("/api/switch/test-ping", paths)


class TestSwitchStatusSemantics(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._previous_db = settings.DATABASE_PATH
        self._previous_autoconnect = settings.AUTO_CONNECT_SWITCH
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db = Path(self.temp_dir.name) / "test_switch_status.db"
        settings.DATABASE_PATH = self.test_db
        settings.AUTO_CONNECT_SWITCH = False
        init_db(self.test_db)
        self._saved = (
            switch_adapter.status,
            switch_adapter.agent_id,
            switch_adapter.api_key,
            switch_adapter.last_connected_at,
            switch_adapter.last_outbound_at,
            switch_adapter.last_inbound_at,
        )
        switch_adapter.status = "CONNECTED"
        switch_adapter.agent_id = "agent-status-test"
        switch_adapter.api_key = "key-status-test"

    async def asyncTearDown(self) -> None:
        (
            switch_adapter.status,
            switch_adapter.agent_id,
            switch_adapter.api_key,
            switch_adapter.last_connected_at,
            switch_adapter.last_outbound_at,
            switch_adapter.last_inbound_at,
        ) = self._saved
        settings.DATABASE_PATH = self._previous_db
        settings.AUTO_CONNECT_SWITCH = self._previous_autoconnect
        self.temp_dir.cleanup()

    def _core(self) -> dict:
        return build_health()["switch_core"]

    async def test_outbound_only_is_not_a_round_trip(self) -> None:
        now = datetime.now(UTC).isoformat()
        switch_adapter.last_connected_at = now
        switch_adapter.last_outbound_at = now
        switch_adapter.last_inbound_at = None
        core = self._core()
        self.assertTrue(core["outbound_verified"])
        self.assertFalse(core["inbound_verified"])
        self.assertFalse(core["real_switch_proven"])
        self.assertEqual(core["connection_claim"], "live_switch_outbound")

    async def test_inbound_only_is_not_a_round_trip(self) -> None:
        now = datetime.now(UTC).isoformat()
        switch_adapter.last_connected_at = now
        switch_adapter.last_outbound_at = None
        switch_adapter.last_inbound_at = now
        core = self._core()
        self.assertFalse(core["outbound_verified"])
        self.assertTrue(core["inbound_verified"])
        self.assertFalse(core["real_switch_proven"])
        self.assertEqual(core["connection_claim"], "live_switch_inbound")

    async def test_both_directions_are_a_round_trip(self) -> None:
        now = datetime.now(UTC).isoformat()
        switch_adapter.last_connected_at = now
        switch_adapter.last_outbound_at = now
        switch_adapter.last_inbound_at = now
        core = self._core()
        self.assertTrue(core["outbound_verified"])
        self.assertTrue(core["inbound_verified"])
        self.assertTrue(core["real_switch_proven"])
        self.assertEqual(core["connection_claim"], "live_switch_round_trip")

    async def test_stale_proof_clears_after_reconnect(self) -> None:
        now = datetime.now(UTC)
        switch_adapter.last_connected_at = now.isoformat()
        old = (now - timedelta(seconds=5)).isoformat()
        switch_adapter.last_outbound_at = old
        switch_adapter.last_inbound_at = old
        core = self._core()
        self.assertFalse(core["outbound_verified"])
        self.assertFalse(core["inbound_verified"])
        self.assertFalse(core["real_switch_proven"])
        self.assertEqual(core["connection_claim"], "live_switch_connected")

    async def test_dashboard_labels_distinguish_outbound_from_round_trip(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "app" / "static" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('if (claim === "live_switch_round_trip") return "Both directions verified";', source)
        self.assertIn('claim === "live_switch_outbound"', source)
        self.assertIn("Live outbound delivery", source)
        self.assertIn("Both Switch directions verified.", source)
        self.assertIn("Both Switch directions are not verified.", source)
        self.assertNotIn("Bidirectional Switch round-trip proven.", source)
        self.assertNotIn("Bidirectional Switch round-trip is not proven.", source)

    async def test_dashboard_token_controls_are_masked_and_session_only(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "app" / "static" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('apiToken: sessionStorage.getItem("voidtrace.apiToken") || "",', source)
        self.assertIn('id: "api-token",', source)
        self.assertIn('type: "password",', source)
        self.assertIn('headers.set("Authorization", `Bearer ${state.apiToken}`);', source)
        self.assertIn("if (response.status === 401) {", source)
        self.assertIn('sessionStorage.removeItem("voidtrace.apiToken");', source)
        self.assertIn('sessionStorage.setItem("voidtrace.apiToken", state.apiToken);', source)
        self.assertNotIn('localStorage.setItem("voidtrace.apiToken"', source)


if __name__ == "__main__":
    unittest.main()
