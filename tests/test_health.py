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
    create_incident,
    health_check,
    list_incidents,
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


if __name__ == "__main__":
    unittest.main()
