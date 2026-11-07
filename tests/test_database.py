"""Unit Tests for SQLite WAL Mode, Incident Models, and Audit Ledger Integrity."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import (
    _GENESIS_PAYLOAD,
    _GENESIS_PREV_HASH,
    get_db_connection,
    init_db,
    record_audit_event,
    verify_ledger_integrity,
)


class TestDatabaseModule(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_voidtrace.db"
        init_db(self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # ── WAL mode ─────────────────────────────────────────────────────────────

    def test_wal_mode_enabled(self) -> None:
        """SQLite must be initialized in WAL mode."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            self.assertEqual(mode.lower(), "wal")
        finally:
            conn.close()

    # ── Credential persistence removed ───────────────────────────────────────

    def test_credentials_not_persisted_to_sqlite(self) -> None:
        """switch_agent_state table must exist (schema preserved) but contain no rows."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM switch_agent_state;")
            count = cursor.fetchone()["cnt"]
            self.assertEqual(count, 0, "No credentials should be persisted to SQLite.")
        finally:
            conn.close()

    # ── Genesis block verification ────────────────────────────────────────────

    def test_genesis_block_exists_and_hash_is_correct(self) -> None:
        """The genesis block must exist and carry the correct fixed SHA-256 hash."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT action, prev_hash, entry_hash FROM audit_events WHERE id = 1;"
            )
            row = cursor.fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(row, "Genesis block must be seeded during init_db().")
        self.assertEqual(row["action"], "GENESIS")
        self.assertEqual(row["prev_hash"], _GENESIS_PREV_HASH)
        expected_hash = hashlib.sha256(_GENESIS_PAYLOAD.encode()).hexdigest()
        self.assertEqual(
            row["entry_hash"],
            expected_hash,
            f"Genesis hash mismatch: expected {expected_hash!r}, got {row['entry_hash']!r}",
        )

    def test_genesis_block_tampering_detected(self) -> None:
        """Altering the genesis entry_hash must be caught by verify_ledger_integrity()."""
        conn = get_db_connection(self.db_path)
        try:
            conn.execute(
                "UPDATE audit_events SET entry_hash = ? WHERE action = 'GENESIS';",
                ("a" * 64,),
            )
            conn.commit()
        finally:
            conn.close()

        ok, msg = verify_ledger_integrity(self.db_path)
        self.assertFalse(ok, "Genesis hash tamper must be detected.")
        # Either "genesis block hash mismatch" or "broken chain link" is acceptable
        self.assertTrue(
            "genesis" in msg.lower() or "broken chain" in msg.lower() or "mismatch" in msg.lower(),
            f"Unexpected message: {msg!r}",
        )

    # ── Hash chain integrity ──────────────────────────────────────────────────

    def test_audit_ledger_hash_chain_integrity(self) -> None:
        """Untampered audit records must pass hash chain verification."""
        conn = get_db_connection(self.db_path)
        try:
            with conn:
                record_audit_event(conn, "TEST_ACTOR", "ACTION_A", {"key": "val1"})
                record_audit_event(conn, "TEST_ACTOR", "ACTION_B", {"key": "val2"})
                record_audit_event(conn, "TEST_ACTOR", "ACTION_C", {"key": "val3"})
        finally:
            conn.close()

        ok, msg = verify_ledger_integrity(self.db_path)
        self.assertTrue(ok, f"Expected integrity check to pass: {msg}")

    def test_audit_ledger_tampering_detection(self) -> None:
        """Altering a past audit record must be immediately detected."""
        conn = get_db_connection(self.db_path)
        try:
            with conn:
                record_audit_event(conn, "ANALYST", "APPROVE", {"plan": "R-1"})
                record_audit_event(conn, "ANALYST", "EXECUTE", {"plan": "R-1"})

            # Intentionally tamper with a historical record
            conn.execute(
                "UPDATE audit_events SET details_json = '{\"plan\": \"MALICIOUS\"}' "
                "WHERE action = 'APPROVE';"
            )
            conn.commit()
        finally:
            conn.close()

        ok, msg = verify_ledger_integrity(self.db_path)
        self.assertFalse(ok, "Integrity check must fail when historical data is tampered with.")
        self.assertIn("tampering detected", msg.lower())

    def test_chain_link_tampering_detected(self) -> None:
        """Altering a prev_hash to break the chain must be detected."""
        conn = get_db_connection(self.db_path)
        try:
            with conn:
                record_audit_event(conn, "ACTOR", "ACTION_X", {})
                record_audit_event(conn, "ACTOR", "ACTION_Y", {})

            # Break the chain by corrupting prev_hash on the last non-genesis record
            conn.execute(
                "UPDATE audit_events SET prev_hash = ? "
                "WHERE id = (SELECT MAX(id) FROM audit_events);",
                ("b" * 64,),
            )
            conn.commit()
        finally:
            conn.close()

        ok, msg = verify_ledger_integrity(self.db_path)
        self.assertFalse(ok, "Chain break must be detected.")
        self.assertTrue(
            "broken chain" in msg.lower() or "tampering detected" in msg.lower(),
            f"Unexpected message: {msg!r}",
        )

    # ── Multi-incident isolation ──────────────────────────────────────────────

    def test_multi_incident_creation(self) -> None:
        """Isolated records for multiple concurrent incidents must be stored and retrieved."""
        conn = get_db_connection(self.db_path)
        try:
            with conn:
                conn.execute("""
                    INSERT INTO incidents
                        (id, title, severity, status, switch_room_id, created_at)
                    VALUES ('INC-001', 'IAM Intrusion', 'HIGH', 'INVESTIGATING',
                            'room-alpha', '2026-11-06T12:00:00Z');
                """)
                conn.execute("""
                    INSERT INTO incidents
                        (id, title, severity, status, switch_room_id, created_at)
                    VALUES ('INC-002', 'Data Exfiltration', 'CRITICAL', 'INVESTIGATING',
                            'room-beta', '2026-11-06T12:05:00Z');
                """)

            cursor = conn.execute("SELECT id, title, switch_room_id FROM incidents ORDER BY id ASC;")
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["id"], "INC-001")
            self.assertEqual(rows[1]["id"], "INC-002")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
