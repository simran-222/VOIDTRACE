"""VOIDTRACE Database Module.

Provides SQLite connection management in WAL (Write-Ahead Logging) mode,
basic schema initialization, and multi-incident isolation structures.

Credentials are NEVER persisted to SQLite.  The switch_agent_state table
definition is kept so that existing databases are not broken, but no code
in this module reads or writes credentials to it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

from app.config import settings

logger = logging.getLogger(__name__)

# The fixed payload that uniquely identifies the genesis audit record.
_GENESIS_PAYLOAD = "GENESIS_VOIDTRACE_SECURITY_AUDIT_LEDGER"
_GENESIS_PREV_HASH = "0" * 64


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Create and configure a SQLite connection with WAL mode enabled."""
    target_path = db_path or settings.DATABASE_PATH
    conn = sqlite3.connect(str(target_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Configure WAL mode and performance pragmas
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize SQLite tables for incidents, audit events, and switch sessions."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            # 1. Incidents Table (Foundation for Requirement 10: Multi-incident isolation)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'MEDIUM',
                    status TEXT NOT NULL DEFAULT 'INVESTIGATING',
                    switch_room_id TEXT,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    metadata_json TEXT DEFAULT '{}'
                );
            """)

            # 2. Tamper-Evident Audit Ledger (Foundation for Requirement 5 & 8)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );
            """)

            # 3. Switch Agent Registration State — schema preserved for existing DBs.
            #    Credentials are kept in memory only; this table is intentionally unused
            #    for new writes.  Do NOT drop it so existing databases remain intact.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS switch_agent_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    agent_id TEXT NOT NULL,
                    api_key TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );
            """)

            # 4. Switch Session Log
            conn.execute("""
                CREATE TABLE IF NOT EXISTS switch_sessions (
                    connection_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    connected_at TEXT NOT NULL,
                    disconnected_at TEXT,
                    status TEXT NOT NULL
                );
            """)

            # 5. Simulated ground truth. One row. Never stores real credentials.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sim_world (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # 6. Incident-scoped resource allow-list enforced by SECURITY.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_scopes (
                    incident_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    granted_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY (incident_id, resource),
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );
            """)

            # 7. Evidence collected through permitted tools.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    trust TEXT NOT NULL,
                    content_json TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );
            """)

            # 8. VOIDTRACE findings. Facts must cite evidence ids.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    category TEXT NOT NULL,
                    statement TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    confidence_reason TEXT NOT NULL,
                    uncertainty TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );
            """)

            # 9. Risk and business-impact assessment.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    incident_id TEXT PRIMARY KEY,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    headline TEXT NOT NULL,
                    drivers_json TEXT NOT NULL,
                    business_impact_json TEXT NOT NULL,
                    uncertainty_json TEXT NOT NULL,
                    confidence_json TEXT NOT NULL,
                    suppressed_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );
            """)

            # 10. SECURITY decisions.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_decisions (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    actor TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    effect TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    requires_approval INTEGER NOT NULL,
                    policy_fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

            # 11. Single-use capability tokens. Only the hash is stored.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS capabilities (
                    token_hash TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    approval_id TEXT,
                    policy_fingerprint TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    used_at TEXT
                );
            """)

            # 12. Human approval lifecycle.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    conflict_group TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    expected_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    decided_at TEXT,
                    approver TEXT,
                    decision_channel TEXT,
                    decision_reason TEXT,
                    executed_at TEXT,
                    verification_result TEXT,
                    verification_json TEXT,
                    notified_via TEXT,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );
            """)

            # 13. Performance samples.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS performance_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    incident_id TEXT,
                    recorded_at TEXT NOT NULL
                );
            """)

            # 14. Inbound Switch / simulation message ids (duplicate suppression).
            conn.execute("""
                CREATE TABLE IF NOT EXISTS switch_inbox (
                    message_id TEXT PRIMARY KEY,
                    room_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_events(incident_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_incident ON findings(incident_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_incident ON policy_decisions(incident_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_incident ON approvals(incident_id);")

            # Seed genesis block in audit log if the table is empty
            cursor = conn.execute("SELECT COUNT(*) as count FROM audit_events;")
            if cursor.fetchone()["count"] == 0:
                genesis_time = datetime.now(UTC).isoformat()
                genesis_hash = hashlib.sha256(_GENESIS_PAYLOAD.encode()).hexdigest()
                conn.execute("""
                    INSERT INTO audit_events
                        (incident_id, timestamp, actor, action, details_json, prev_hash, entry_hash)
                    VALUES (NULL, ?, 'SYSTEM', 'GENESIS', '{}', ?, ?);
                """, (genesis_time, _GENESIS_PREV_HASH, genesis_hash))

        logger.info("SQLite database initialized successfully in WAL mode.")
    finally:
        conn.close()


def get_latest_audit_hash(conn: sqlite3.Connection) -> str:
    """Retrieve the entry hash of the most recent audit record."""
    cursor = conn.execute("SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1;")
    row = cursor.fetchone()
    return row["entry_hash"] if row else _GENESIS_PREV_HASH


def record_audit_event(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    details: dict[str, Any],
    incident_id: Optional[str] = None,
) -> str:
    """Append a tamper-evident audit record with SHA-256 hash chaining."""
    prev_hash = get_latest_audit_hash(conn)
    timestamp = datetime.now(UTC).isoformat()
    details_str = json.dumps(details, sort_keys=True)

    # Calculate chained hash — identical formula used by verify_ledger_integrity()
    payload = f"{timestamp}:{incident_id or ''}:{actor}:{action}:{details_str}:{prev_hash}"
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    conn.execute("""
        INSERT INTO audit_events
            (incident_id, timestamp, actor, action, details_json, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (incident_id, timestamp, actor, action, details_str, prev_hash, entry_hash))

    return entry_hash


def verify_ledger_integrity(db_path: Optional[Path] = None) -> tuple[bool, str]:
    """Verify that no audit records have been tampered with or modified.

    Checks:
    1. Genesis entry has the expected fixed hash.
    2. Every subsequent entry's prev_hash equals the previous entry's entry_hash.
    3. Every entry's stored entry_hash matches the recomputed hash of its fields.

    Limitations: this is tamper-*evident*, not tamper-*proof*.  An attacker
    with direct database write access can rebuild the entire hash chain.  The
    chain is meaningful as an integrity signal when the database file itself is
    protected by OS permissions and monitored externally.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, incident_id, timestamp, actor, action, details_json, prev_hash, entry_hash "
            "FROM audit_events ORDER BY id ASC;"
        )
        rows = cursor.fetchall()
        if not rows:
            return True, "Audit log is empty."

        for i, row in enumerate(rows):
            if i == 0:
                # --- Verify genesis block independently ---
                if row["action"] != "GENESIS":
                    return False, f"First audit record is not a genesis block (action={row['action']!r})"
                if row["prev_hash"] not in ("0", _GENESIS_PREV_HASH):
                    return (
                        False,
                        f"Genesis block has unexpected prev_hash: {row['prev_hash']!r}",
                    )
                expected_genesis_hash = hashlib.sha256(_GENESIS_PAYLOAD.encode()).hexdigest()
                if row["entry_hash"] != expected_genesis_hash:
                    return (
                        False,
                        f"Genesis block hash mismatch: "
                        f"stored={row['entry_hash']!r}, expected={expected_genesis_hash!r}",
                    )
                prev_hash = row["entry_hash"]
                continue

            # --- Verify chain link ---
            if row["prev_hash"] != prev_hash:
                return (
                    False,
                    f"Broken chain link at audit record id {row['id']}: "
                    f"expected prev_hash {prev_hash}, found {row['prev_hash']}",
                )

            # --- Verify entry hash ---
            expected_payload = (
                f"{row['timestamp']}:{row['incident_id'] or ''}:"
                f"{row['actor']}:{row['action']}:{row['details_json']}:{row['prev_hash']}"
            )
            computed_hash = hashlib.sha256(expected_payload.encode()).hexdigest()
            if row["entry_hash"] != computed_hash:
                return (
                    False,
                    f"Data tampering detected at audit record id {row['id']}: "
                    f"stored hash {row['entry_hash']} != computed {computed_hash}",
                )

            prev_hash = row["entry_hash"]

        return True, f"Integrity verified across {len(rows)} audit records."
    finally:
        conn.close()
