"""Operation ShadowCredential — the incident VOIDTRACE refuses to guess through.

The default command uses an isolated database file. It will not delete voidtrace.db.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any, Optional

from app.config import settings
from app.database import get_db_connection, init_db, verify_ledger_integrity
from app.workflow import (
    create_incident_record,
    decide,
    execute_approved,
    incident_bundle,
    investigate,
    publish_incident,
    reseed_simulation,
)

SHADOW_REPORT = (
    "Operation ShadowCredential: On host pay-worker-04 a suspicious process may have "
    "read IAM credential cred-shadow-7f3a used by svc-payments-reader. "
    "Please investigate. Do not guess."
)

VAGUE_REPORT = "We heard something might be wrong somewhere. Please investigate and do not guess."


def protected_databases() -> set[Path]:
    paths = {Path("voidtrace.db").resolve()}
    try:
        paths.add(Path(settings.DATABASE_PATH).resolve())
    except Exception:
        pass
    return paths


def assert_isolated_database(path: Path) -> None:
    resolved = path.resolve()
    if resolved in protected_databases() or resolved.name == "voidtrace.db":
        raise SystemExit(
            "Refusing to rebuild the user database. "
            "Choose a different --database path. voidtrace.db was not modified."
        )


async def run_shadow_scenario(
    *,
    auto_approve: bool = False,
    approver: str = "Avery Chen",
    channel: str = "local_operator",
    simulation: bool = True,
) -> dict[str, Any]:
    """Seed the simulation, open two incidents, and optionally finish the approved path.

    `simulation=True` means outbound text is labelled as not sent through Switch.
    """
    reseed = reseed_simulation()
    vague_id = _open_incident(
        title="Unscoped rumor",
        severity="LOW",
        report=VAGUE_REPORT,
        channel=channel,
    )
    investigate(vague_id)
    shadow_id = _open_incident(
        title="Operation ShadowCredential",
        severity="HIGH",
        report=SHADOW_REPORT,
        channel=channel,
    )
    investigate(shadow_id)
    published = await publish_incident(shadow_id, "room-shadow-credential", simulation=simulation)
    executed: list[dict[str, Any]] = []
    if auto_approve:
        for approval in list(published["approvals"]):
            decide(approval["id"], "approve", approver, channel=channel, comment="Local operator approval")
            executed.append(execute_approved(approval["id"]))
        published = await publish_incident(shadow_id, "room-shadow-credential", simulation=simulation)
    shadow = incident_bundle(shadow_id)
    vague = incident_bundle(vague_id)
    integrity_ok, integrity_message = verify_ledger_integrity()
    return {
        "real_switch_proven": False,
        "simulation_reseeded": reseed["simulation_reseeded"],
        "user_database_wiped": False,
        "incidents_deleted": 0,
        "channel": channel,
        "shadow_incident_id": shadow_id,
        "vague_incident_id": vague_id,
        "shadow": shadow,
        "vague": vague,
        "executed": executed,
        "audit_verified": integrity_ok,
        "audit_details": integrity_message,
        "delivery": published.get("delivery"),
    }


def _open_incident(*, title: str, severity: str, report: str, channel: str) -> str:
    conn = get_db_connection()
    try:
        with conn:
            created = create_incident_record(
                conn,
                title=title,
                severity=severity,
                switch_room_id="room-shadow-credential",
                metadata={"report": report, "channel": channel},
                actor="Avery Chen",
            )
        return created["id"]
    finally:
        conn.close()


def _prepare_isolated(path: Path) -> None:
    assert_isolated_database(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            candidate.unlink()
    settings.DATABASE_PATH = path
    init_db(path)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the VOIDTRACE signature demo on an isolated database.")
    parser.add_argument("--database", default="demo_data/voidtrace_demo.db")
    parser.add_argument("--no-approve", action="store_true", help="Stop after the proposal. Do not apply a local approval.")
    args = parser.parse_args(argv)
    target = Path(args.database)
    _prepare_isolated(target)
    result = asyncio.run(
        run_shadow_scenario(
            auto_approve=not args.no_approve,
            approver="Avery Chen",
            channel="local_operator_cli",
            simulation=True,
        )
    )
    shadow = result["shadow"]
    kinds = {finding["kind"] for finding in shadow["findings"]}
    categories = {finding["category"] for finding in shadow["findings"]}
    verified = [item for item in result["executed"] if item.get("verification_result") == "VERIFIED"]
    print("VOIDTRACE signature demo")
    print(f"Database: {target.resolve()}")
    print("User database wiped: false")
    print("Real Switch connection: not claimed")
    print(f"Shadow incident: {result['shadow_incident_id']} status={shadow['incident']['status']}")
    print(f"Vague incident: {result['vague_incident_id']} status={result['vague']['incident']['status']}")
    print(f"Verified actions: {len(verified)}")
    print(f"Audit: {result['audit_details']}")
    ok = (
        result["audit_verified"]
        and "unknown" in kinds
        and "injection" in categories
        and "contradiction" in categories
        and (args.no_approve or (shadow["incident"]["status"] == "RESOLVED" and len(verified) >= 2))
        and result["vague"]["incident"]["status"] == "INSUFFICIENT_EVIDENCE"
    )
    print("Demo result:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
