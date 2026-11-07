"""VOIDTRACE FastAPI application.

Trust nothing. Verify everything.
SECURITY gates simulated tools. VOIDTRACE cites evidence. Switch state is reported honestly.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Literal, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel, Field

from app.config import settings
from app.controls import control_board
from app.database import (
    get_db_connection,
    init_db,
    record_audit_event,
    verify_ledger_integrity,
)
from app.demo import run_shadow_scenario
from app.errors import SecurityBypassError, SecurityDenied, WorkflowError
from app.security import security
from app.performance import get_memory_metrics, recent_timings
from app.switch_adapter import STAGE_1_VERIFICATION_RESPONSE, SwitchAdapter
from app.workflow import (
    create_incident_record,
    decide,
    delivery,
    execute_approved,
    handle_operator_event,
    incident_bundle,
    investigate,
    list_incident_rows,
    priority_list,
    publish_incident,
    verify_approval,
    verify_evidence_integrity,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("voidtrace")

STATIC_DIR = Path(__file__).resolve().parent / "static"
switch_adapter = SwitchAdapter()


async def _send_to_switch(room_id: str, content: str) -> str:
    return await switch_adapter.send_message(room_id, content)


def _switch_is_live() -> bool:
    return switch_adapter.status == "CONNECTED" and bool(switch_adapter.agent_id and switch_adapter.api_key)


async def _on_switch_event(event: dict[str, Any]) -> None:
    channel = "switch" if _switch_is_live() else "switch_unverified"
    await handle_operator_event(event, channel=channel)


delivery.configure(_send_to_switch, _switch_is_live)
switch_adapter.set_message_handler(_on_switch_event)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Open the database, record startup, and optionally connect to Switch."""
    logger.info("Initializing VOIDTRACE %s", settings.APP_VERSION)
    init_db()
    conn = get_db_connection()
    try:
        with conn:
            record_audit_event(
                conn,
                actor="SYSTEM",
                action="VOIDTRACE_BACKEND_STARTED",
                details={"version": settings.APP_VERSION, "env": "local"},
            )
            record_audit_event(
                conn,
                actor="SECURITY",
                action="SECURITY_SEALED",
                details={"policy_fingerprint": security.fingerprint(), "intact": security.intact()},
            )
    finally:
        conn.close()

    if settings.AUTO_CONNECT_SWITCH:
        await switch_adapter.start()
        logger.info("Switch adapter started. Registration runs only when a token is configured.")
    else:
        logger.info("AUTO_CONNECT_SWITCH is False; Switch adapter was not started.")
    yield
    logger.info("Shutting down VOIDTRACE.")
    await switch_adapter.stop()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Trust nothing. Verify everything. Defensive security incident investigation and response.",
    lifespan=lifespan,
)


@app.exception_handler(WorkflowError)
async def handle_workflow_error(_request: Any, exc: WorkflowError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message, "code": exc.code})


@app.exception_handler(SecurityDenied)
async def handle_denied(_request: Any, exc: SecurityDenied) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": exc.decision.get("reason", "denied"), "decision": exc.decision},
    )


@app.exception_handler(SecurityBypassError)
async def handle_bypass(_request: Any, exc: SecurityBypassError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc), "code": "bypass_blocked"})


def build_health() -> dict[str, Any]:
    """Health payload. Switch is reported separately and is not implied to be live."""
    conn = get_db_connection()
    try:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        incidents_count = conn.execute("SELECT COUNT(*) AS cnt FROM incidents;").fetchone()["cnt"]
        audit_count = conn.execute("SELECT COUNT(*) AS cnt FROM audit_events;").fetchone()["cnt"]
    finally:
        conn.close()
    integrity_ok, integrity_msg = verify_ledger_integrity()
    evidence_ok, evidence_msg = verify_evidence_integrity()
    perf = get_memory_metrics()
    live = _switch_is_live()
    proven = live and switch_adapter.round_trip_completed
    if proven:
        claim = "live_switch_round_trip"
    elif live:
        claim = "live_switch_connected"
    else:
        claim = "not_connected"
    overall = "healthy" if integrity_ok and security.intact() else "degraded"
    return {
        "status": overall,
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "tagline": "Trust nothing. Verify everything.",
        "switch_core": {
            "target_server": settings.SWITCH_SERVER_URL,
            "status": switch_adapter.status,
            "agent_id": switch_adapter.agent_id,
            "last_connected_at": switch_adapter.last_connected_at,
            "messages_received": switch_adapter.messages_received,
            "messages_sent": switch_adapter.messages_sent,
            "last_error": switch_adapter.last_error,
            "registration_token_configured": bool(settings.SWITCH_REGISTRATION_TOKEN),
            "connection_claim": claim,
            "real_switch_proven": proven,
            "honesty": _switch_honesty(claim),
        },
        "database": {
            "connected": True,
            "journal_mode": journal_mode,
            "incidents_count": incidents_count,
            "audit_events_count": audit_count,
            "audit_integrity_verified": integrity_ok,
            "audit_integrity_details": integrity_msg,
            "evidence_integrity_verified": evidence_ok,
            "evidence_integrity_details": evidence_msg,
        },
        "components": {
            "security": "enforcing" if security.intact() else "fail_closed",
            "investigation": "ready",
            "verification": "independent",
            "switch": claim,
            "database": "ok" if integrity_ok else "degraded",
        },
        "performance": {
            "current_memory_kb": perf.current_memory_kb,
            "peak_memory_kb": perf.peak_memory_kb,
            "timestamp": perf.timestamp_iso,
            "operations": recent_timings(20),
        },
    }


def _switch_honesty(claim: str) -> str:
    if claim == "live_switch_round_trip":
        return "A live Switch connection completed registration and a message post."
    if claim == "live_switch_connected":
        return "The Switch socket is connected. A message round-trip has not completed yet."
    return "Switch is not connected. Local simulation is not a Switch connection."


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> dict[str, Any]:
    """Component status, ledger integrity, Switch claim, and memory."""
    return build_health()


class IncidentCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: str = "MEDIUM"
    switch_room_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    report: Optional[str] = None


@app.get("/api/incidents")
async def list_incidents() -> list[dict[str, Any]]:
    """List tracked incidents."""
    return list_incident_rows()


@app.post("/api/incidents", status_code=status.HTTP_201_CREATED)
async def create_incident(req: IncidentCreateRequest) -> dict[str, Any]:
    """Create an incident. This does not start simulated changes."""
    metadata = dict(req.metadata)
    if req.report:
        metadata["report"] = req.report
    elif "report" not in metadata:
        metadata["report"] = req.title
    metadata.setdefault("channel", "api")
    conn = get_db_connection()
    try:
        with conn:
            created = create_incident_record(
                conn,
                title=req.title.strip(),
                severity=req.severity.upper(),
                switch_room_id=req.switch_room_id,
                metadata=metadata,
            )
        return created
    finally:
        conn.close()


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    try:
        return incident_bundle(incident_id)
    except WorkflowError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@app.post("/api/incidents/{incident_id}/investigate")
async def investigate_incident(incident_id: str) -> dict[str, Any]:
    try:
        investigate(incident_id)
        bundle = incident_bundle(incident_id)
        room = bundle["incident"].get("switch_room_id")
        return await publish_incident(incident_id, room, simulation=False)
    except WorkflowError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@app.get("/api/incidents/{incident_id}/evidence")
async def get_evidence(incident_id: str) -> dict[str, Any]:
    bundle = await get_incident(incident_id)
    return {"incident_id": incident_id, "evidence": bundle["evidence"]}


@app.get("/api/incidents/{incident_id}/findings")
async def get_findings(incident_id: str) -> dict[str, Any]:
    bundle = await get_incident(incident_id)
    return {"incident_id": incident_id, "findings": bundle["findings"], "assessment": bundle["assessment"]}


@app.get("/api/incidents/{incident_id}/risk")
async def get_risk(incident_id: str) -> dict[str, Any]:
    bundle = await get_incident(incident_id)
    return {"incident_id": incident_id, "assessment": bundle["assessment"]}


@app.get("/api/incidents/{incident_id}/decisions")
async def get_decisions(incident_id: str) -> dict[str, Any]:
    bundle = await get_incident(incident_id)
    return {"incident_id": incident_id, "decisions": bundle["decisions"]}


@app.get("/api/incidents/{incident_id}/approvals")
async def get_approvals(incident_id: str) -> dict[str, Any]:
    bundle = await get_incident(incident_id)
    return {"incident_id": incident_id, "approvals": bundle["approvals"]}


@app.get("/api/incidents/{incident_id}/timeline")
async def get_timeline(incident_id: str) -> dict[str, Any]:
    bundle = await get_incident(incident_id)
    return {"incident_id": incident_id, "timeline": bundle["timeline"]}


class DecisionBody(BaseModel):
    decision: Literal["approve", "reject"]
    approver: str = Field(min_length=2, max_length=80)
    comment: str = ""
    channel: str = "local_dashboard"


@app.post("/api/incidents/{incident_id}/approvals/{approval_id}/decision")
async def decide_approval(incident_id: str, approval_id: str, body: DecisionBody) -> dict[str, Any]:
    current = await get_incident(incident_id)
    if not any(item["id"] == approval_id for item in current["approvals"]):
        raise HTTPException(status_code=404, detail="Approval does not belong to this incident.")
    approval = decide(
        approval_id,
        body.decision,
        body.approver,
        channel=body.channel,
        comment=body.comment,
    )
    bundle = incident_bundle(incident_id)
    note = await delivery.notify(
        bundle["incident"].get("switch_room_id") or "local",
        f"Decision recorded for {approval_id}: {approval['status']}. Channel: {body.channel}.",
        simulation=body.channel != "switch",
    )
    return {"approval": approval, "delivery": note, "real_switch_proven": bool(note["real_switch"])}


@app.post("/api/incidents/{incident_id}/approvals/{approval_id}/execute")
async def execute_action(incident_id: str, approval_id: str) -> dict[str, Any]:
    current = await get_incident(incident_id)
    if not any(item["id"] == approval_id for item in current["approvals"]):
        raise HTTPException(status_code=404, detail="Approval does not belong to this incident.")
    return execute_approved(approval_id)


@app.post("/api/incidents/{incident_id}/verify")
async def verify_incident(incident_id: str) -> dict[str, Any]:
    bundle = await get_incident(incident_id)
    results = []
    for approval in bundle["approvals"]:
        if approval["status"] in {"EXECUTED", "VERIFICATION_PENDING", "VERIFIED", "FAILED", "APPROVED"}:
            if approval["status"] == "APPROVED":
                continue
            results.append(verify_approval(approval["id"]))
    return {"incident_id": incident_id, "results": results, "incident": incident_bundle(incident_id)["incident"]}


@app.get("/api/audit/verify")
async def verify_audit_log() -> dict[str, Any]:
    """Verify the SHA-256 audit ledger."""
    ok, message = verify_ledger_integrity()
    evidence_ok, evidence_message = verify_evidence_integrity()
    return {
        "verified": ok,
        "details": message,
        "evidence_verified": evidence_ok,
        "evidence_details": evidence_message,
    }


@app.get("/api/audit")
async def audit_history(incident_id: Optional[str] = None, limit: int = 80) -> dict[str, Any]:
    limit = max(1, min(limit, 300))
    conn = get_db_connection()
    try:
        if incident_id:
            rows = conn.execute(
                """
                SELECT id, incident_id, timestamp, actor, action, details_json, prev_hash, entry_hash
                FROM audit_events WHERE incident_id = ? OR incident_id IS NULL
                ORDER BY id DESC LIMIT ?;
                """,
                (incident_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, incident_id, timestamp, actor, action, details_json, prev_hash, entry_hash
                FROM audit_events ORDER BY id DESC LIMIT ?;
                """,
                (limit,),
            ).fetchall()
    finally:
        conn.close()
    events = [dict(row) for row in rows]
    events.reverse()
    return {"events": events}


@app.get("/api/performance")
async def performance() -> dict[str, Any]:
    perf = get_memory_metrics()
    return {
        "current_memory_kb": perf.current_memory_kb,
        "peak_memory_kb": perf.peak_memory_kb,
        "timestamp": perf.timestamp_iso,
        "operations": recent_timings(50),
    }


@app.get("/api/risk/priority")
async def risk_priority() -> dict[str, Any]:
    return {"incidents": priority_list()}


@app.get("/api/controls")
async def controls() -> dict[str, Any]:
    board = control_board()
    return {"controls": board, "observed": sum(1 for item in board if item["observed"]), "total": len(board)}


@app.get("/api/switch/status")
async def switch_status() -> dict[str, Any]:
    health = build_health()["switch_core"]
    return health


class ManualPingRequest(BaseModel):
    room_id: str


@app.post("/api/switch/test-ping")
async def trigger_test_ping(req: ManualPingRequest) -> dict[str, Any]:
    """Dispatch the verified Stage 1 ping response when the agent is registered."""
    if not switch_adapter.agent_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Switch agent is not registered or connected.",
        )
    try:
        event_id = await switch_adapter.send_message(req.room_id, STAGE_1_VERIFICATION_RESPONSE)
        return {
            "status": "dispatched",
            "room_id": req.room_id,
            "event_id": event_id,
            "real_switch_proven": bool(switch_adapter.round_trip_completed and _switch_is_live()),
        }
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)[:300]) from exc


class SimulateMessage(BaseModel):
    room_id: str = "room-sim"
    body: str = Field(min_length=1, max_length=4000)
    sender_name: str = "Local Operator"
    sender: str = "user-local"


@app.post("/api/switch/simulate")
async def simulate_switch_message(body: SimulateMessage) -> dict[str, Any]:
    """Run the operator workflow locally. This never claims a live Switch connection."""
    result = await handle_operator_event(
        {
            "type": "message",
            "room_id": body.room_id,
            "payload": {
                "body": body.body,
                "sender": body.sender,
                "sender_name": body.sender_name,
                "sender_kind": "user",
                "message_id": None,
            },
        },
        channel="switch_simulation",
    )
    result["real_switch_proven"] = False
    result["connection"] = "simulated_local"
    return result


@app.get("/api/switch/feed")
async def switch_feed() -> dict[str, Any]:
    return {
        "connection_claim": build_health()["switch_core"]["connection_claim"],
        "real_switch_proven": build_health()["switch_core"]["real_switch_proven"],
        "messages": list(delivery.feed),
    }


@app.post("/api/demo/shadow-credential")
async def demo_shadow() -> dict[str, Any]:
    """Run Operation ShadowCredential on the current database without deleting incidents.

    The simulated world row is rebuilt. The audit ledger and existing incidents stay.
    Approval is left to a person. This endpoint does not claim a Switch connection.
    """
    result = await run_shadow_scenario(
        auto_approve=False,
        channel="local_demo",
        simulation=True,
    )
    return {
        "real_switch_proven": False,
        "user_database_wiped": False,
        "incidents_deleted": 0,
        "simulation_reseeded": True,
        "shadow_incident_id": result["shadow_incident_id"],
        "vague_incident_id": result["vague_incident_id"],
        "shadow_status": result["shadow"]["incident"]["status"],
        "vague_status": result["vague"]["incident"]["status"],
        "headline": (result["shadow"].get("assessment") or {}).get("headline"),
        "note": (
            "Simulated world was rebuilt. Incidents and the audit ledger were not deleted. "
            "Outbound text is a local simulation, not a Switch delivery."
        ),
    }


@app.get("/api/overview")
async def overview(incident_id: Optional[str] = None) -> dict[str, Any]:
    incidents = priority_list()
    selected = incident_id
    if selected is None and incidents:
        selected = incidents[0]["id"]
    bundle = None
    if selected:
        try:
            bundle = incident_bundle(selected)
        except WorkflowError:
            bundle = None
    return {
        "health": build_health(),
        "controls": control_board(),
        "incidents": incidents,
        "selected": bundle,
        "feed": list(delivery.feed),
    }


@app.get("/")
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
