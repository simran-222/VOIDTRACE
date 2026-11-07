"""Incident investigation, approval, simulated response, and verification.

SECURITY is the only path to simulated tools. Verification reads ground truth
again and does not trust the executor's return value.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

from app.commands import parse_operator_command
from app.database import get_db_connection, record_audit_event
from app.errors import SecurityDenied, SimulationUnavailable, WorkflowError
from app.security import approver_allowed, security
from app.performance import record_timing
from app.untrusted import annotate_untrusted
from app.investigation import assess

logger = logging.getLogger(__name__)

_LOCK = threading.RLock()
_OPEN_STATUSES = ("PROPOSED", "AWAITING_APPROVAL", "APPROVED")
_DONE_POSITIVE = ("VERIFIED",)
_TERMINAL_NEGATIVE = ("REJECTED", "FAILED")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Delivery:
    """Outbound operator messages. A local copy is always kept.

    `real_switch` is true only when the configured Switch adapter accepts the post.
    """

    def __init__(self) -> None:
        self.feed: deque[dict[str, Any]] = deque(maxlen=100)
        self._send = None
        self._is_live = lambda: False

    def configure(self, send: Any, is_live: Any) -> None:
        self._send = send
        self._is_live = is_live

    async def notify(self, room_id: str, content: str, *, simulation: bool) -> dict[str, Any]:
        live = bool(self._is_live()) and self._send is not None and not simulation
        entry: dict[str, Any] = {
            "room_id": room_id or "local",
            "content": content,
            "real_switch": False,
            "channel": "local_simulation" if simulation else "local_fallback",
            "at": _now(),
        }
        if live:
            try:
                event_id = await self._send(room_id, content)
                entry["real_switch"] = True
                entry["channel"] = "switch"
                entry["event_id"] = event_id
            except Exception as exc:
                entry["channel"] = "local_fallback"
                entry["error"] = str(exc)[:300]
                entry["real_switch"] = False
        banner = _banner(simulation=simulation, real_switch=bool(entry["real_switch"]))
        entry["content"] = banner + content
        self.feed.append(entry)
        return entry


delivery = Delivery()


def _banner(*, simulation: bool, real_switch: bool) -> str:
    if simulation:
        return "SIMULATED CHANNEL — This transcript was not sent through Switch.\n\n"
    if real_switch:
        return "SWITCH — Delivered to the connected Switch room.\n\n"
    return "LOCAL FALLBACK — Switch is not connected. This is not a Switch delivery.\n\n"


def create_incident_record(
    conn: Any,
    *,
    title: str,
    severity: str,
    switch_room_id: Optional[str],
    metadata: dict[str, Any],
    actor: str = "ANALYST",
) -> dict[str, Any]:
    incident_id = _new_id("INC")
    created_at = _now()
    conn.execute(
        """
        INSERT INTO incidents (id, title, severity, status, switch_room_id, created_at, metadata_json)
        VALUES (?, ?, ?, 'INVESTIGATING', ?, ?, ?);
        """,
        (
            incident_id,
            title,
            severity,
            switch_room_id,
            created_at,
            json.dumps(metadata, sort_keys=True),
        ),
    )
    record_audit_event(
        conn,
        actor=actor,
        action="INCIDENT_CREATED",
        details={"title": title, "severity": severity, "room": switch_room_id},
        incident_id=incident_id,
    )
    return {"id": incident_id, "status": "INVESTIGATING", "created_at": created_at, "title": title}


def investigate(incident_id: str) -> dict[str, Any]:
    """Run VOIDTRACE for one incident. Does not execute high-risk actions."""
    started = time.perf_counter()
    with _LOCK:
        conn = get_db_connection()
        try:
            with conn:
                report = _investigate(conn, incident_id)
        finally:
            conn.close()
    record_timing(
        "investigation",
        (time.perf_counter() - started) * 1000.0,
        incident_id,
        audit=True,
    )
    return report


def judge_snapshot(
    snapshot: dict[str, Any],
    expected: dict[str, Any],
    claimed_result: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Judge ground truth. The executor claim is not read."""
    ignored = claimed_result is not None
    actual = _read_expected(snapshot, expected)
    if actual is None:
        return {
            "verification_result": "FAILED",
            "reason": "Expected simulated state was not present.",
            "expected": expected,
            "actual": None,
            "ignored_executor_claim": ignored,
        }
    if actual != expected.get("equals"):
        return {
            "verification_result": "FAILED",
            "reason": "Ground truth does not match the intended result.",
            "expected": expected,
            "actual": actual,
            "ignored_executor_claim": ignored,
        }
    return {
        "verification_result": "VERIFIED",
        "reason": "Independent inspection matches the intended simulated state.",
        "expected": expected,
        "actual": actual,
        "ignored_executor_claim": ignored,
    }


def _investigate(conn: Any, incident_id: str) -> dict[str, Any]:
    incident = _require_incident(conn, incident_id)
    existing = conn.execute(
        "SELECT status FROM approvals WHERE incident_id = ?;",
        (incident_id,),
    ).fetchall()
    if any(row["status"] != "PROPOSED" for row in existing):
        raise WorkflowError(
            "This incident already has a human decision. It was not investigated again.",
            409,
            "already_decided",
        )
    conn.execute("DELETE FROM approvals WHERE incident_id = ? AND status = 'PROPOSED';", (incident_id,))
    conn.execute("DELETE FROM evidence WHERE incident_id = ?;", (incident_id,))
    metadata = json.loads(incident["metadata_json"] or "{}")
    report_text = str(metadata.get("report") or incident["title"])
    from app.simulation import ensure_world

    ensure_world(conn, _now())
    security.grant_from_report(conn, incident_id, report_text)
    evidence: list[dict[str, Any]] = []
    failures: list[str] = []
    evidence.append(_store_evidence(
        conn,
        incident_id,
        source="human.report",
        tool="operator.message",
        data={"record_type": "human_report", "message": report_text, "channel": metadata.get("channel", "api")},
    ))

    scopes = [
        row["resource"]
        for row in conn.execute(
            "SELECT resource FROM incident_scopes WHERE incident_id = ? ORDER BY resource;",
            (incident_id,),
        ).fetchall()
    ]
    for resource in scopes:
        if resource.startswith("credential:"):
            _collect(conn, incident_id, "VOIDTRACE", "iam.read_credential", resource, evidence, failures)
        elif resource.startswith("host:"):
            for tool in ("telemetry.read_host", "events.read", "assets.read"):
                _collect(conn, incident_id, "VOIDTRACE", tool, resource, evidence, failures)

    for item in list(evidence):
        data = item["data"]
        if data.get("record_type") != "host_telemetry":
            continue
        host = data.get("host")
        for process in data.get("processes", []):
            security.grant_correlated_process(conn, incident_id, host, int(process.get("pid", -1)))

    assessment = assess(evidence)
    kept_proposals = []
    for proposal in assessment["proposals"]:
        granted = conn.execute(
            "SELECT 1 FROM incident_scopes WHERE incident_id = ? AND resource = ?;",
            (incident_id, proposal["resource"]),
        ).fetchone()
        if granted is None:
            record_audit_event(
                conn,
                actor="SECURITY",
                action="SCOPE_DENIED",
                details={"resource": proposal["resource"], "reason": "proposal_outside_scope"},
                incident_id=incident_id,
            )
            continue
        kept_proposals.append(proposal)
    assessment["proposals"] = kept_proposals

    _replace_findings(conn, incident_id, assessment["findings"])
    _save_assessment(conn, incident_id, assessment)
    approvals = [_insert_proposal(conn, incident_id, proposal) for proposal in kept_proposals]

    if kept_proposals:
        status = "AWAITING_APPROVAL"
    elif failures and len(evidence) <= 1:
        status = "FAILED"
        record_audit_event(
            conn,
            actor="VOIDTRACE",
            action="INCIDENT_TOOL_FAILURE",
            details={"failures": failures},
            incident_id=incident_id,
        )
    elif any(
        finding.get("category") in {
            "privilege_escalation",
            "data_transfer",
            "access_anomaly",
            "benign_maintenance",
        }
        and finding.get("kind") in {"fact", "hypothesis"}
        for finding in assessment["findings"]
    ):
        status = "INVESTIGATED"
        record_audit_event(
            conn,
            actor="VOIDTRACE",
            action="INVESTIGATION_COMPLETED",
            details={
                "finding_categories": [
                    finding["category"]
                    for finding in assessment["findings"]
                    if finding.get("category") in {
                        "privilege_escalation",
                        "data_transfer",
                        "access_anomaly",
                        "benign_maintenance",
                    }
                ],
                "remediation_performed": False,
            },
            incident_id=incident_id,
        )
    else:
        status = "INSUFFICIENT_EVIDENCE"
        record_audit_event(
            conn,
            actor="VOIDTRACE",
            action="INVESTIGATION_INSUFFICIENT",
            details={"headline": assessment["headline"], "failures": failures},
            incident_id=incident_id,
        )
    conn.execute("UPDATE incidents SET status = ? WHERE id = ?;", (status, incident_id))
    return {"incident_id": incident_id, "status": status, "failures": failures}


def _collect(
    conn: Any,
    incident_id: str,
    actor: str,
    tool: str,
    resource: str,
    evidence: list[dict[str, Any]],
    failures: list[str],
) -> None:
    try:
        outcome = security.execute(
            conn,
            actor=actor,
            tool=tool,
            resource=resource,
            incident_id=incident_id,
        )
    except SecurityDenied as exc:
        failures.append(f"{tool} {resource} denied:{exc.decision['reason']}")
        return
    except Exception as exc:
        failures.append(f"{tool} {resource} failed:{type(exc).__name__}")
        record_audit_event(
            conn,
            actor="VOIDTRACE",
            action="INCIDENT_TOOL_FAILURE",
            details={"tool": tool, "resource": resource, "error": type(exc).__name__},
            incident_id=incident_id,
        )
        return
    for piece in _explode(tool, outcome["result"]):
        evidence.append(_store_evidence(
            conn,
            incident_id,
            source=f"sim.{tool}",
            tool=tool,
            data=piece,
        ))


def _explode(tool: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    if tool == "events.read":
        pieces = []
        for event in result.get("events", []):
            row = dict(event)
            row["record_type"] = "security_event"
            row.setdefault("host", result.get("host"))
            pieces.append(row)
        return pieces
    return [result]


def _store_evidence(conn: Any, incident_id: str, source: str, tool: str, data: dict[str, Any]) -> dict[str, Any]:
    annotated = annotate_untrusted(data)
    content = canonical_json(annotated)
    digest = hashlib.sha256(content.encode()).hexdigest()
    evidence_id = _new_id("EV")
    collected_at = _now()
    conn.execute(
        """
        INSERT INTO evidence (
            id, incident_id, source, tool_name, collected_at, trust, content_json, content_hash
        ) VALUES (?, ?, ?, ?, ?, 'untrusted', ?, ?);
        """,
        (evidence_id, incident_id, source, tool, collected_at, content, digest),
    )
    record_audit_event(
        conn,
        actor="VOIDTRACE",
        action="EVIDENCE_RECORDED",
        details={"evidence_id": evidence_id, "source": source, "tool": tool, "content_hash": digest},
        incident_id=incident_id,
    )
    if annotated.get("injection_detected"):
        record_audit_event(
            conn,
            actor="SECURITY",
            action="INJECTION_IGNORED",
            details={
                "evidence_id": evidence_id,
                "patterns": annotated.get("injection_patterns", []),
            },
            incident_id=incident_id,
        )
    return {
        "id": evidence_id,
        "source": source,
        "tool": tool,
        "collected_at": collected_at,
        "trust": "untrusted",
        "data": annotated,
        "content_hash": digest,
    }


def _replace_findings(conn: Any, incident_id: str, findings: list[dict[str, Any]]) -> None:
    conn.execute("DELETE FROM findings WHERE incident_id = ?;", (incident_id,))
    for finding in findings:
        if finding["kind"] == "fact" and not finding["evidence_ids"]:
            raise WorkflowError("Refusing to store a fact without evidence.", 500, "fact_without_evidence")
        finding_id = _new_id("FND")
        conn.execute(
            """
            INSERT INTO findings (
                id, incident_id, kind, category, statement, confidence, confidence_reason,
                uncertainty, evidence_ids_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                finding_id,
                incident_id,
                finding["kind"],
                finding["category"],
                finding["statement"],
                finding["confidence"],
                finding["confidence_reason"],
                finding["uncertainty"],
                json.dumps(finding["evidence_ids"]),
                _now(),
            ),
        )
        record_audit_event(
            conn,
            actor="VOIDTRACE",
            action="FINDING_RECORDED",
            details={
                "finding_id": finding_id,
                "kind": finding["kind"],
                "category": finding["category"],
                "confidence": finding["confidence"],
                "evidence_ids": finding["evidence_ids"],
            },
            incident_id=incident_id,
        )


def _save_assessment(conn: Any, incident_id: str, assessment: dict[str, Any]) -> None:
    risk = assessment["risk"]
    conn.execute("DELETE FROM assessments WHERE incident_id = ?;", (incident_id,))
    conn.execute(
        """
        INSERT INTO assessments (
            incident_id, risk_score, risk_level, headline, drivers_json, business_impact_json,
            uncertainty_json, confidence_json, suppressed_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            incident_id,
            risk["score"],
            risk["level"],
            assessment["headline"],
            json.dumps(risk["drivers"]),
            json.dumps(assessment["business_impact"]),
            json.dumps(assessment["uncertainty"]),
            json.dumps(assessment["confidence"]),
            json.dumps(assessment["suppressed_actions"]),
            _now(),
        ),
    )
    record_audit_event(
        conn,
        actor="VOIDTRACE",
        action="RISK_ASSESSED",
        details={"score": risk["score"], "level": risk["level"], "method": risk["method"]},
        incident_id=incident_id,
    )
    record_audit_event(
        conn,
        actor="VOIDTRACE",
        action="BUSINESS_IMPACT_ASSESSED",
        details=assessment["business_impact"],
        incident_id=incident_id,
    )


def _insert_proposal(conn: Any, incident_id: str, proposal: dict[str, Any]) -> dict[str, Any]:
    approval_id = _new_id("APR")
    requested = _now()
    expires = (datetime.now(UTC) + timedelta(minutes=30)).isoformat()
    conn.execute(
        """
        INSERT INTO approvals (
            id, incident_id, action, resource, risk, conflict_group, justification,
            evidence_ids_json, expected_json, status, requested_at, expires_at, notified_via
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?, ?, 'pending');
        """,
        (
            approval_id,
            incident_id,
            proposal["action"],
            proposal["resource"],
            proposal["risk"],
            proposal["conflict_group"],
            proposal["justification"],
            json.dumps(proposal["evidence_ids"]),
            json.dumps(proposal["expected"]),
            requested,
            expires,
        ),
    )
    record_audit_event(
        conn,
        actor="VOIDTRACE",
        action="APPROVAL_REQUESTED",
        details={
            "approval_id": approval_id,
            "action": proposal["action"],
            "resource": proposal["resource"],
            "risk": proposal["risk"],
            "status": "PROPOSED",
        },
        incident_id=incident_id,
    )
    return approval_row(conn, approval_id)


def publish_approvals(conn: Any, incident_id: str, channel: str) -> None:
    conn.execute(
        """
        UPDATE approvals
        SET status = 'AWAITING_APPROVAL', notified_via = ?
        WHERE incident_id = ? AND status = 'PROPOSED';
        """,
        (channel, incident_id),
    )


def decide(
    approval_id: str,
    decision: str,
    approver: str,
    *,
    channel: str,
    comment: str = "",
) -> dict[str, Any]:
    if decision not in {"approve", "reject"}:
        raise WorkflowError("Decision must be approve or reject.", 400, "bad_decision")
    if not approver_allowed(approver):
        raise WorkflowError(
            "A person must approve or reject. Automated actors cannot decide.",
            403,
            "approver_rejected",
        )
    return _commit_workflow(lambda conn: _decide(conn, approval_id, decision, approver, channel, comment))


def _decide(
    conn: Any,
    approval_id: str,
    decision: str,
    approver: str,
    channel: str,
    comment: str,
) -> dict[str, Any]:
    row = _require_approval(conn, approval_id)
    if row["status"] not in {"PROPOSED", "AWAITING_APPROVAL"}:
        raise WorkflowError("This approval was already decided.", 409, "duplicate_decision")
    if row["expires_at"] <= _now():
        conn.execute(
            """
            UPDATE approvals
            SET status = 'REJECTED', decided_at = ?, approver = ?, decision_channel = ?, decision_reason = ?
            WHERE id = ?;
            """,
            (_now(), approver, channel, "expired_before_decision", approval_id),
        )
        record_audit_event(
            conn,
            actor=approver,
            action="APPROVAL_EXPIRED",
            details={"approval_id": approval_id},
            incident_id=row["incident_id"],
        )
        _refresh_incident_status(conn, row["incident_id"])
        raise WorkflowError("This approval expired before a decision.", 409, "approval_expired")

    if decision == "approve":
        sibling = conn.execute(
            """
            SELECT id, status FROM approvals
            WHERE incident_id = ? AND conflict_group = ? AND id != ?
              AND status IN ('APPROVED', 'EXECUTED', 'VERIFICATION_PENDING', 'VERIFIED');
            """,
            (row["incident_id"], row["conflict_group"], approval_id),
        ).fetchone()
        if sibling is not None:
            conn.execute(
                """
                UPDATE approvals
                SET status = 'REJECTED', decided_at = ?, approver = ?, decision_channel = ?,
                    decision_reason = ?
                WHERE id = ?;
                """,
                (_now(), approver, channel, f"conflict_with_{sibling['id']}", approval_id),
            )
            record_audit_event(
                conn,
                actor="SECURITY",
                action="APPROVAL_CONFLICT",
                details={"approval_id": approval_id, "conflicts_with": sibling["id"]},
                incident_id=row["incident_id"],
            )
            raise WorkflowError(
                "A conflicting action is already approved for this resource.",
                409,
                "approval_conflict",
            )
        conn.execute(
            """
            UPDATE approvals
            SET status = 'REJECTED', decided_at = ?, approver = 'SECURITY',
                decision_channel = ?, decision_reason = ?
            WHERE incident_id = ? AND conflict_group = ? AND id != ?
              AND status IN ('PROPOSED', 'AWAITING_APPROVAL');
            """,
            (
                _now(),
                channel,
                f"conflict_with_{approval_id}",
                row["incident_id"],
                row["conflict_group"],
                approval_id,
            ),
        )
        if conn.execute("SELECT changes();").fetchone()[0]:
            record_audit_event(
                conn,
                actor="SECURITY",
                action="APPROVAL_CONFLICT",
                details={"winner": approval_id, "conflict_group": row["conflict_group"]},
                incident_id=row["incident_id"],
            )
        new_status = "APPROVED"
        reason = comment or "approved"
    else:
        new_status = "REJECTED"
        reason = comment or "rejected"

    conn.execute(
        """
        UPDATE approvals
        SET status = ?, decided_at = ?, approver = ?, decision_channel = ?, decision_reason = ?
        WHERE id = ?;
        """,
        (new_status, _now(), approver, channel, reason, approval_id),
    )
    record_audit_event(
        conn,
        actor=approver,
        action="APPROVAL_DECIDED",
        details={
            "approval_id": approval_id,
            "decision": decision,
            "channel": channel,
            "status": new_status,
        },
        incident_id=row["incident_id"],
    )
    _refresh_incident_status(conn, row["incident_id"])
    return approval_row(conn, approval_id)


def execute_approved(approval_id: str) -> dict[str, Any]:
    started = time.perf_counter()
    result = _commit_workflow(lambda conn: _execute_approved(conn, approval_id))
    record_timing("simulated_action", (time.perf_counter() - started) * 1000.0, result.get("incident_id"), audit=True)
    return result


def _execute_approved(conn: Any, approval_id: str) -> dict[str, Any]:
    row = _require_approval(conn, approval_id)
    if row["status"] != "APPROVED":
        raise WorkflowError("High-risk actions run only after an explicit approval.", 409, "not_approved")
    try:
        outcome = security.execute(
            conn,
            actor="RESPONDER",
            tool=row["action"],
            resource=row["resource"],
            incident_id=row["incident_id"],
            approval_id=approval_id,
        )
    except SecurityDenied as exc:
        raise WorkflowError(str(exc.decision["reason"]), 403, str(exc.decision["reason"]))
    conn.execute(
        """
        UPDATE approvals
        SET status = 'VERIFICATION_PENDING', executed_at = ?
        WHERE id = ?;
        """,
        (_now(), approval_id),
    )
    record_audit_event(
        conn,
        actor="RESPONDER",
        action="APPROVAL_EXECUTED",
        details={
            "approval_id": approval_id,
            "action": row["action"],
            "resource": row["resource"],
            "executor_reported": outcome["result"],
        },
        incident_id=row["incident_id"],
    )
    # The executor payload is intentionally ignored by the verifier.
    verification = _verify(conn, approval_id, claimed_result=outcome["result"])
    verification["incident_id"] = row["incident_id"]
    return verification


def verify_approval(approval_id: str, claimed_result: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return _commit_workflow(lambda conn: _verify(conn, approval_id, claimed_result=claimed_result))


def _commit_workflow(fn: Any) -> dict[str, Any]:
    """Commit workflow writes even when the function rejects the action.

    A denial still needs its audit row. SQLite's `with conn` rolls those rows back.
    """
    with _LOCK:
        conn = get_db_connection()
        try:
            try:
                result = fn(conn)
            except WorkflowError:
                conn.commit()
                raise
            conn.commit()
            return result
        finally:
            conn.close()


def _verify(conn: Any, approval_id: str, claimed_result: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Compare expected state with a fresh ground-truth read.

    `claimed_result` is accepted so callers can see it is not consulted.
    """
    row = _require_approval(conn, approval_id)
    expected = json.loads(row["expected_json"])
    try:
        outcome = security.execute(
            conn,
            actor="VERIFIER",
            tool="verify.read_state",
            resource=f"verify:{row['incident_id']}",
            incident_id=row["incident_id"],
        )
        result = judge_snapshot(outcome["result"], expected, claimed_result)
        new_status = "VERIFIED" if result["verification_result"] == "VERIFIED" else "FAILED"
    except (SecurityDenied, SimulationUnavailable, KeyError, TypeError) as exc:
        reason = exc.decision["reason"] if isinstance(exc, SecurityDenied) else str(exc)
        result = {
            "verification_result": "UNVERIFIED",
            "reason": reason or "Verification could not read ground truth.",
            "expected": expected,
            "actual": None,
            "ignored_executor_claim": claimed_result is not None,
        }
        new_status = "VERIFICATION_PENDING"
    except Exception as exc:
        result = {
            "verification_result": "UNVERIFIED",
            "reason": f"Verification failed closed: {type(exc).__name__}",
            "expected": expected,
            "actual": None,
            "ignored_executor_claim": claimed_result is not None,
        }
        new_status = "VERIFICATION_PENDING"

    conn.execute(
        """
        UPDATE approvals
        SET status = ?, verification_result = ?, verification_json = ?
        WHERE id = ?;
        """,
        (new_status, result["verification_result"], json.dumps(result), approval_id),
    )
    record_audit_event(
        conn,
        actor="VERIFIER",
        action="VERIFICATION_COMPLETED",
        details={"approval_id": approval_id, **{k: result[k] for k in ("verification_result", "reason", "actual")}},
        incident_id=row["incident_id"],
    )
    _refresh_incident_status(conn, row["incident_id"])
    result["approval_id"] = approval_id
    result["incident_id"] = row["incident_id"]
    result["incident_status"] = _incident_status(conn, row["incident_id"])
    return result


def _read_expected(snapshot: dict[str, Any], expected: dict[str, Any]) -> Any:
    kind = expected.get("type")
    field = expected.get("field")
    if kind == "credential":
        record = snapshot.get("credentials", {}).get(expected.get("id"))
        return None if record is None else record.get(field)
    if kind == "process":
        for process in snapshot.get("processes", []):
            if process.get("host") == expected.get("host") and int(process.get("pid", -1)) == int(expected.get("pid", -2)):
                return process.get(field)
        return None
    if kind == "host":
        record = snapshot.get("assets", {}).get(expected.get("id") or expected.get("host"))
        return None if record is None else record.get(field)
    return None


def _refresh_incident_status(conn: Any, incident_id: str) -> None:
    rows = conn.execute(
        "SELECT status, verification_result FROM approvals WHERE incident_id = ?;",
        (incident_id,),
    ).fetchall()
    statuses = [row["status"] for row in rows]
    results = [row["verification_result"] for row in rows]
    if any(item == "UNVERIFIED" for item in results):
        status = "UNVERIFIED"
        resolved_at = None
    elif any(item == "FAILED" for item in statuses):
        status = "FAILED"
        resolved_at = None
    elif any(item in {"PROPOSED", "AWAITING_APPROVAL"} for item in statuses):
        status = "AWAITING_APPROVAL"
        resolved_at = None
    elif any(item == "APPROVED" for item in statuses):
        status = "APPROVED"
        resolved_at = None
    elif any(item == "VERIFICATION_PENDING" for item in statuses):
        status = "VERIFICATION_PENDING"
        resolved_at = None
    elif statuses and any(item == "VERIFIED" for item in statuses) and all(item in {"VERIFIED", "REJECTED"} for item in statuses):
        status = "RESOLVED"
        resolved_at = _now()
    elif statuses and all(item == "REJECTED" for item in statuses):
        status = "REJECTED"
        resolved_at = None
    else:
        status = _incident_status(conn, incident_id)
        resolved_at = None
    if resolved_at is None:
        conn.execute(
            "UPDATE incidents SET status = ?, resolved_at = NULL WHERE id = ?;",
            (status, incident_id),
        )
    else:
        conn.execute(
            "UPDATE incidents SET status = ?, resolved_at = ? WHERE id = ?;",
            (status, resolved_at, incident_id),
        )


def verify_evidence_integrity(incident_id: Optional[str] = None) -> tuple[bool, str]:
    conn = get_db_connection()
    try:
        if incident_id:
            rows = conn.execute(
                "SELECT id, content_json, content_hash FROM evidence WHERE incident_id = ?;",
                (incident_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT id, content_json, content_hash FROM evidence;").fetchall()
        for row in rows:
            digest = hashlib.sha256(row["content_json"].encode()).hexdigest()
            if digest != row["content_hash"]:
                return False, f"Evidence {row['id']} hash mismatch."
            json.loads(row["content_json"])
        return True, f"Evidence integrity verified across {len(rows)} records."
    finally:
        conn.close()


def reseed_simulation() -> dict[str, Any]:
    """Rebuild simulated ground truth. Incidents and the audit ledger stay."""
    with _LOCK:
        conn = get_db_connection()
        try:
            with conn:
                from app.simulation import reseed_world

                reseed_world(conn, _now())
                record_audit_event(
                    conn,
                    actor="SYSTEM",
                    action="SIMULATION_RESEEDED",
                    details={
                        "user_database_wiped": False,
                        "incidents_deleted": 0,
                        "target": "sim_world",
                    },
                )
        finally:
            conn.close()
    return {
        "simulation_reseeded": True,
        "user_database_wiped": False,
        "incidents_deleted": 0,
        "note": "Only the simulated world was rebuilt. Incidents and the audit ledger were kept.",
    }


def message_for_incident(incident_id: str) -> str:
    report = incident_bundle(incident_id)
    lines = [
        f"VOIDTRACE — {report['incident']['title']}",
        f"Incident {report['incident']['id']} is {report['incident']['status']}.",
        report["assessment"]["headline"] if report.get("assessment") else "Investigation has not produced a headline.",
        "",
        "Findings",
    ]
    for finding in report["findings"]:
        cited = ",".join(json.loads(finding["evidence_ids_json"])) if isinstance(finding["evidence_ids_json"], str) else ""
        lines.append(
            f"- {finding['kind'].upper()} {finding['confidence']:.2f} {finding['statement']} [{cited}]"
        )
    if report.get("assessment"):
        impact = report["assessment"]["business_impact"]
        lines.extend([
            "",
            f"Risk {report['assessment']['risk_level']} {report['assessment']['risk_score']}",
            impact.get("recommendation") or impact.get("statement") or "",
        ])
    if report["approvals"]:
        lines.append("")
        lines.append("Approvals")
        for approval in report["approvals"]:
            lines.append(
                f"- {approval['id']} {approval['status']} {approval['action']} {approval['resource']} risk {approval['risk']}"
            )
            if approval["status"] in {"PROPOSED", "AWAITING_APPROVAL"}:
                lines.append(f"  Reply: @voidtrace approve {approval['id']}")
                lines.append(f"  Or:    @voidtrace reject {approval['id']}")
            if approval["status"] == "APPROVED":
                lines.append(f"  Reply: @voidtrace execute {approval['id']}")
    lines.append("")
    lines.append("High-risk simulated actions do not run until a person approves them.")
    lines.append("Success is reported only after independent verification of simulated state.")
    return "\n".join(lines)


async def publish_incident(incident_id: str, room_id: Optional[str], *, simulation: bool) -> dict[str, Any]:
    text = message_for_incident(incident_id)
    note = await delivery.notify(room_id or "local", text, simulation=simulation)
    conn = get_db_connection()
    try:
        with conn:
            publish_approvals(conn, incident_id, note["channel"])
    finally:
        conn.close()
    bundle = incident_bundle(incident_id)
    bundle["delivery"] = note
    bundle["real_switch_proven"] = bool(note["real_switch"])
    return bundle


async def handle_operator_event(event: dict[str, Any], *, channel: str) -> dict[str, Any]:
    """Handle one operator message. Evidence never reaches this function."""
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    body = str(payload.get("body") or "")
    room_id = str(event.get("room_id") or "")
    sender_kind = str(payload.get("sender_kind") or "user")
    sender_name = str(payload.get("sender_name") or payload.get("sender") or "Operator")
    if sender_kind == "agent":
        return {"ignored": True, "reason": "agent_message", "real_switch_proven": False}
    message_id = str(payload.get("message_id") or "")
    if not message_id:
        message_id = hashlib.sha256(f"{channel}|{room_id}|{body}".encode()).hexdigest()
    simulation = channel == "switch_simulation"
    command = parse_operator_command(body)
    with _LOCK:
        conn = get_db_connection()
        try:
            with conn:
                existing = conn.execute(
                    "SELECT message_id FROM switch_inbox WHERE message_id = ?;",
                    (message_id,),
                ).fetchone()
                if existing is not None:
                    return {"duplicate": True, "real_switch_proven": False, "channel": channel}
                conn.execute(
                    "INSERT INTO switch_inbox (message_id, room_id, channel, received_at) VALUES (?, ?, ?, ?);",
                    (message_id, room_id or "local", channel, _now()),
                )
                action = "SWITCH_SIMULATION_RECEIVED" if simulation else "SWITCH_OPERATOR_MESSAGE"
                record_audit_event(
                    conn,
                    actor=sender_name,
                    action=action,
                    details={"room_id": room_id, "command": None if command is None else command.get("command"), "channel": channel},
                )
        finally:
            conn.close()

    if command is None or command.get("command") == "ping":
        return {"handled": False, "channel": channel, "real_switch_proven": False}

    if command["command"] == "status":
        note = await delivery.notify(room_id, _status_text(), simulation=simulation)
        return {"handled": True, "command": "status", "delivery": note, "real_switch_proven": bool(note["real_switch"])}

    if command["command"] == "incident":
        title = _title_from_report(command["report"])
        with _LOCK:
            conn = get_db_connection()
            try:
                with conn:
                    created = create_incident_record(
                        conn,
                        title=title,
                        severity="HIGH",
                        switch_room_id=room_id or None,
                        metadata={"report": command["report"], "channel": channel},
                        actor=sender_name,
                    )
            finally:
                conn.close()
        investigate(created["id"])
        bundle = await publish_incident(created["id"], room_id, simulation=simulation)
        bundle["handled"] = True
        bundle["command"] = "incident"
        return bundle

    if command["command"] in {"approve", "reject"}:
        try:
            approval = decide(
                command["approval_id"],
                command["command"],
                sender_name,
                channel=channel,
                comment=command.get("comment") or "",
            )
        except WorkflowError as exc:
            note = await delivery.notify(room_id, f"VOIDTRACE could not record that decision. {exc.message}", simulation=simulation)
            return {"handled": True, "ok": False, "detail": exc.message, "code": exc.code, "delivery": note, "real_switch_proven": False}
        note = await delivery.notify(room_id, message_for_incident(approval["incident_id"]), simulation=simulation)
        return {
            "handled": True,
            "ok": True,
            "approval": approval,
            "delivery": note,
            "real_switch_proven": bool(note["real_switch"]),
        }

    if command["command"] == "execute":
        try:
            result = execute_approved(command["approval_id"])
        except WorkflowError as exc:
            note = await delivery.notify(room_id, f"VOIDTRACE did not execute that action. {exc.message}", simulation=simulation)
            return {"handled": True, "ok": False, "detail": exc.message, "code": exc.code, "delivery": note, "real_switch_proven": False}
        note = await delivery.notify(room_id, message_for_incident(result["incident_id"]), simulation=simulation)
        result["delivery"] = note
        result["handled"] = True
        result["real_switch_proven"] = bool(note["real_switch"])
        return result

    return {"handled": False, "channel": channel, "real_switch_proven": False}


def _title_from_report(report: str) -> str:
    first = report.strip().splitlines()[0].strip()
    if first.lower().startswith("operation "):
        title = first.split(":")[0].strip()
        return title[:120]
    if ":" in first:
        return first.split(":", 1)[0].strip()[:120] or "Reported incident"
    return (first[:80] or "Reported incident")


def _status_text() -> str:
    conn = get_db_connection()
    try:
        count = conn.execute("SELECT COUNT(*) AS cnt FROM incidents;").fetchone()["cnt"]
        pending = conn.execute(
            "SELECT COUNT(*) AS cnt FROM approvals WHERE status IN ('PROPOSED', 'AWAITING_APPROVAL');"
        ).fetchone()["cnt"]
    finally:
        conn.close()
    return (
        f"VOIDTRACE status. Incidents: {count}. Approvals waiting: {pending}. "
        "High-risk simulated actions stay blocked until a person approves them."
    )


def _require_incident(conn: Any, incident_id: str) -> Any:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?;", (incident_id,)).fetchone()
    if row is None:
        raise WorkflowError("Incident not found.", 404, "not_found")
    return row


def _require_approval(conn: Any, approval_id: str) -> Any:
    row = conn.execute("SELECT * FROM approvals WHERE id = ?;", (approval_id,)).fetchone()
    if row is None:
        raise WorkflowError("Approval not found.", 404, "not_found")
    return row


def _incident_status(conn: Any, incident_id: str) -> str:
    row = conn.execute("SELECT status FROM incidents WHERE id = ?;", (incident_id,)).fetchone()
    return row["status"] if row else "UNKNOWN"


def approval_row(conn: Any, approval_id: str) -> dict[str, Any]:
    row = _require_approval(conn, approval_id)
    return _approval_dict(row)


def _approval_dict(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["evidence_ids"] = json.loads(data.pop("evidence_ids_json"))
    data["expected"] = json.loads(data.pop("expected_json"))
    if data.get("verification_json"):
        data["verification"] = json.loads(data["verification_json"])
    return data


def incident_bundle(incident_id: str) -> dict[str, Any]:
    conn = get_db_connection()
    try:
        incident = _require_incident(conn, incident_id)
        evidence = [ _evidence_dict(row) for row in conn.execute(
            "SELECT * FROM evidence WHERE incident_id = ? ORDER BY collected_at, id;",
            (incident_id,),
        ).fetchall()]
        findings = []
        for row in conn.execute(
            "SELECT * FROM findings WHERE incident_id = ? ORDER BY created_at, id;",
            (incident_id,),
        ).fetchall():
            finding = dict(row)
            finding["evidence_ids"] = json.loads(finding["evidence_ids_json"])
            findings.append(finding)
        assessment_row = conn.execute(
            "SELECT * FROM assessments WHERE incident_id = ?;",
            (incident_id,),
        ).fetchone()
        decisions = [dict(row) for row in conn.execute(
            "SELECT * FROM policy_decisions WHERE incident_id = ? ORDER BY created_at, id;",
            (incident_id,),
        ).fetchall()]
        approvals = [
            _approval_dict(row)
            for row in conn.execute(
                "SELECT * FROM approvals WHERE incident_id = ? ORDER BY requested_at, id;",
                (incident_id,),
            ).fetchall()
        ]
        timeline = [
            dict(row)
            for row in conn.execute(
                """
                SELECT id, timestamp, actor, action, details_json, entry_hash
                FROM audit_events
                WHERE incident_id = ?
                ORDER BY id ASC;
                """,
                (incident_id,),
            ).fetchall()
        ]
    finally:
        conn.close()
    assessment = None
    if assessment_row is not None:
        assessment = {
            "risk_score": assessment_row["risk_score"],
            "risk_level": assessment_row["risk_level"],
            "headline": assessment_row["headline"],
            "drivers": json.loads(assessment_row["drivers_json"]),
            "business_impact": json.loads(assessment_row["business_impact_json"]),
            "uncertainty": json.loads(assessment_row["uncertainty_json"]),
            "confidence": json.loads(assessment_row["confidence_json"]),
            "suppressed_actions": json.loads(assessment_row["suppressed_json"]),
            "created_at": assessment_row["created_at"],
        }
    incident_data = dict(incident)
    incident_data["metadata"] = json.loads(incident_data.pop("metadata_json") or "{}")
    return {
        "incident": incident_data,
        "evidence": evidence,
        "findings": findings,
        "assessment": assessment,
        "decisions": decisions,
        "approvals": approvals,
        "timeline": timeline,
    }


def _evidence_dict(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["data"] = json.loads(data.pop("content_json"))
    return data


def list_incident_rows() -> list[dict[str, Any]]:
    conn = get_db_connection()
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM incidents ORDER BY created_at DESC;").fetchall()]
    finally:
        conn.close()


def priority_list() -> list[dict[str, Any]]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT i.id, i.title, i.severity, i.status, i.created_at,
                   a.risk_score, a.risk_level, a.headline
            FROM incidents i
            LEFT JOIN assessments a ON a.incident_id = i.id
            ORDER BY COALESCE(a.risk_score, -1) DESC, i.created_at DESC;
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
