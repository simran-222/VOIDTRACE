"""SECURITY — allowlists, scopes, approval checks, and fail-closed enforcement.

Every simulated tool operation in the product goes through `execute`.
A broken policy seal denies every operation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
from datetime import UTC, datetime
from typing import Any, Optional

from app.database import record_audit_event
from app.errors import SecurityBypassError, SecurityDenied

BASE_POLICY: dict[str, Any] = {
    "version": 1,
    "tools": {
        "iam.read_credential": {
            "effect": "read",
            "approval": False,
            "actors": ["VOIDTRACE", "VERIFIER"],
            "risk": "LOW",
        },
        "telemetry.read_host": {
            "effect": "read",
            "approval": False,
            "actors": ["VOIDTRACE", "VERIFIER"],
            "risk": "LOW",
        },
        "events.read": {
            "effect": "read",
            "approval": False,
            "actors": ["VOIDTRACE", "VERIFIER"],
            "risk": "LOW",
        },
        "assets.read": {
            "effect": "read",
            "approval": False,
            "actors": ["VOIDTRACE", "VERIFIER"],
            "risk": "LOW",
        },
        "response.disable_credential": {
            "effect": "mutate",
            "approval": True,
            "actors": ["RESPONDER"],
            "risk": "HIGH",
        },
        "response.terminate_process": {
            "effect": "mutate",
            "approval": True,
            "actors": ["RESPONDER"],
            "risk": "HIGH",
        },
        "response.isolate_host": {
            "effect": "mutate",
            "approval": True,
            "actors": ["RESPONDER"],
            "risk": "CRITICAL",
        },
        "verify.read_state": {
            "effect": "read",
            "approval": False,
            "actors": ["VERIFIER"],
            "risk": "LOW",
        },
    },
}

_ACTIVE_STATUSES = ("APPROVED", "EXECUTED", "VERIFICATION_PENDING", "VERIFIED")
_BLOCKED_APPROVERS = {
    "ai",
    "agent",
    "voidtrace",
    "investigation",
    "security",
    "system",
    "responder",
}


def policy_fingerprint(policy: dict[str, Any]) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4).upper()}"


class Security:
    """Instance-local policy seal so tests can tamper a copy without leaking."""

    def __init__(self) -> None:
        self._policy = copy.deepcopy(BASE_POLICY)
        self._seal = policy_fingerprint(self._policy)

    def intact(self) -> bool:
        return policy_fingerprint(self._policy) == self._seal

    def fingerprint(self) -> str:
        return self._seal

    def tool_names(self) -> list[str]:
        if not self.intact():
            return []
        return sorted(self._policy["tools"].keys())

    def restore(self) -> None:
        self._policy = copy.deepcopy(BASE_POLICY)
        self._seal = policy_fingerprint(self._policy)

    def grant(self, conn: Any, incident_id: str, resource: str, reason: str) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO incident_scopes (incident_id, resource, granted_at, reason)
            VALUES (?, ?, ?, ?);
            """,
            (incident_id, resource, _now(), reason),
        )
        record_audit_event(
            conn,
            actor="SECURITY",
            action="SCOPE_GRANTED",
            details={"resource": resource, "reason": reason},
            incident_id=incident_id,
        )

    def grant_from_report(self, conn: Any, incident_id: str, report: str) -> list[str]:
        """Scope resources that the human report names. Evidence cannot call this."""
        from app.simulation import ensure_world, match_report

        state = ensure_world(conn, _now())
        resources = [f"verify:{incident_id}"]
        resources.extend(match_report(state, report))
        for resource in resources:
            self.grant(conn, incident_id, resource, "named_in_human_report" if not resource.startswith("verify:") else "verifier_channel")
        return resources

    def grant_correlated_process(self, conn: Any, incident_id: str, host: str, pid: int) -> bool:
        """Grant a process only when ground truth, not log text, shows a scoped credential."""
        from app.simulation import find_process, read_ground_truth

        host_resource = f"host:{host}"
        if not self._in_scope(conn, incident_id, host_resource):
            record_audit_event(
                conn,
                actor="SECURITY",
                action="SCOPE_DENIED",
                details={"resource": f"process:{host}:{pid}", "reason": "host_outside_incident_scope"},
                incident_id=incident_id,
            )
            return False
        try:
            state = read_ground_truth(conn)
        except Exception:
            return False
        process = find_process(state, host, pid)
        scoped_credentials = [
            row["resource"].split(":", 1)[1]
            for row in conn.execute(
                "SELECT resource FROM incident_scopes WHERE incident_id = ? AND resource LIKE 'credential:%';",
                (incident_id,),
            ).fetchall()
        ]
        cmdline = "" if process is None else str(process.get("cmdline", ""))
        if process is None or not any(credential_id in cmdline for credential_id in scoped_credentials):
            record_audit_event(
                conn,
                actor="SECURITY",
                action="SCOPE_DENIED",
                details={
                    "resource": f"process:{host}:{pid}",
                    "reason": "process_not_correlated_to_scoped_credential",
                },
                incident_id=incident_id,
            )
            return False
        self.grant(conn, incident_id, f"process:{host}:{pid}", "correlated_process_on_scoped_host")
        return True

    def evaluate(
        self,
        conn: Any,
        *,
        actor: str,
        tool: str,
        resource: str,
        incident_id: str,
        approval_id: Optional[str] = None,
    ) -> dict[str, Any]:
        base = {
            "id": _new_id("DEC"),
            "incident_id": incident_id,
            "actor": actor,
            "tool": tool,
            "operation": tool,
            "resource": resource,
            "effect": "unknown",
            "allowed": False,
            "reason": "denied",
            "requires_approval": False,
            "policy_fingerprint": self._seal,
            "created_at": _now(),
        }
        if not self.intact():
            base["reason"] = "policy_integrity_failure"
            record_audit_event(
                conn,
                actor="SECURITY",
                action="SECURITY_TAMPER_DETECTED",
                details={"tool": tool, "resource": resource, "result": "fail_closed"},
                incident_id=incident_id,
            )
            return base

        spec = self._policy["tools"].get(tool)
        if spec is None:
            base["reason"] = "tool_not_allowlisted"
            return base

        base["effect"] = spec["effect"]
        base["requires_approval"] = bool(spec["approval"])
        if actor not in spec["actors"]:
            base["reason"] = "actor_not_permitted"
            return base
        if not self._in_scope(conn, incident_id, resource):
            base["reason"] = "resource_outside_incident_scope"
            return base
        if spec["approval"]:
            approval_reason = self._check_approval(
                conn,
                approval_id=approval_id,
                incident_id=incident_id,
                tool=tool,
                resource=resource,
            )
            if approval_reason != "ok":
                base["reason"] = approval_reason
                return base
        base["allowed"] = True
        base["reason"] = "approved_by_human" if spec["approval"] else "allowlisted_for_incident_scope"
        return base

    def persist(self, conn: Any, decision: dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT INTO policy_decisions (
                id, incident_id, actor, tool_name, operation, resource, effect,
                allowed, reason, requires_approval, policy_fingerprint, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                decision["id"],
                decision["incident_id"],
                decision["actor"],
                decision["tool"],
                decision["operation"],
                decision["resource"],
                decision["effect"],
                1 if decision["allowed"] else 0,
                decision["reason"],
                1 if decision["requires_approval"] else 0,
                decision["policy_fingerprint"],
                decision["created_at"],
            ),
        )
        record_audit_event(
            conn,
            actor="SECURITY",
            action="TOOL_ALLOWED" if decision["allowed"] else "TOOL_DENIED",
            details={
                "decision_id": decision["id"],
                "tool": decision["tool"],
                "operation": decision["operation"],
                "resource": decision["resource"],
                "effect": decision["effect"],
                "reason": decision["reason"],
                "actor": decision["actor"],
            },
            incident_id=decision["incident_id"],
        )

    def execute(
        self,
        conn: Any,
        *,
        actor: str,
        tool: str,
        resource: str,
        incident_id: str,
        approval_id: Optional[str] = None,
    ) -> dict[str, Any]:
        decision = self.evaluate(
            conn,
            actor=actor,
            tool=tool,
            resource=resource,
            incident_id=incident_id,
            approval_id=approval_id,
        )
        self.persist(conn, decision)
        if not decision["allowed"]:
            raise SecurityDenied(decision)
        token = self.issue_capability(conn, decision, approval_id)
        from app.simulation import dispatch

        result = dispatch(conn, tool, resource, token, incident_id, _now())
        return {"decision": decision, "result": result}

    def issue_capability(self, conn: Any, decision: dict[str, Any], approval_id: Optional[str]) -> str:
        token = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        conn.execute(
            """
            INSERT INTO capabilities (
                token_hash, incident_id, tool_name, resource, approval_id,
                policy_fingerprint, issued_at, used_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL);
            """,
            (
                token_hash,
                decision["incident_id"],
                decision["tool"],
                decision["resource"],
                approval_id,
                self._seal,
                _now(),
            ),
        )
        return token

    def consume_capability(
        self,
        conn: Any,
        *,
        token: str,
        tool: str,
        resource: str,
        incident_id: str,
    ) -> None:
        if not token or not self.intact():
            raise SecurityBypassError("Capability rejected. Policy seal is not intact or token is missing.")
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = conn.execute(
            "SELECT * FROM capabilities WHERE token_hash = ?;",
            (token_hash,),
        ).fetchone()
        if row is None or row["used_at"] is not None:
            raise SecurityBypassError("Capability is missing or already used.")
        if (
            row["tool_name"] != tool
            or row["resource"] != resource
            or row["incident_id"] != incident_id
            or row["policy_fingerprint"] != self._seal
        ):
            raise SecurityBypassError("Capability does not match this operation.")
        conn.execute(
            "UPDATE capabilities SET used_at = ? WHERE token_hash = ?;",
            (_now(), token_hash),
        )

    def _in_scope(self, conn: Any, incident_id: str, resource: str) -> bool:
        row = conn.execute(
            """
            SELECT 1 FROM incident_scopes
            WHERE incident_id = ? AND resource = ?;
            """,
            (incident_id, resource),
        ).fetchone()
        return row is not None

    def _check_approval(
        self,
        conn: Any,
        *,
        approval_id: Optional[str],
        incident_id: str,
        tool: str,
        resource: str,
    ) -> str:
        if not approval_id:
            return "human_approval_required"
        row = conn.execute("SELECT * FROM approvals WHERE id = ?;", (approval_id,)).fetchone()
        if row is None:
            return "approval_mismatch"
        if row["incident_id"] != incident_id or row["action"] != tool or row["resource"] != resource:
            return "approval_mismatch"
        if row["expires_at"] <= _now():
            return "approval_expired"
        if row["status"] != "APPROVED":
            return "approval_not_approved"
        conflict = conn.execute(
            """
            SELECT id FROM approvals
            WHERE incident_id = ? AND conflict_group = ? AND id != ?
              AND status IN ('APPROVED', 'EXECUTED', 'VERIFICATION_PENDING', 'VERIFIED', 'FAILED');
            """,
            (incident_id, row["conflict_group"], approval_id),
        ).fetchone()
        # Another APPROVED row in the same group is a conflict. The current row is APPROVED,
        # so the query above includes siblings only.
        if conflict is not None and conflict["id"] != approval_id:
            sibling = conn.execute("SELECT status FROM approvals WHERE id = ?;", (conflict["id"],)).fetchone()
            if sibling and sibling["status"] in _ACTIVE_STATUSES:
                return "approval_conflict"
        return "ok"


def approver_allowed(name: str) -> bool:
    cleaned = " ".join(name.strip().lower().split())
    if len(cleaned) < 2:
        return False
    return cleaned not in _BLOCKED_APPROVERS


security = Security()
