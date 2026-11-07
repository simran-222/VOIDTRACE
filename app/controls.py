"""Observable status for the thirteen required architecture areas.

A control is "observed" only when the database shows the behaviour, not because
the module imported.
"""

from __future__ import annotations

from typing import Any

from app.database import get_db_connection
from app.security import security


def control_board() -> list[dict[str, Any]]:
    conn = get_db_connection()
    try:
        actions = {
            row["action"]
            for row in conn.execute("SELECT DISTINCT action FROM audit_events;")
        }

        def count(sql: str) -> int:
            return int(conn.execute(sql).fetchone()[0])

        evidence = count("SELECT COUNT(*) FROM evidence;")
        findings = count("SELECT COUNT(*) FROM findings;")
        fact_findings = count("SELECT COUNT(*) FROM findings WHERE kind = 'fact';")
        assessments = count("SELECT COUNT(*) FROM assessments;")
        samples = count("SELECT COUNT(*) FROM performance_samples;")
        incidents = count("SELECT COUNT(*) FROM incidents;")
        decisions = count("SELECT COUNT(*) FROM policy_decisions;")
        allows = count("SELECT COUNT(*) FROM policy_decisions WHERE allowed = 1;")
        denies = count("SELECT COUNT(*) FROM policy_decisions WHERE allowed = 0;")
        scoped_denies = count(
            "SELECT COUNT(*) FROM policy_decisions WHERE reason = 'resource_outside_incident_scope';"
        )
        cross_scope = count(
            """
            SELECT COUNT(*) FROM policy_decisions d
            WHERE d.allowed = 0
              AND d.reason = 'resource_outside_incident_scope'
              AND EXISTS (
                SELECT 1 FROM incident_scopes s
                WHERE s.resource = d.resource AND s.incident_id != d.incident_id
              );
            """
        )
        decisions_made = count(
            "SELECT COUNT(*) FROM approvals WHERE decided_at IS NOT NULL;"
        )
        tamper = "SECURITY_TAMPER_DETECTED" in actions or count(
            "SELECT COUNT(*) FROM policy_decisions WHERE reason = 'policy_integrity_failure';"
        ) > 0
        switch_seen = bool(
            actions
            & {
                "SWITCH_MESSAGE_RECEIVED",
                "SWITCH_MESSAGE_SENT",
                "SWITCH_SIMULATION_RECEIVED",
                "SWITCH_OPERATOR_MESSAGE",
            }
        )
    finally:
        conn.close()

    seal_ok = security.intact()
    areas = [
        {
            "id": 1,
            "name": "Agent Manipulation Protection",
            "observed": "INJECTION_IGNORED" in actions,
            "detail": "Embedded instructions were flagged and ignored." if "INJECTION_IGNORED" in actions else "Armed. Instruction patterns are scanned before evidence is stored.",
        },
        {
            "id": 2,
            "name": "Reliable Information and Evidence",
            "observed": evidence > 0 and findings > 0 and fact_findings > 0,
            "detail": f"{evidence} evidence records, {fact_findings} facts citing them.",
        },
        {
            "id": 3,
            "name": "Risk Prioritisation",
            "observed": "RISK_ASSESSED" in actions and assessments > 0,
            "detail": "Risk scores use corroborated facts only.",
        },
        {
            "id": 4,
            "name": "Incident Failure Handling",
            "observed": bool(actions & {"INVESTIGATION_INSUFFICIENT", "INCIDENT_TOOL_FAILURE", "VERIFICATION_COMPLETED"}),
            "detail": "Insufficient evidence, tool failure, and unverified results stay unresolved.",
        },
        {
            "id": 5,
            "name": "Tool and Resource Permissions",
            "observed": allows > 0 and denies > 0 and decisions > 0,
            "detail": f"{allows} allows and {denies} denials recorded.",
        },
        {
            "id": 6,
            "name": "Human Approval",
            "observed": decisions_made > 0 and "APPROVAL_REQUESTED" in actions,
            "detail": "High-risk actions keep a proposal, approver, time, and outcome.",
        },
        {
            "id": 7,
            "name": "Switch Integration",
            "observed": switch_seen,
            "detail": "Live Switch and the labelled local simulation are recorded separately.",
        },
        {
            "id": 8,
            "name": "SECURITY Tampering Protection",
            "observed": tamper and seal_ok,
            "detail": "A broken policy seal fails closed." if tamper else "Seal is intact. Tamper detection has not been exercised on this database.",
            "seal_intact": seal_ok,
            "policy_fingerprint": security.fingerprint(),
        },
        {
            "id": 9,
            "name": "Legitimate-Tool Misuse",
            "observed": scoped_denies > 0,
            "detail": "Allowlisted tools were denied for resources outside the incident.",
        },
        {
            "id": 10,
            "name": "Multiple Incident Isolation",
            "observed": incidents >= 2 and cross_scope > 0,
            "detail": f"{incidents} incidents. Cross-scope denials: {cross_scope}.",
        },
        {
            "id": 11,
            "name": "Conflicting Actions",
            "observed": "APPROVAL_CONFLICT" in actions,
            "detail": "A second action in the same conflict group was refused.",
        },
        {
            "id": 12,
            "name": "Business-Impact Assessment",
            "observed": "BUSINESS_IMPACT_ASSESSED" in actions and assessments > 0,
            "detail": "Impact comes from simulated asset records, not invented figures.",
        },
        {
            "id": 13,
            "name": "Performance Measurement",
            "observed": samples > 0 and "PERFORMANCE_RECORDED" in actions,
            "detail": f"{samples} timing samples stored.",
        },
    ]
    for area in areas:
        area["state"] = "observed" if area["observed"] else "armed"
    return areas
