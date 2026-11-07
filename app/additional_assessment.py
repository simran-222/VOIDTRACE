from typing import Any


def assess_additional_scenarios(
    original_assess,
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    result = original_assess(evidence)

    def records(record_type):
        return [
            item for item in evidence
            if (item.get("data") or {}).get("record_type") == record_type
        ]

    events = records("security_event")
    telemetry = records("host_telemetry")

    def event_data(event_type, host):
        return [
            item for item in events
            if item["data"].get("event_type") == event_type
            and item["data"].get("host") == host
        ]

    def add_finding(kind, category, statement, confidence, reason, uncertainty, ids):
        if not ids or any(f["evidence_ids"] == ids for f in result["findings"]):
            return
        result["findings"].append({
            "kind": kind,
            "category": category,
            "statement": statement,
            "confidence": confidence,
            "confidence_reason": reason,
            "uncertainty": uncertainty,
            "evidence_ids": ids,
        })

    # Privilege escalation: two independent records must match.
    for grant in event_data("identity.role.grant", "identity-admin-03"):
        g = grant["data"]
        matches = [
            item for item in event_data(
                "identity.audit.privilege_change", "identity-admin-03"
            )
            if item["data"].get("correlation_id") == g.get("correlation_id")
            and item["data"].get("actor") == g.get("actor")
            and item["data"].get("target_principal") == g.get("target_principal")
            and item["data"].get("role") == g.get("role")
            and item["data"].get("result") == "success"
        ]
        if g.get("result") == "success" and matches:
            add_finding(
                "fact", "privilege_escalation",
                "A simulated privileged role grant is corroborated by an independent identity audit record.",
                0.96,
                "Both records agree on actor, target, role and correlation ID.",
                "The records establish the privilege change, not malicious intent.",
                [grant["id"], matches[0]["id"]],
            )

    # Data transfer: matching transfer telemetry and DLP alert.
    for transfer in event_data("network.transfer", "archive-node-02"):
        t = transfer["data"]
        matches = [
            item for item in event_data("dlp.alert", "archive-node-02")
            if item["data"].get("correlation_id") == t.get("correlation_id")
            and item["data"].get("bytes_transferred") == t.get("bytes_transferred")
            and item["data"].get("destination_category") == t.get("destination_category")
        ]
        if t.get("result") == "success" and matches:
            add_finding(
                "fact", "data_transfer",
                "A simulated outbound data transfer is corroborated by a matching independent DLP alert.",
                0.95,
                "Transfer telemetry and DLP records agree on correlation ID, byte count and destination category.",
                "The simulation does not establish the identity of a human operator.",
                [transfer["id"], matches[0]["id"]],
            )

    # Insider anomaly: unusual access is not proof of misuse.
    for anomaly in event_data("records.access.anomaly", "records-laptop-05"):
        context = event_data("approval.context.incomplete", "records-laptop-05")
        if context:
            add_finding(
                "hypothesis", "access_anomaly",
                "Unusual records access was observed, but its approval context is incomplete.",
                0.55,
                "An access anomaly and an incomplete approval record are present.",
                "Authorization and intent remain unestablished. No individual is accused.",
                [anomaly["id"], context[0]["id"]],
            )

    # Maintenance: approved change must match signed process telemetry.
    for approval in event_data("change.approved", "build-agent-07"):
        a = approval["data"]
        maintenance = [
            item for item in event_data(
                "maintenance.task.completed", "build-agent-07"
            )
            if item["data"].get("change_id") == a.get("change_id")
            and item["data"].get("process_name") == a.get("process_name")
            and item["data"].get("signed") is True
        ]
        host_records = [
            item for item in telemetry
            if item["data"].get("host") == "build-agent-07"
        ]
        signed_process = any(
            p.get("name") == a.get("process_name") and p.get("signed") is True
            for item in host_records
            for p in item["data"].get("processes", [])
        )
        if maintenance and signed_process:
            add_finding(
                "fact", "benign_maintenance",
                "The maintenance activity matches an approved change and a signed process record.",
                0.97,
                "The change record, maintenance event and host process inventory agree.",
                "This conclusion applies only to the observed simulated maintenance activity.",
                [approval["id"], maintenance[0]["id"], host_records[0]["id"]],
            )

    # Recalculate summary counts while preserving original findings and proposals.
    findings = result["findings"]
    result["confidence"] = {
        "facts": sum(f["kind"] == "fact" for f in findings),
        "hypotheses": sum(f["kind"] == "hypothesis" for f in findings),
        "unknowns": sum(f["kind"] == "unknown" for f in findings),
        "highest_fact_confidence": max(
            [f["confidence"] for f in findings if f["kind"] == "fact"] or [0]
        ),
    }
    result["uncertainty"] = [
        f["statement"] for f in findings if f["kind"] != "fact"
    ]

    # Evidence-based risk scoring for the additional simulated scenarios.
    # Only corroborated facts with confidence >= 0.80 can contribute.
    scenario_hosts = {
        "privilege_escalation": "identity-admin-03",
        "data_transfer": "archive-node-02",
    }

    risk_drivers = []
    risk_score = 0

    for category, host in scenario_hosts.items():
        confirmed = [
            finding for finding in findings
            if finding.get("category") == category
            and finding.get("kind") == "fact"
            and finding.get("confidence", 0) >= 0.80
        ]

        if not confirmed:
            continue

        finding = confirmed[0]
        risk_score += 55
        risk_drivers.append({
            "factor": (
                "Confirmed privileged role change"
                if category == "privilege_escalation"
                else "Corroborated outbound data transfer"
            ),
            "points": 55,
            "evidence_ids": finding["evidence_ids"],
        })

        high_assets = [
            item for item in records("asset")
            if item["data"].get("host") == host
            and item["data"].get("criticality") == "HIGH"
        ]

        if high_assets:
            risk_score += 25
            risk_drivers.append({
                "factor": "High-criticality business service tied to the finding",
                "points": 25,
                "evidence_ids": [item["id"] for item in high_assets],
            })

    if risk_drivers:
        risk_score = min(100, risk_score)
        if risk_score >= 85:
            risk_level = "CRITICAL"
        elif risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "NONE"

        result["risk"] = {
            "score": risk_score,
            "level": risk_level,
            "drivers": risk_drivers,
            "method": (
                "Only corroborated facts at confidence 0.80 or higher "
                "contribute. Confirmed privilege changes or outbound data "
                "transfers add 55 points. A tied HIGH-criticality asset "
                "adds 25 points. Hypotheses do not increase risk."
            ),
        }

    return result
