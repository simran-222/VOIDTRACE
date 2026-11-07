"""VOIDTRACE — deterministic investigation. It does not invent evidence.

Facts require cited records. A single uncorroborated claim stays unknown.
Human-report text is not treated as proof.
"""

from __future__ import annotations

import re
from typing import Any

_LATERAL = re.compile(r"lateral movement to ([A-Za-z0-9.-]+)", re.I)


def assess(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate untrusted evidence into findings, risk, impact, and proposals."""
    findings: list[dict[str, Any]] = []
    proposals: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    usable = [item for item in evidence if item.get("data", {}).get("record_type") != "human_report"]
    if not evidence:
        findings.append(_finding(
            kind="unknown",
            category="coverage",
            statement=(
                "No evidence was collected. VOIDTRACE refuses to select a target, "
                "an actor, or a response."
            ),
            confidence=0.0,
            confidence_reason="The human report did not name a catalogued simulated asset.",
            uncertainty="There is nothing to corroborate.",
            evidence_ids=[],
        ))
        packaged = _package(findings, proposals, suppressed, evidence)
        packaged["headline"] = (
            "VOIDTRACE refused to guess. There is not enough corroborated evidence "
            "to name a compromise or a response."
        )
        packaged["risk"] = {
            "score": 0,
            "level": "NONE",
            "drivers": [],
            "method": "No corroborated exposure fact. Unknowns do not add risk points.",
        }
        return packaged

    for item in evidence:
        data = item.get("data") or {}
        if data.get("injection_detected"):
            patterns = ", ".join(data.get("injection_patterns") or [])
            findings.append(_finding(
                kind="fact",
                category="injection",
                statement=(
                    "Untrusted content matched an embedded-instruction pattern "
                    f"({patterns}). The text was retained as evidence and was not applied "
                    "as policy, approval, or a status change."
                ),
                confidence=1.0,
                confidence_reason="The pattern match is a property of the stored text, not a conclusion about the attacker.",
                uncertainty="The instruction has no operational effect.",
                evidence_ids=[item["id"]],
            ))

    credentials = [item for item in usable if item["data"].get("record_type") == "credential"]
    telemetry = [item for item in usable if item["data"].get("record_type") == "host_telemetry"]
    events = [item for item in usable if item["data"].get("record_type") == "security_event"]
    assets = [item for item in usable if item["data"].get("record_type") == "asset"]

    _lateral_unknowns(findings, events, telemetry)
    _signature_contradictions(findings, events, telemetry)

    exposure_facts: list[dict[str, Any]] = []
    for credential in credentials:
        exposure = _correlate_credential(credential, telemetry, events)
        if exposure is None:
            findings.append(_finding(
                kind="unknown",
                category="coverage",
                statement=(
                    f"Credential {credential['data']['credential_id']} was in scope, but no "
                    "process or GetSecret evidence shows that it was used. "
                    "VOIDTRACE refuses to call it compromised."
                ),
                confidence=0.0,
                confidence_reason="The IAM record proves the credential exists, not that it was abused.",
                uncertainty="Use of this credential is unconfirmed.",
                evidence_ids=[credential["id"]],
            ))
            continue
        findings.append(exposure)
        if exposure["kind"] == "fact":
            exposure_facts.append(exposure)
            proposals.extend(_proposals_for_exposure(exposure))

    business = _business_impact(assets, exposure_facts, findings)
    if exposure_facts and any(item["data"].get("criticality") == "HIGH" for item in assets):
        for asset in assets:
            if asset["data"].get("criticality") != "HIGH":
                continue
            suppressed.append({
                "action": "response.isolate_host",
                "resource": f"host:{asset['data']['host']}",
                "reason": (
                    f"Business impact: isolating {asset['data']['host']} would disrupt "
                    f"{asset['data'].get('service')}. Evidence shows a single process, "
                    "not a host-wide compromise. Host isolation was not proposed."
                ),
                "evidence_ids": [asset["id"]],
            })

    packaged = _package(findings, proposals, suppressed, evidence)
    packaged["business_impact"] = business
    packaged["risk"] = _risk(findings, assets, exposure_facts)
    packaged["headline"] = _headline(packaged["risk"], findings)
    return packaged


def _correlate_credential(
    credential: dict[str, Any],
    telemetry: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any] | None:
    credential_id = credential["data"]["credential_id"]
    secret_events = [
        item for item in events
        if item["data"].get("event_type") == "iam.GetSecret"
        and item["data"].get("credential_id") == credential_id
        and item["data"].get("result") == "success"
    ]
    matched_processes: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for item in telemetry:
        for process in item["data"].get("processes", []):
            if credential_id in str(process.get("cmdline", "")):
                matched_processes.append((item, process))

    if secret_events and matched_processes:
        event = secret_events[0]
        telemetry_item, process = _matching_process(matched_processes, event["data"])
        evidence_ids = [credential["id"], telemetry_item["id"], event["id"]]
        signed = bool(process.get("signed"))
        return _finding(
            kind="fact",
            category="exposure",
            statement=(
                f"Credential {credential_id} was read on {process.get('host')} by process "
                f"{process.get('name')} (pid {process.get('pid')}). "
                f"The process record is {'signed' if signed else 'unsigned'} and its command line "
                "names that credential. An iam.GetSecret success event names the same credential, host, and pid."
            ),
            confidence=0.93,
            confidence_reason=(
                "Three simulated sources agree: the IAM record, process telemetry, and a GetSecret event. "
                "The human report was not used as proof."
            ),
            uncertainty="This does not identify a human operator. Lateral movement is a separate question.",
            evidence_ids=evidence_ids,
            extra={
                "credential_id": credential_id,
                "host": process.get("host"),
                "pid": process.get("pid"),
                "process_name": process.get("name"),
                "signed": signed,
            },
        )
    if secret_events or matched_processes:
        ids = [credential["id"]]
        if secret_events:
            ids.append(secret_events[0]["id"])
        if matched_processes:
            ids.append(matched_processes[0][0]["id"])
        return _finding(
            kind="hypothesis",
            category="exposure",
            statement=(
                f"Credential {credential_id} has only one supporting source beside its IAM record. "
                "VOIDTRACE will not treat that as a confirmed exposure and will not propose revocation."
            ),
            confidence=0.46,
            confidence_reason="A single supporting source is not enough for a fact.",
            uncertainty="The missing source could disprove the hypothesis.",
            evidence_ids=ids,
        )
    return None


def _matching_process(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    event: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    for item, process in pairs:
        if process.get("host") == event.get("host") and int(process.get("pid", -1)) == int(event.get("pid", -2)):
            return item, process
    return pairs[0]


def _lateral_unknowns(
    findings: list[dict[str, Any]],
    events: list[dict[str, Any]],
    telemetry: list[dict[str, Any]],
) -> None:
    for item in events:
        message = str(item["data"].get("message", ""))
        match = _LATERAL.search(message)
        if not match:
            continue
        target = match.group(1)
        corroborated = False
        for event in events:
            data = event["data"]
            if (
                data.get("host") == target
                and data.get("result") == "success"
                and str(data.get("event_type", "")).startswith(("iam.", "process."))
            ):
                corroborated = True
        for telemetry_item in telemetry:
            if telemetry_item["data"].get("host") == target and telemetry_item["data"].get("processes"):
                corroborated = True
        if corroborated:
            continue
        findings.append(_finding(
            kind="unknown",
            category="lateral",
            statement=(
                f"A log line mentions possible lateral movement to {target}. "
                "No process, authentication success, or credential-use event supports that claim. "
                "VOIDTRACE refuses to guess an actor or a second compromised host."
            ),
            confidence=0.0,
            confidence_reason="One uncorroborated mention is not evidence of movement.",
            uncertainty=f"Whether {target} is involved is unknown.",
            evidence_ids=[item["id"]],
        ))


def _signature_contradictions(
    findings: list[dict[str, Any]],
    events: list[dict[str, Any]],
    telemetry: list[dict[str, Any]],
) -> None:
    claims = [
        item for item in events
        if item["data"].get("claims_signed_vendor") is True or item["data"].get("event_type") == "log.vendor_claim"
    ]
    for claim in claims:
        name = claim["data"].get("process_name") or "credharvest.exe"
        unsigned: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for item in telemetry:
            for process in item["data"].get("processes", []):
                if process.get("name") == name and process.get("signed") is False:
                    unsigned.append((item, process))
        if not unsigned:
            continue
        telemetry_item, _process = unsigned[0]
        findings.append(_finding(
            kind="fact",
            category="contradiction",
            statement=(
                f"A vendor-claim log says {name} is a signed Microsoft update, but host telemetry "
                "records that process as unsigned. The claim is not accepted as clearance."
            ),
            confidence=0.99,
            confidence_reason="Both the claim and the telemetry flag are present. The disagreement itself is the fact.",
            uncertainty="The vendor claim and the telemetry cannot both be a complete description of the process.",
            evidence_ids=[claim["id"], telemetry_item["id"]],
        ))
        findings.append(_finding(
            kind="hypothesis",
            category="contradiction",
            statement=(
                f"The vendor claim cannot be reconciled with telemetry. "
                f"Legitimacy of {name} is not established from that claim."
            ),
            confidence=0.35,
            confidence_reason="A contradiction lowers confidence in the vendor story. It is not a new fact about intent.",
            uncertainty="This hypothesis does not drive the risk score.",
            evidence_ids=[claim["id"], telemetry_item["id"]],
        ))


def _proposals_for_exposure(exposure: dict[str, Any]) -> list[dict[str, Any]]:
    extra = exposure.get("extra") or {}
    credential_id = extra["credential_id"]
    host = extra["host"]
    pid = extra["pid"]
    evidence_ids = list(exposure["evidence_ids"])
    return [
        {
            "action": "response.disable_credential",
            "resource": f"credential:{credential_id}",
            "risk": "HIGH",
            "conflict_group": f"credential:{credential_id}",
            "justification": (
                f"Disable simulated credential {credential_id}. "
                "The exposure fact cites the IAM record, telemetry, and GetSecret. "
                "This action does not run until a person approves it."
            ),
            "evidence_ids": evidence_ids,
            "expected": {
                "type": "credential",
                "id": credential_id,
                "field": "status",
                "equals": "DISABLED",
            },
        },
        {
            "action": "response.terminate_process",
            "resource": f"process:{host}:{pid}",
            "risk": "HIGH",
            "conflict_group": f"process:{host}:{pid}",
            "justification": (
                f"Terminate simulated process {extra.get('process_name')} pid {pid} on {host}. "
                "The process command line names the exposed credential."
            ),
            "evidence_ids": evidence_ids,
            "expected": {
                "type": "process",
                "host": host,
                "pid": pid,
                "field": "status",
                "equals": "TERMINATED",
            },
        },
    ]


def _business_impact(
    assets: list[dict[str, Any]],
    exposure_facts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    if not assets:
        return {
            "known": False,
            "statement": "No asset record was collected. Business impact is unknown and will not be invented.",
            "unknowns": ["No criticality, service, or impact record is available."],
        }
    asset = assets[0]["data"]
    unknowns = [
        item["statement"] for item in findings if item["kind"] in {"unknown", "hypothesis"}
    ]
    credential_ids = [
        (item.get("extra") or {}).get("credential_id")
        for item in exposure_facts
    ]
    credential_ids = [item for item in credential_ids if item]
    if_disabled = (
        f"Disabling {', '.join(credential_ids)} stops the {asset.get('service')} reader "
        "until a replacement simulated credential is issued. Jobs that depend on it pause."
        if credential_ids
        else "No credential-disable impact is estimated because exposure is not confirmed."
    )
    return {
        "known": True,
        "service": asset.get("service"),
        "criticality": asset.get("criticality"),
        "host": asset.get("host"),
        "if_credential_disabled": if_disabled,
        "if_host_isolated": asset.get("impact"),
        "recommendation": (
            "Disable the exposed credential and terminate the unsigned process. "
            f"Do not isolate {asset.get('host')}: the corroborated evidence is one process, "
            f"and host isolation would disrupt {asset.get('service')}."
            if credential_ids
            else "No high-risk change is recommended. Impact records exist, but exposure is not confirmed."
        ),
        "evidence_ids": [item["id"] for item in assets],
        "unknowns": unknowns,
    }


def _risk(
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    exposure_facts: list[dict[str, Any]],
) -> dict[str, Any]:
    score = 0
    drivers: list[dict[str, Any]] = []
    if exposure_facts:
        score += 55
        drivers.append({
            "factor": "Confirmed credential exposure",
            "points": 55,
            "evidence_ids": exposure_facts[0]["evidence_ids"],
        })
    if exposure_facts and any(item["data"].get("criticality") == "HIGH" for item in assets):
        score += 25
        drivers.append({
            "factor": "High-criticality business service tied to the exposed credential",
            "points": 25,
            "evidence_ids": [item["id"] for item in assets if item["data"].get("criticality") == "HIGH"],
        })
    score = min(100, score)
    if score >= 85:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"
    return {
        "score": score,
        "level": level,
        "drivers": drivers,
        "method": (
            "Only facts at confidence 0.80 or higher can add points. "
            "Hypotheses, unknowns, and embedded instructions do not raise or lower the score. "
            "Confirmed exposure adds 55. A high-criticality asset tied to that exposure adds 25."
        ),
    }


def _headline(risk: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    exposure = next((item for item in findings if item["category"] == "exposure" and item["kind"] == "fact"), None)
    if exposure:
        return (
            f"{exposure['statement']} Confidence {exposure['confidence']:.2f}. "
            "Uncorroborated claims were not treated as fact."
        )
    return (
        "VOIDTRACE refused to guess. There is not enough corroborated evidence "
        "to name a compromise or a response."
    )


def _package(
    findings: list[dict[str, Any]],
    proposals: list[dict[str, Any]],
    suppressed: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    known_ids = {item["id"] for item in evidence}
    for finding in findings:
        if finding["kind"] == "fact" and not finding["evidence_ids"]:
            raise ValueError("Refusing to emit a fact without evidence ids.")
        missing = [item for item in finding["evidence_ids"] if item not in known_ids]
        if missing:
            raise ValueError(f"Finding cites evidence that was not supplied: {missing}")
    confidence = {
        "facts": sum(1 for item in findings if item["kind"] == "fact"),
        "hypotheses": sum(1 for item in findings if item["kind"] == "hypothesis"),
        "unknowns": sum(1 for item in findings if item["kind"] == "unknown"),
        "highest_fact_confidence": max(
            [item["confidence"] for item in findings if item["kind"] == "fact"] or [0]
        ),
    }
    uncertainty = [item["statement"] for item in findings if item["kind"] != "fact"]
    return {
        "findings": findings,
        "proposals": proposals,
        "suppressed_actions": suppressed,
        "business_impact": {
            "known": False,
            "statement": "No asset record was collected. Business impact is unknown and will not be invented.",
            "unknowns": uncertainty,
        },
        "risk": {"score": 0, "level": "NONE", "drivers": [], "method": "No corroborated exposure fact."},
        "headline": "",
        "confidence": confidence,
        "uncertainty": uncertainty,
    }


def _finding(
    *,
    kind: str,
    category: str,
    statement: str,
    confidence: float,
    confidence_reason: str,
    uncertainty: str,
    evidence_ids: list[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding = {
        "kind": kind,
        "category": category,
        "statement": statement,
        "confidence": confidence,
        "confidence_reason": confidence_reason,
        "uncertainty": uncertainty,
        "evidence_ids": evidence_ids,
    }
    if extra:
        finding["extra"] = extra
    return finding

# Additive assessment extension; original assessment logic remains intact.
_original_assess = assess
from .additional_assessment import assess_additional_scenarios as _assess_additional

def assess(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    return _assess_additional(_original_assess, evidence)
