from __future__ import annotations


def extend_world(state: dict) -> dict:
    """Add four independent, simulated incident scenarios without replacing existing data."""

    assets = state.setdefault("assets", {})
    events = state.setdefault("events", [])
    processes = state.setdefault("processes", [])

    new_assets = {
        "identity-admin-03": {
            "criticality": "HIGH",
            "service": "identity-management",
            "impact": "Identity administration is unavailable while this simulated host is isolated.",
            "isolated": False,
        },
        "archive-node-02": {
            "criticality": "HIGH",
            "service": "records-archive",
            "impact": "Archive access is interrupted while this simulated host is isolated.",
            "isolated": False,
        },
        "records-laptop-05": {
            "criticality": "MEDIUM",
            "service": "records-management",
            "impact": "Records staff temporarily lose access while this simulated host is isolated.",
            "isolated": False,
        },
        "build-agent-07": {
            "criticality": "LOW",
            "service": "build-maintenance",
            "impact": "Scheduled build maintenance is delayed while this simulated host is isolated.",
            "isolated": False,
        },
    }

    for host, asset in new_assets.items():
        assets.setdefault(host, asset)

    new_processes = [
        {
            "pid": 3101, "host": "identity-admin-03",
            "name": "identity-sync.exe",
            "cmdline": "identity-sync.exe --operation simulated",
            "signed": True, "sha256": "simulated-identity-sync",
            "status": "RUNNING", "user": "svc-identity-admin",
        },
        {
            "pid": 4202, "host": "archive-node-02",
            "name": "archive-transfer-sim.exe",
            "cmdline": "archive-transfer-sim.exe --mode simulated",
            "signed": True, "sha256": "simulated-archive-transfer",
            "status": "RUNNING", "user": "svc-archive",
        },
        {
            "pid": 5305, "host": "records-laptop-05",
            "name": "records-client.exe",
            "cmdline": "records-client.exe --session simulated",
            "signed": True, "sha256": "simulated-records-client",
            "status": "RUNNING", "user": "records-user",
        },
        {
            "pid": 6707, "host": "build-agent-07",
            "name": "maintenance-runner.exe",
            "cmdline": "maintenance-runner.exe --change CHG-SIM-007",
            "signed": True, "sha256": "simulated-maintenance-runner",
            "status": "RUNNING", "user": "svc-build",
        },
    ]

    known_pids = {p.get("pid") for p in processes}
    processes.extend(p for p in new_processes if p["pid"] not in known_pids)

    new_events = [
        {
            "event_id": "SIM-PRIV-001",
            "event_type": "identity.role.grant",
            "host": "identity-admin-03",
            "actor": "svc-identity-admin",
            "target_principal": "svc-report-reader",
            "role": "privileged-operator",
            "correlation_id": "CORR-PRIV-001",
            "result": "success",
            "message": "Simulated role grant recorded.",
        },
        {
            "event_id": "SIM-PRIV-002",
            "event_type": "identity.audit.privilege_change",
            "host": "identity-admin-03",
            "actor": "svc-identity-admin",
            "target_principal": "svc-report-reader",
            "role": "privileged-operator",
            "correlation_id": "CORR-PRIV-001",
            "result": "success",
            "message": "Independent privilege-change audit record.",
        },
        {
            "event_id": "SIM-EXFIL-001",
            "event_type": "network.transfer",
            "host": "archive-node-02",
            "correlation_id": "CORR-EXFIL-001",
            "bytes_transferred": 52428800,
            "destination_category": "external-storage-simulated",
            "result": "success",
            "message": "Simulated outbound transfer telemetry.",
        },
        {
            "event_id": "SIM-EXFIL-002",
            "event_type": "dlp.alert",
            "host": "archive-node-02",
            "correlation_id": "CORR-EXFIL-001",
            "bytes_transferred": 52428800,
            "destination_category": "external-storage-simulated",
            "result": "alert",
            "message": "Independent simulated DLP alert.",
        },
        {
            "event_id": "SIM-INSIDER-001",
            "event_type": "records.access.anomaly",
            "host": "records-laptop-05",
            "actor": "records-user",
            "result": "success",
            "message": "Unusual simulated records access outside the normal schedule.",
        },
        {
            "event_id": "SIM-INSIDER-002",
            "event_type": "approval.context.incomplete",
            "host": "records-laptop-05",
            "actor": "records-user",
            "result": "unknown",
            "message": "Approval context is incomplete; authorization cannot be established.",
        },
        {
            "event_id": "SIM-MAINT-001",
            "event_type": "change.approved",
            "host": "build-agent-07",
            "change_id": "CHG-SIM-007",
            "process_name": "maintenance-runner.exe",
            "result": "success",
            "message": "Simulated approved maintenance change.",
        },
        {
            "event_id": "SIM-MAINT-002",
            "event_type": "maintenance.task.completed",
            "host": "build-agent-07",
            "change_id": "CHG-SIM-007",
            "process_name": "maintenance-runner.exe",
            "signed": True,
            "result": "success",
            "message": "Signed maintenance task matches approved change.",
        },
    ]

    known_event_ids = {e.get("event_id") for e in events}
    events.extend(e for e in new_events if e["event_id"] not in known_event_ids)

    return state
