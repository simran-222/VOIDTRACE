# VOIDTRACE

**Trust nothing. Verify everything.**

VOIDTRACE is a defensive security incident investigation and response platform that turns untrusted reports and fragmented telemetry into evidence-backed decisions, controlled response simulations, and independently verified outcomes.

It is designed around one principle: **a security decision should never be more certain than the evidence behind it.**

## Overview

Security incidents rarely arrive with a complete picture. Reports can be misleading, telemetry can conflict, and seemingly straightforward response actions can affect critical services.

VOIDTRACE brings investigation, policy enforcement, response simulation, and verification into one workflow.

The platform operates on local simulated environments. It does not execute remediation against production infrastructure.

## Key Capabilities

- **Evidence-based investigation** — Correlates available telemetry and links conclusions to supporting evidence.
- **Uncertainty handling** — Missing, conflicting, or uncorroborated information is not treated as confirmed fact.
- **Untrusted input handling** — Instructions embedded in incident reports, logs, and telemetry are treated as data, not commands.
- **Policy-controlled responses** — The internal SECURITY layer evaluates permissions before simulated tools or response actions can be accessed.
- **Approval controls** — High-risk actions require approval rather than being automatically executed.
- **Response simulation** — Proposed actions are tested in a local simulation instead of being applied to production systems.
- **Independent verification** — A separate verification step checks the resulting simulated state.
- **Tamper-evident audit trail** — Audit records are linked using a SHA-256 hash chain.

## How It Works

A typical incident moves through the following stages:

1. **Report intake** — An incident report is received and its claims are treated as unverified.
2. **Investigation** — Available telemetry is examined and relevant evidence is collected.
3. **Assessment** — Findings, confidence, risk, and business impact are evaluated.
4. **Policy evaluation** — SECURITY checks whether the requested operations are permitted.
5. **Approval** — Actions requiring human authorization remain pending until approval is provided.
6. **Simulation** — Permitted response actions are executed in the local simulation.
7. **Verification** — The resulting state is checked independently of the execution result.
8. **Audit** — Decisions, evidence, approvals, and outcomes are recorded.

## SECURITY

SECURITY is VOIDTRACE's internal policy enforcement layer, not a separate product.

It controls access to simulated operations through permission checks and policy rules. When a policy check fails or its integrity cannot be established, access is denied.

High-risk actions are subject to approval controls. A successful execution response alone is not considered proof that an action achieved its intended result.

## Running Locally

### Requirements

- Python 3.13+
- Windows (tested environment)

### Setup

Clone the repository and open the project directory:

```powershell
git clone https://github.com/simran-222/VOIDTRACE.git
cd VOIDTRACE
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start the application:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in a browser.

## Dashboard

The dashboard brings the main parts of the investigation workflow together:

- **Overview** — Incident summary and system status.
- **Incidents** — Incident reports and investigation results.
- **Evidence** — Collected telemetry and supporting evidence.
- **Response** — Proposed actions and approval status.
- **Verification** — Independent checks of simulated outcomes.
- **Switch** — Switch integration status and connectivity.
- **Trust** — Audit history and integrity checks.
- **Settings** — Application configuration.

## Demo

A standalone demo can be started with:

```powershell
.\.venv\Scripts\python.exe -m app.demo
```

The demo uses a separate database at:

```text
demo_data/voidtrace_demo.db
```

It does not use or overwrite the default `voidtrace.db` database.

The demo includes an approval workflow and a simulated response scenario.

## Example Investigation: Operation ShadowCredential

Operation ShadowCredential demonstrates how VOIDTRACE handles a suspicious credential-access incident.

The scenario involves:

- **Host:** `pay-worker-04`
- **Credential:** `cred-shadow-7f3a`
- **Service:** `payments-api`
- **Principal:** `svc-payments-reader`
- **Process:** `credharvest.exe`

The available telemetry includes an IAM read event, unsigned process telemetry referencing the credential, and an `iam.GetSecret` operation.

The investigation evaluates the evidence, identifies the risk, and considers the impact of possible response actions.

The recommended response focuses on disabling the affected credential and terminating the suspicious process. Isolating the entire host is avoided because of its potential impact on the payment service.

The scenario also tests how the platform handles misleading claims, untrusted instructions embedded in logs, and unrelated reports that cannot be corroborated.

## Switch Integration

VOIDTRACE integrates with a local Switch Core instance for agent communication.

The integration supports:

- Agent registration with Switch Core.
- WebSocket-based connection and event handling.
- Outbound message delivery.
- Inbound message handling.
- Automated-agent loop protection.
- Sender validation and platform-message filtering.
- Connection health reporting.

The Switch adapter includes safeguards against automated message loops, platform-generated pings, and unidentified senders.

A mock Switch server is also included for testing registration, authentication, messaging, and connection behaviour.

Registration credentials are supplied through local environment configuration and are not stored in the repository.

**Integration status:** Agent registration, live connectivity, and outbound message delivery have been verified against a live Switch Core instance. A live outbound message round-trip has also been confirmed. Human-to-agent addressing remains subject to Switch room membership and recipient policies and has not yet been verified end-to-end.

## Tests

Run the test suite with:

```powershell
.\.venv\Scripts\python.exe run_tests.py
```

The tests cover investigation workflows, policy controls, database integrity, application health, and Switch adapter behaviour.

## Core Principles

- Evidence before conclusions.
- Uncertainty instead of unsupported assumptions.
- Untrusted input never becomes an instruction.
- Policy checks before access or action.
- Human approval for high-risk operations.
- Simulation before real-world remediation.
- Independent verification after execution.
- Audit records designed to reveal tampering.

---

**VOIDTRACE — Trust nothing. Verify everything.**