# VOIDTRACE

### Trust nothing. Verify everything.

**VOIDTRACE** is a defensive AI-powered security incident investigation and response platform that transforms untrusted reports and fragmented telemetry into evidence-backed decisions, controlled response simulations, and independently verified outcomes.

Built for the WeMakeDevs × DevTools Academy **Flip the Switch** hackathon.

VOIDTRACE investigates a locally simulated company environment. It does not interact with production infrastructure and does not require a paid language model.

## What VOIDTRACE Does

VOIDTRACE brings the security investigation and response workflow into one platform.

- **Evidence-driven investigation:** Correlates available telemetry, cites supporting evidence IDs, and distinguishes verified facts from assumptions.
- **Untrusted input protection:** Treats embedded instructions and unsupported claims as untrusted data rather than authority.
- **Risk assessment:** Evaluates incidents using available evidence and business impact.
- **Controlled response:** Proposes security actions and requires human approval for high-risk simulated changes.
- **Independent verification:** Checks the resulting simulated state instead of trusting an executor's success message.
- **Tamper-evident audit trail:** Records security events in a SHA-256 hash-chained SQLite ledger.

## Security Architecture

### NIGHTWATCH — Internal Security Layer

NIGHTWATCH is VOIDTRACE's internal security and policy enforcement layer.

It provides:

- Role-based and attribute-based access control.
- Capability-based authorization for protected operations.
- Policy enforcement before simulated tool calls and mutations.
- Fail-closed behaviour when policy integrity cannot be established.
- Human approval requirements for high-risk actions.

NIGHTWATCH is part of VOIDTRACE, not a separate product.

## How It Works

1. An incident report enters VOIDTRACE.
2. Available telemetry is collected and evaluated.
3. Findings are correlated with supporting evidence.
4. Unsupported or conflicting claims remain uncertain.
5. VOIDTRACE assesses risk and proposes an appropriate response.
6. Human approval is required where policy demands it.
7. The action runs against the local simulation.
8. An independent verifier checks the resulting state.
9. The audit ledger records the investigation and response history.

## Run Locally

Start the application:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

http://127.0.0.1:8000

The dashboard provides access to the investigation, evidence, response, verification, Switch integration, and audit history.

## One-Command Demo

Run:

```powershell
.\.venv\Scripts\python.exe -m app.demo
```

This creates `demo_data/voidtrace_demo.db` and refuses to delete `voidtrace.db`.

The demo applies a local operator approval for Avery Chen. Its transcript identifies the channel as local and does not claim a live Switch connection.

## Operation ShadowCredential

The signature demonstration investigates a simulated credential exposure involving:

- Host: `pay-worker-04`
- Credential: `cred-shadow-7f3a`
- Service: `payments-api`
- Suspicious process: `credharvest.exe`

VOIDTRACE evaluates the available IAM and process telemetry, distinguishes evidence from untrusted claims, and assesses the potential business impact.

It does not accept embedded instructions as authority, invent corroborating evidence, or treat an unverified lateral-movement rumor as fact.

The recommended response focuses on the affected credential and process rather than unnecessarily isolating a payment-critical host.

A separate report without an identifiable asset remains `INSUFFICIENT_EVIDENCE`.

## Switch Integration

VOIDTRACE supports integration with Switch Core through its agent registration, WebSocket, and messaging protocols.

Configure `SWITCH_REGISTRATION_TOKEN` in your local `.env` when connecting to a running Switch Core instance.

The registration token is not written to SQLite and is redacted from errors.

A successful registration alone is not sufficient to claim a verified connection. VOIDTRACE requires successful message delivery before reporting a proven live round trip.

The dashboard distinguishes simulated communication from a verified live Switch connection.

## Operator Commands

Supported command patterns include:

- `@voidtrace incident <report>`
- `@voidtrace status`
- `@voidtrace approve APR-...`
- `@voidtrace reject APR-...`
- `@voidtrace execute APR-...`
- `@voidtrace ping`

## Run Tests

```powershell
.\.venv\Scripts\python.exe run_tests.py
```

## Core Security Principles

1. **Evidence over assumptions:** Conclusions must cite stored evidence.
2. **Uncertainty over invention:** Missing or conflicting telemetry must not become fabricated facts.
3. **Policy before action:** Protected operations pass through NIGHTWATCH enforcement.
4. **Human accountability:** High-risk simulated changes require appropriate human approval.
5. **Independent verification:** An executor's success claim is not proof of a successful outcome.
6. **Audit integrity:** Security events are recorded in a tamper-evident hash-chained ledger.

---

**VOIDTRACE — Trust nothing. Verify everything.**
