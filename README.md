# VOIDTRACE

Trust nothing. Verify everything.

VOIDTRACE is a defensive security incident investigation and response platform for the WeMakeDevs Flip the Switch hackathon. It investigates a local simulated company. It does not touch production infrastructure and it does not use a paid language model.

Two components share one product:

- **NIGHTWATCH** allows or denies every simulated tool call. A broken policy seal fails closed.
- **ZERO HOUR** correlates evidence, cites evidence IDs, and leaves uncorroborated claims as unknown.

## Run

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000

The dashboard reads the API. Run **Operation ShadowCredential** from the button labelled Run signature demo. That rebuilds only the simulated world. It does not delete incidents or the audit ledger.

Approve a proposal with your name, then execute it. The verifier reads simulated ground truth. If that state does not match, the incident is not resolved.

## One-command demo

This creates `demo_data/voidtrace_demo.db`. It refuses to delete `voidtrace.db`.

```powershell
.\.venv\Scripts\python.exe -m app.demo
```

The command applies a local operator approval for Avery Chen. The transcript says the channel is local. It does not claim a live Switch connection.

## Switch

The adapter speaks the verified agent protocol already in this repository: `POST /agents`, the agent WebSocket, and `POST /agents/{id}/message`. Set `SWITCH_REGISTRATION_TOKEN` in `.env` if Switch Core is running. The token is never written to SQLite and is redacted from errors.

Until a registration and a message post both succeed, the health payload reports `real_switch_proven: false`. The simulated room in the dashboard is labelled as a simulation.

Operator commands, after a mention:

- `@voidtrace incident <report>`
- `@voidtrace status`
- `@voidtrace approve APR-...`
- `@voidtrace reject APR-...`
- `@voidtrace execute APR-...`
- `@voidtrace ping`

## Tests

```powershell
.\.venv\Scripts\python.exe run_tests.py
```

## Signature case

**The incident that AI refused to guess.** A simulated payments credential is read by an unsigned process. A log also contains an embedded instruction, a contradictory vendor-signature claim, and an uncorroborated lateral-movement rumor. ZERO HOUR confirms only the three-source exposure, ignores the instruction, and refuses to name a second host. A separate report that names no asset stays `INSUFFICIENT_EVIDENCE`.

High-risk simulated changes require a person. Host isolation is not proposed because the asset record says it would stop payment authorization, and the evidence is one process.

## Principles in code

1. Facts cite stored evidence. A human sentence is not proof.
2. Simulated mutations require a one-use NIGHTWATCH capability. Direct calls raise.
3. Verification re-reads the simulated world. An executor success flag cannot resolve an incident.
