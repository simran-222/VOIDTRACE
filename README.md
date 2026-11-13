# VOIDTRACE

### Trust nothing. Verify everything.

VOIDTRACE is a defensive AI-powered security incident investigation and response platform.

VOIDTRACE is built on the idea: **Security decisions should be based on evidence, actions should require permission, and success should be independently verified.**

A security tool shouldn't simply detect something suspicious, execute an action and declare everything fixed. It should explain what happened, show the evidence behind its decision, check whether an action is permitted, require approval and verify the result afterward.


## What VOIDTRACE does

VOIDTRACE brings the incident investigation and response workflow into one platform.

- Investigates security incidents and collects supporting evidence.
- Correlates evidence and generates findings to explain suspicious activity.
- Evaluates response actions against a defined security policy.
- Requires approval before authorised response actions can execute.
- Uses controlled, single-use capabilities for approved actions.
- Independently verifies the resulting state instead of trusting an executor's success message.
- Maintains an audit trail so decisions and actions can be reviewed.
- Integrates with Switch for agent communication and operator interaction.

## How it works

The workflow follows a simple principle: investigate first, authorise second, execute only when permitted, and verify afterward.

1. **Incident intake** — An incident enters the investigation workflow.
2. **Evidence collection** — Relevant evidence is collected and associated with the incident.
3. **Investigation** — Findings are generated from available evidence.
4. **Threat assessment** — The incident is evaluated using investigation results.
5. **Policy evaluation** — The requested response is checked against the security policy.
6. **Human approval** — An authorised operator must approve the action.
7. **Capability issuance** — A time-limited, single-use capability is issued for the approved action.
8. **Response execution** — Only an allowed and approved action can proceed.
9. **Independent verification** — VOIDTRACE checks the resulting state separately and records the outcome.

The important part is that a successful execution response is not automatically treated as proof of remediation.

## Security and policy enforcement

Security controls are a central part of VOIDTRACE, not something added at the end.

### Security policy

VOIDTRACE uses an explicit eight-tool allowlist:

- Four read-only tools.
- Three mutation tools.
- One dedicated verification tool: `verify.read_state`.

This separates investigation, response and verification permissions.

### Policy integrity

The policy is protected using a SHA-256 fingerprint.

If the policy is modified unexpectedly, VOIDTRACE fails closed and records a `SECURITY_TAMPER_DETECTED` event rather than silently continuing with a changed policy.

### Human approval and capabilities

Response actions require matching, unexpired human approval.

Approved actions use a single-use capability. The capability is time-limited, and its hash is stored rather than relying on a reusable approval alone.

### API authentication

The deployed application includes Bearer-token authentication for mutating API requests.

- `VOIDTRACE_API_TOKEN` configures the API token.
- `VOIDTRACE_ALLOW_INSECURE_LOCAL_MUTATIONS` controls the explicit local-development exception.
- Public deployments should keep insecure local mutations disabled.
- Read-only dashboard and health requests remain accessible without the mutation token.

The dashboard stores the entered API token in browser session storage and attaches it to authorised mutation requests.

## Independent verification

Verification is one of the most important parts of VOIDTRACE.

The response executor does not get to decide whether its own action succeeded.

Instead, the verifier reads the resulting state separately and compares it with the expected state.

The verification result is recorded so that an operator can distinguish between:

- An action that was requested.
- An action that was authorised.
- An action that was executed.
- An action whose expected result was actually verified.

The demonstration environment uses simulated operations backed by SQLite.

## Audit trail and evidence integrity

VOIDTRACE records investigation and response activity so that decisions can be reviewed afterward.

The audit ledger uses a SHA-256 hash chain with a fixed genesis entry. Evidence records also have their own hashes.

This makes unexpected changes to recorded audit history detectable through integrity verification.

The application includes an audit verification endpoint:

`/api/audit/verify`

The goal is to make security decisions traceable rather than leaving operators with unexplained results.

## Switch integration

Switch is also integrated with VOIDTRACE so that the platform can communicate through an agent-based interface.

The integration includes:

- Switch agent registration.
- WebSocket connectivity.
- Relay-based communication between the hosted application and Switch.
- Configured agent-name handling.
- Operator addressing and message handling.
- Ping and status responses.

The integration completed a successful live message round-trip in Switch Town Square.

**Tested interaction:**

`@voidtrace-render ping`

**Response:**

`VOIDTRACE ONLINE — Switch connection verified. Backend healthy. SQLite connected.`

The successful round-trip was also reflected in the Switch status:

- Received: 1
- Sent: 1
- Live connection proven

This confirmed that the configured agent could receive and respond to an operator message through the integration.

## Dashboard

VOIDTRACE includes a web dashboard with the following sections:

| Section | Purpose |
|---|---|
| Overview | View platform and incident status |
| Incidents | Review and investigate security incidents |
| Evidence | Examine collected evidence |
| Response | Review and manage response actions |
| Verification | Check whether expected outcomes were achieved |
| Switch | View and interact with the Switch integration |
| Trust | Review trust and integrity information |
| Settings | Configure application-level settings |

## Technology

- **Backend:** Python, FastAPI
- **Frontend:** HTML, CSS and JavaScript
- **Database:** SQLite
- **Security:** SHA-256 integrity checks, policy enforcement, approval and capability controls, Bearer-token API authentication
- **Communication:** Switch, WebSockets and relay integration
- **Hosting:** Render
- **Testing:** Python automated test suite

## Run locally

### Requirements

- Python 3.13
- Git

### 1. Clone the repository

```bash
git clone https://github.com/simran-222/VOIDTRACE.git
cd VOIDTRACE
```

### 2. Create a virtual environment

```bash
py -3.13 -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

Configure the required values in `.env` for your environment.

### 5. Start the application

```bash
uvicorn app.main:app --reload
```

Open:

`http://127.0.0.1:8000`

## Testing

Run the automated test suite:

```powershell
python run_tests.py
```

The test suite covers areas including:

- API authentication.
- Protected mutation endpoints.
- Security policy enforcement.
- Approval and capability handling.
- Switch message and command handling.
- Incident and response workflows.
- Verification and audit integrity.

**Latest test result:**

```text
Ran 74 tests
OK

Tests Run: 74
Errors: 0
Failures: 0
```

The 74-test suite passed after the API authentication and Switch status changes.

## Deployment

VOIDTRACE is deployed as a Python web service on Render.

The deployed application includes:

- A working hosted dashboard.
- SQLite demonstration data.
- API authentication for mutation requests.
- Protected response and modification endpoints.
- Switch integration support.

The latest deployment uses commit `ef8d7ef` from the GitHub `main` branch.

The live dashboard and incident list were checked successfully after deployment.

The API token is configured through Render environment variables and must never be committed to the repository.


**VOIDTRACE — Trust nothing. Verify everything.**
