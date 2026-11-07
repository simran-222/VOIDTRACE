"""Shared application errors."""

from __future__ import annotations

from typing import Any, Optional


class WorkflowError(Exception):
    """A caller-facing workflow rejection with an HTTP status."""

    def __init__(self, message: str, status_code: int = 409, code: str = "workflow_error") -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class SecurityDenied(Exception):
    """SECURITY refused a tool operation. Fail closed."""

    def __init__(self, decision: dict[str, Any]) -> None:
        super().__init__(decision.get("reason", "denied"))
        self.decision = decision


class SecurityBypassError(Exception):
    """A state-changing simulated tool was called without SECURITY."""


class SimulationUnavailable(Exception):
    """Ground truth could not be read. Callers must report UNVERIFIED, not success."""


def public_decision(decision: dict[str, Any]) -> dict[str, Any]:
    """Return a decision dict that is safe to show in an API response."""
    hidden = {"token", "token_hash", "api_key"}
    return {key: value for key, value in decision.items() if key not in hidden}
