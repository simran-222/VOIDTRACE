"""Parse operator commands from Switch room text.

Only the operator channel uses this parser. Evidence and logs never do.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from app.config import settings


def _mention_pattern(agent_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"^\s*(?:@|/|!)?{re.escape(agent_name)}\b[\s,:!-]*(.*)$",
        re.I | re.S,
    )


def parse_operator_command(
    body: str, *, agent_name: str | None = None
) -> Optional[dict[str, Any]]:
    """Return a command dict when the message is addressed to the agent.

    The mention is taken from ``settings.AGENT_NAME`` unless ``agent_name``
    is given, so each deployment answers its own name.

    Accepted commands, after the mention:
      ping
      status
      incident <report>
      investigate <report>
      approve <approval id> [comment]
      reject <approval id> [comment]
      execute <approval id>
    """
    if not body or not isinstance(body, str):
        return None
    resolved = agent_name if agent_name is not None else settings.AGENT_NAME
    name = (resolved or "").strip()
    if not name:
        return None
    match = _mention_pattern(name).match(body.strip())
    if not match:
        return None
    rest = match.group(1).strip()
    if not rest:
        return None
    lowered = rest.lower()
    if lowered == "ping":
        return {"command": "ping"}
    if lowered == "status":
        return {"command": "status"}
    for name in ("incident", "investigate"):
        prefix = name + " "
        if lowered.startswith(prefix):
            report = rest[len(prefix):].strip()
            if not report:
                return None
            return {"command": "incident", "report": report}
    for name in ("approve", "reject"):
        prefix = name + " "
        if lowered.startswith(prefix):
            parts = rest[len(prefix):].strip().split(None, 1)
            if not parts or not parts[0]:
                return None
            return {
                "command": name,
                "approval_id": parts[0],
                "comment": parts[1].strip() if len(parts) > 1 else "",
            }
    if lowered.startswith("execute "):
        approval_id = rest[len("execute "):].strip().split()[0] if rest[len("execute "):].strip() else ""
        if not approval_id:
            return None
        return {"command": "execute", "approval_id": approval_id}
    return None
