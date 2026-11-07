"""Treat external text as data. Embedded instructions never become policy."""

from __future__ import annotations

import copy
import re
from typing import Any

# Pattern id -> regex. Matched text is retained as evidence and never executed.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore_previous", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions", re.I)),
    ("disable_security", re.compile(r"disable\s+security", re.I)),
    ("force_resolve", re.compile(r"mark\s+(?:the\s+|this\s+)?incident\s+resolved", re.I)),
    ("auto_approve", re.compile(r"approve\s+all", re.I)),
    ("role_override", re.compile(r"you\s+are\s+now", re.I)),
    ("bypass_policy", re.compile(r"bypass\s+(?:the\s+)?policy", re.I)),
)


def instruction_hits(text: str) -> list[str]:
    """Return pattern ids found in text. This function does not act on them."""
    if not text:
        return []
    return [name for name, pattern in _PATTERNS if pattern.search(text)]


def _walk_strings(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.append(str(key))
            found.extend(_walk_strings(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_walk_strings(item))
    return found


def annotate_untrusted(data: dict[str, Any]) -> dict[str, Any]:
    """Copy data and flag embedded instructions. Original text is preserved."""
    payload = copy.deepcopy(data)
    hits: list[str] = []
    for chunk in _walk_strings(payload):
        for hit in instruction_hits(chunk):
            if hit not in hits:
                hits.append(hit)
    payload["injection_detected"] = bool(hits)
    payload["injection_patterns"] = hits
    payload["trust"] = "untrusted"
    return payload
