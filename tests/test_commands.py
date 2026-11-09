"""Unit tests for operator command mention parsing."""

from __future__ import annotations

import unittest

from app.commands import parse_operator_command
from app.config import settings


class TestCommandMentionParsing(unittest.TestCase):
    """parse_operator_command() must follow settings.AGENT_NAME."""

    def setUp(self) -> None:
        self._original_name = settings.AGENT_NAME

    def tearDown(self) -> None:
        settings.AGENT_NAME = self._original_name

    def test_local_voidtrace_commands(self) -> None:
        settings.AGENT_NAME = "voidtrace"
        self.assertEqual(
            parse_operator_command("@voidtrace ping"),
            {"command": "ping"},
        )
        self.assertEqual(
            parse_operator_command("@voidtrace status"),
            {"command": "status"},
        )
        self.assertEqual(
            parse_operator_command("@voidtrace incident suspicious login"),
            {"command": "incident", "report": "suspicious login"},
        )

    def test_render_voidtrace_commands(self) -> None:
        settings.AGENT_NAME = "voidtrace-render"
        self.assertEqual(
            parse_operator_command("@voidtrace-render ping"),
            {"command": "ping"},
        )
        self.assertEqual(
            parse_operator_command("@voidtrace-render status"),
            {"command": "status"},
        )
        self.assertEqual(
            parse_operator_command("@voidtrace-render incident suspicious login"),
            {"command": "incident", "report": "suspicious login"},
        )

    def test_explicit_agent_name_overrides_settings(self) -> None:
        settings.AGENT_NAME = "voidtrace"
        self.assertEqual(
            parse_operator_command(
                "@voidtrace-render status", agent_name="voidtrace-render"
            ),
            {"command": "status"},
        )

    def test_other_agent_mention_is_not_parsed(self) -> None:
        settings.AGENT_NAME = "voidtrace"
        self.assertIsNone(parse_operator_command("@voidtrace-render status"))
        settings.AGENT_NAME = "voidtrace-render"
        self.assertIsNone(parse_operator_command("@voidtrace status"))


if __name__ == "__main__":
    unittest.main()
