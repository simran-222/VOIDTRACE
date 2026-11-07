"""End-to-end checks for SECURITY, approvals, verification, isolation, and the signature demo."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from app.config import settings
from app.database import get_db_connection, init_db, verify_ledger_integrity
from app.demo import run_shadow_scenario
from app.errors import SecurityBypassError, SecurityDenied, WorkflowError
from app.security import security
from app.simulation import disable_credential, dispatch, read_ground_truth
from app.workflow import (
    _insert_proposal,
    decide,
    execute_approved,
    handle_operator_event,
    investigate,
    judge_snapshot,
    verify_approval,
    verify_evidence_integrity,
)
from app.controls import control_board


class TestSignaturePlatform(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._previous_db = settings.DATABASE_PATH
        self._previous_token = settings.SWITCH_REGISTRATION_TOKEN
        self._previous_autoconnect = settings.AUTO_CONNECT_SWITCH
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "platform.db"
        settings.DATABASE_PATH = self.db_path
        settings.AUTO_CONNECT_SWITCH = False
        init_db(self.db_path)
        security.restore()

    async def asyncTearDown(self) -> None:
        security.restore()
        settings.DATABASE_PATH = self._previous_db
        settings.SWITCH_REGISTRATION_TOKEN = self._previous_token
        settings.AUTO_CONNECT_SWITCH = self._previous_autoconnect
        self.temp_dir.cleanup()

    async def test_shadow_credential_refuses_to_guess_then_verifies(self) -> None:
        snapshot = read_after = None
        result = await run_shadow_scenario(auto_approve=False, channel="test", simulation=True)
        self.assertFalse(result["real_switch_proven"])
        self.assertFalse(result["user_database_wiped"])
        shadow = result["shadow"]
        self.assertEqual(shadow["incident"]["status"], "AWAITING_APPROVAL")
        self.assertTrue(any(item["kind"] == "unknown" for item in shadow["findings"]))
        self.assertTrue(any(item["category"] == "injection" for item in shadow["findings"]))
        self.assertTrue(any(item["category"] == "contradiction" for item in shadow["findings"]))
        self.assertEqual(shadow["assessment"]["risk_score"], 80)
        self.assertIn("payments-api", shadow["assessment"]["business_impact"]["service"])
        self.assertTrue(shadow["approvals"])
        self.assertTrue(all(item["status"] in {"PROPOSED", "AWAITING_APPROVAL"} for item in shadow["approvals"]))
        evidence_ids = {item["id"] for item in shadow["evidence"]}
        for finding in shadow["findings"]:
            if finding["kind"] == "fact":
                self.assertTrue(finding["evidence_ids"])
                self.assertTrue(set(finding["evidence_ids"]).issubset(evidence_ids))
        evidence_ok, evidence_msg = verify_evidence_integrity(shadow["incident"]["id"])
        self.assertTrue(evidence_ok, evidence_msg)

        state = _world()
        claim = judge_snapshot(
            {
                "credentials": {"cred-shadow-7f3a": {"status": state["credentials"]["cred-shadow-7f3a"]["status"]}},
                "processes": [],
                "assets": {},
            },
            {"type": "credential", "id": "cred-shadow-7f3a", "field": "status", "equals": "DISABLED"},
            claimed_result={"reported_status": "DISABLED"},
        )
        self.assertEqual(claim["verification_result"], "FAILED")
        self.assertEqual(claim["actual"], "ACTIVE")
        self.assertTrue(claim["ignored_executor_claim"])

        with self.assertRaises(SecurityBypassError):
            disable_credential("cred-shadow-7f3a")
        self.assertEqual(_world()["credentials"]["cred-shadow-7f3a"]["status"], "ACTIVE")

        approval = shadow["approvals"][0]
        with self.assertRaises(WorkflowError):
            execute_approved(approval["id"])
        self.assertEqual(_world()["credentials"]["cred-shadow-7f3a"]["status"], "ACTIVE")

        with self.assertRaises(WorkflowError) as denied_actor:
            decide(approval["id"], "approve", "VOIDTRACE", channel="test")
        self.assertEqual(denied_actor.exception.code, "approver_rejected")

        decided = decide(approval["id"], "approve", "Avery Chen", channel="test", comment="reviewed")
        self.assertEqual(decided["status"], "APPROVED")
        with self.assertRaises(WorkflowError) as duplicate:
            decide(approval["id"], "approve", "Avery Chen", channel="test")
        self.assertEqual(duplicate.exception.code, "duplicate_decision")

        with self.assertRaises(SecurityDenied) as actor_block:
            _expect_denied(lambda conn: security.execute(
                conn,
                actor="VOIDTRACE",
                tool=approval["action"],
                resource=approval["resource"],
                incident_id=shadow["incident"]["id"],
                approval_id=approval["id"],
            ))
        self.assertEqual(actor_block.exception.decision["reason"], "actor_not_permitted")

        first = execute_approved(approval["id"])
        self.assertEqual(first["verification_result"], "VERIFIED")
        self.assertNotEqual(first["incident_status"], "RESOLVED")
        again = verify_approval(approval["id"], claimed_result={"reported_status": "STILL_ACTIVE"})
        self.assertEqual(again["verification_result"], "VERIFIED")
        self.assertTrue(again["ignored_executor_claim"])

        for pending in result["shadow"]["approvals"][1:]:
            decide(pending["id"], "approve", "Avery Chen", channel="test")
            outcome = execute_approved(pending["id"])
            self.assertEqual(outcome["verification_result"], "VERIFIED")
        final_status = execute_approved.__wrapped__ if False else None
        bundle_status = __import__("app.workflow", fromlist=["incident_bundle"]).incident_bundle(shadow["incident"]["id"])
        self.assertEqual(bundle_status["incident"]["status"], "RESOLVED")
        self.assertIsNotNone(bundle_status["incident"]["resolved_at"])
        ledger_ok, ledger_msg = verify_ledger_integrity(self.db_path)
        self.assertTrue(ledger_ok, ledger_msg)
        del snapshot, read_after, final_status

    async def test_vague_incident_and_requirements_are_observed(self) -> None:
        result = await run_shadow_scenario(auto_approve=False, channel="test", simulation=True)
        vague = result["vague"]
        self.assertEqual(vague["incident"]["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(vague["approvals"], [])
        self.assertEqual(vague["assessment"]["risk_score"], 0)
        self.assertIn("refused to guess", vague["assessment"]["headline"].lower())

        shadow_id = result["shadow_incident_id"]
        with self.assertRaises(SecurityDenied) as misuse:
            _expect_denied(lambda conn: security.execute(
                conn,
                actor="VOIDTRACE",
                tool="iam.read_credential",
                resource="credential:cred-hr-portal",
                incident_id=shadow_id,
            ))
        self.assertEqual(misuse.exception.decision["reason"], "resource_outside_incident_scope")

        with self.assertRaises(SecurityDenied) as unknown_tool:
            _expect_denied(lambda conn: (
                security.grant(conn, shadow_id, "evil:resource", "test"),
                security.execute(
                    conn,
                    actor="VOIDTRACE",
                    tool="response.drop_database",
                    resource="evil:resource",
                    incident_id=shadow_id,
                ),
            ))
        self.assertEqual(unknown_tool.exception.decision["reason"], "tool_not_allowlisted")

        hr = _open(title="HR portal check", report="Look at credential cred-hr-portal only.")
        investigate(hr)
        with self.assertRaises(SecurityDenied) as isolated:
            _expect_denied(lambda conn: security.execute(
                conn,
                actor="VOIDTRACE",
                tool="iam.read_credential",
                resource="credential:cred-shadow-7f3a",
                incident_id=hr,
            ))
        self.assertEqual(isolated.exception.decision["reason"], "resource_outside_incident_scope")

        disable = next(item for item in result["shadow"]["approvals"] if item["action"] == "response.disable_credential")
        conn = _connect()
        try:
            with conn:
                _insert_proposal(conn, shadow_id, {
                    "action": "response.disable_credential",
                    "resource": "credential:cred-shadow-7f3a",
                    "risk": "HIGH",
                    "conflict_group": "credential:cred-shadow-7f3a",
                    "justification": "Conflicting second disable.",
                    "evidence_ids": disable["evidence_ids"],
                    "expected": disable["expected"],
                })
        finally:
            conn.close()
        decide(disable["id"], "approve", "Avery Chen", channel="test")
        from app.workflow import incident_bundle
        sibling = next(item for item in incident_bundle(shadow_id)["approvals"] if item["id"] != disable["id"] and item["resource"] == disable["resource"])
        self.assertEqual(sibling["status"], "REJECTED")
        with self.assertRaises(WorkflowError):
            decide(sibling["id"], "approve", "Avery Chen", channel="test")

        conn = _connect()
        try:
            conn.execute(
                "UPDATE approvals SET expires_at = ? WHERE id = ?;",
                ("2000-01-01T00:00:00+00:00", sibling["id"]),
            )
            # The sibling is already rejected. Expire a fresh proposed row instead.
            with conn:
                expired = _insert_proposal(conn, shadow_id, {
                    "action": "response.isolate_host",
                    "resource": "host:pay-worker-04",
                    "risk": "CRITICAL",
                    "conflict_group": "host:pay-worker-04",
                    "justification": "Expires before a person decides.",
                    "evidence_ids": disable["evidence_ids"],
                    "expected": {"type": "host", "id": "pay-worker-04", "field": "isolated", "equals": True},
                })
                conn.execute(
                    "UPDATE approvals SET expires_at = ? WHERE id = ?;",
                    ("2000-01-01T00:00:00+00:00", expired["id"]),
                )
        finally:
            conn.close()
        with self.assertRaises(WorkflowError) as expired_decision:
            decide(expired["id"], "approve", "Avery Chen", channel="test")
        self.assertEqual(expired_decision.exception.code, "approval_expired")

        try:
            security._policy["tools"]["evil.tool"] = {"effect": "mutate", "approval": False, "actors": ["VOIDTRACE"], "risk": "LOW"}
            self.assertFalse(security.intact())
            with self.assertRaises(SecurityDenied) as tamper:
                _expect_denied(lambda conn: security.execute(
                    conn,
                    actor="VOIDTRACE",
                    tool="iam.read_credential",
                    resource="credential:cred-shadow-7f3a",
                    incident_id=shadow_id,
                ))
            self.assertEqual(tamper.exception.decision["reason"], "policy_integrity_failure")
        finally:
            security.restore()
        self.assertTrue(security.intact())

        conn = _connect()
        try:
            with self.assertRaises(SecurityBypassError):
                dispatch(conn, "response.disable_credential", "credential:cred-hr-portal", "", hr, "2026-11-06T00:00:00+00:00")
            self.assertEqual(read_ground_truth(conn)["credentials"]["cred-hr-portal"]["status"], "ACTIVE")
        finally:
            conn.close()

        await handle_operator_event(
            {
                "type": "message",
                "room_id": "room-sim",
                "payload": {
                    "body": "@voidtrace status",
                    "sender_name": "Avery Chen",
                    "sender_kind": "user",
                    "message_id": "msg-status-1",
                },
            },
            channel="switch_simulation",
        )
        duplicate = await handle_operator_event(
            {
                "type": "message",
                "room_id": "room-sim",
                "payload": {
                    "body": "@voidtrace status",
                    "sender_name": "Avery Chen",
                    "sender_kind": "user",
                    "message_id": "msg-status-1",
                },
            },
            channel="switch_simulation",
        )
        self.assertTrue(duplicate["duplicate"])
        self.assertFalse(duplicate["real_switch_proven"])

        observed = {item["id"]: item["observed"] for item in control_board()}
        missing = [item_id for item_id, seen in observed.items() if not seen]
        self.assertEqual(missing, [], control_board())

    async def test_legacy_database_stays_verifiable(self) -> None:
        source = Path("voidtrace.db")
        if not source.exists():
            self.skipTest("voidtrace.db is not present")
        target = Path(self.temp_dir.name) / "legacy.db"
        shutil.copy(source, target)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(source) + suffix)
            if sidecar.exists():
                shutil.copy(sidecar, Path(str(target) + suffix))
        init_db(target)
        ok, message = verify_ledger_integrity(target)
        self.assertTrue(ok, message)
        ok_after, _ = verify_ledger_integrity(source)
        self.assertTrue(ok_after)


def _connect():
    return get_db_connection()


def _world() -> dict:
    conn = get_db_connection()
    try:
        return read_ground_truth(conn)
    finally:
        conn.close()


def _expect_denied(fn) -> None:
    conn = get_db_connection()
    try:
        try:
            fn(conn)
        except SecurityDenied:
            conn.commit()
            raise
        conn.commit()
    finally:
        conn.close()


def _open(*, title: str, report: str) -> str:
    from app.workflow import create_incident_record

    conn = get_db_connection()
    try:
        with conn:
            created = create_incident_record(
                conn,
                title=title,
                severity="MEDIUM",
                switch_room_id="room-hr",
                metadata={"report": report, "channel": "test"},
            )
        return created["id"]
    finally:
        conn.close()


if __name__ == "__main__":
    unittest.main()
