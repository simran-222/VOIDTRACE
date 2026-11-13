"""HTTP authentication tests for every mutating VOIDTRACE endpoint."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import SecretStr

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import settings

settings.AUTO_CONNECT_SWITCH = False

from app.main import app


TOKEN = "unit-test-api-token"
WRONG_TOKEN = "unit-test-wrong-token"

MUTATING_ENDPOINTS = (
    ("/api/incidents", {"title": "Auth test", "severity": "LOW", "report": "No evidence."}),
    ("/api/incidents/INC-AUTH/investigate", None),
    (
        "/api/incidents/INC-AUTH/approvals/APR-AUTH/decision",
        {
            "decision": "approve",
            "approver": "Avery Chen",
            "comment": "Dashboard decision",
            "channel": "local_dashboard",
        },
    ),
    ("/api/incidents/INC-AUTH/approvals/APR-AUTH/execute", None),
    ("/api/incidents/INC-AUTH/verify", None),
    (
        "/api/switch/simulate",
        {"room_id": "room-auth", "body": "@voidtrace status", "sender_name": "Avery Chen"},
    ),
    ("/api/demo/shadow-credential", None),
)


def _auth(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _post(client: TestClient, path: str, payload: object = None, headers: dict[str, str] | None = None):
    if payload is None:
        return client.post(path, headers=headers)
    return client.post(path, json=payload, headers=headers)


class ApiAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "api_auth.db"
        self._previous_db = settings.DATABASE_PATH
        self._previous_auto_connect = settings.AUTO_CONNECT_SWITCH
        self._previous_token = settings.VOIDTRACE_API_TOKEN
        self._previous_opt_in = settings.VOIDTRACE_ALLOW_INSECURE_LOCAL_MUTATIONS
        settings.DATABASE_PATH = self.db_path
        settings.AUTO_CONNECT_SWITCH = False
        settings.VOIDTRACE_API_TOKEN = SecretStr("")
        settings.VOIDTRACE_ALLOW_INSECURE_LOCAL_MUTATIONS = False

    def tearDown(self) -> None:
        settings.DATABASE_PATH = self._previous_db
        settings.AUTO_CONNECT_SWITCH = self._previous_auto_connect
        settings.VOIDTRACE_API_TOKEN = self._previous_token
        settings.VOIDTRACE_ALLOW_INSECURE_LOCAL_MUTATIONS = self._previous_opt_in
        self.temp_dir.cleanup()

    def _client(self, *, loopback: bool = True) -> TestClient:
        client_address = ("127.0.0.1", 50000) if loopback else ("testclient", 50000)
        return TestClient(app, client=client_address)

    def test_every_mutating_endpoint_rejects_missing_token(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        with self._client() as client:
            for path, payload in MUTATING_ENDPOINTS:
                with self.subTest(path=path):
                    response = _post(client, path, payload)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.headers.get("www-authenticate"), "Bearer")
                    self.assertNotIn(TOKEN, response.text)

    def test_every_mutating_endpoint_rejects_incorrect_token(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        with self._client() as client:
            for path, payload in MUTATING_ENDPOINTS:
                with self.subTest(path=path):
                    response = _post(client, path, payload, headers=_auth(WRONG_TOKEN))
                    self.assertEqual(response.status_code, 401)
                    self.assertNotIn(TOKEN, response.text)

    def test_bearer_scheme_is_the_only_accepted_credential(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        payload = {"room_id": "room-auth", "body": "@voidtrace status", "sender_name": "Avery Chen"}
        with self._client() as client:
            self.assertEqual(
                client.post("/api/switch/simulate", json=payload, headers={"Authorization": f"Basic {TOKEN}"}).status_code,
                401,
            )
            self.assertEqual(
                client.post("/api/switch/simulate", json=payload, headers={"X-Voidtrace-Api-Token": TOKEN}).status_code,
                401,
            )
            self.assertEqual(
                client.post("/api/switch/simulate?token=query-token-not-used", json=payload).status_code,
                401,
            )
            self.assertEqual(
                client.post("/api/switch/simulate", json=payload, headers={"Authorization": "Bearer"}).status_code,
                401,
            )

    def test_put_patch_and_delete_require_a_token(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        with self._client() as client:
            for method in ("put", "patch", "delete"):
                with self.subTest(method=method):
                    response = getattr(client, method)("/api/incidents")
                    self.assertEqual(response.status_code, 401)

    def test_correct_token_allows_all_mutations_and_dashboard_workflow(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        with self._client() as client:
            created = client.post(
                "/api/incidents",
                json={"title": "Auth workflow", "severity": "LOW", "report": "No evidence."},
                headers=_auth(),
            )
            self.assertEqual(created.status_code, 201)
            incident_id = created.json()["id"]

            investigated = client.post(f"/api/incidents/{incident_id}/investigate", headers=_auth())
            self.assertEqual(investigated.status_code, 200)

            demo = client.post("/api/demo/shadow-credential", headers=_auth())
            self.assertEqual(demo.status_code, 200)
            shadow_id = demo.json()["shadow_incident_id"]

            bundle = client.get(f"/api/incidents/{shadow_id}")
            self.assertEqual(bundle.status_code, 200)
            approvals = bundle.json()["approvals"]
            self.assertTrue(approvals)
            approval_id = approvals[0]["id"]

            decision = client.post(
                f"/api/incidents/{shadow_id}/approvals/{approval_id}/decision",
                json={
                    "decision": "approve",
                    "approver": "Avery Chen",
                    "comment": "Dashboard decision",
                    "channel": "local_dashboard",
                },
                headers=_auth(),
            )
            self.assertEqual(decision.status_code, 200)
            self.assertEqual(decision.json()["approval"]["status"], "APPROVED")

            executed = client.post(
                f"/api/incidents/{shadow_id}/approvals/{approval_id}/execute",
                headers=_auth(),
            )
            self.assertEqual(executed.status_code, 200)
            self.assertEqual(executed.json()["verification_result"], "VERIFIED")

            verified = client.post(f"/api/incidents/{shadow_id}/verify", headers=_auth())
            self.assertEqual(verified.status_code, 200)

            simulated = client.post(
                "/api/switch/simulate",
                json={"room_id": "room-auth", "body": "@voidtrace status", "sender_name": "Avery Chen"},
                headers=_auth(),
            )
            self.assertEqual(simulated.status_code, 200)
            self.assertFalse(simulated.json()["real_switch_proven"])

    def test_unset_token_fails_closed_for_public_and_local_requests(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr("")
        settings.VOIDTRACE_ALLOW_INSECURE_LOCAL_MUTATIONS = False
        payload = {"room_id": "room-auth", "body": "@voidtrace status", "sender_name": "Avery Chen"}

        with self._client(loopback=False) as client:
            response = client.post("/api/switch/simulate", json=payload)
            self.assertEqual(response.status_code, 403)

        with self._client(loopback=True) as client:
            response = client.post("/api/switch/simulate", json=payload)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(client.get("/health").status_code, 200)

    def test_explicit_local_opt_in_allows_only_loopback(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr("")
        settings.VOIDTRACE_ALLOW_INSECURE_LOCAL_MUTATIONS = True
        payload = {"room_id": "room-auth", "body": "@voidtrace status", "sender_name": "Avery Chen"}

        with self._client(loopback=True) as client:
            response = client.post("/api/switch/simulate", json=payload)
            self.assertEqual(response.status_code, 200)

        with self._client(loopback=False) as client:
            response = client.post("/api/switch/simulate", json=payload)
            self.assertEqual(response.status_code, 403)

    def test_configured_token_takes_precedence_over_local_opt_in(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        settings.VOIDTRACE_ALLOW_INSECURE_LOCAL_MUTATIONS = True
        payload = {"room_id": "room-auth", "body": "@voidtrace status", "sender_name": "Avery Chen"}

        with self._client(loopback=True) as client:
            response = client.post("/api/switch/simulate", json=payload)
            self.assertEqual(response.status_code, 401)

    def test_get_health_static_and_dashboard_reads_remain_open(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        with self._client() as client:
            for path in ("/health", "/", "/static/app.js", "/api/overview", "/api/switch/feed", "/api/incidents"):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 200)
            self.assertEqual(
                client.get("/health", headers={"Authorization": f"Bearer {WRONG_TOKEN}"}).status_code,
                200,
            )

    def test_token_is_not_leaked_in_responses_logs_or_settings_repr(self) -> None:
        settings.VOIDTRACE_API_TOKEN = SecretStr(TOKEN)
        payload = {"room_id": "room-auth", "body": "@voidtrace status", "sender_name": "Avery Chen"}
        records: list[str] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = Capture()
        handler.setLevel(logging.DEBUG)
        root = logging.getLogger()
        previous_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            with self._client() as client:
                responses = (
                    client.post("/api/switch/simulate", json=payload),
                    client.post("/api/switch/simulate", json=payload, headers=_auth(WRONG_TOKEN)),
                    client.post("/api/switch/simulate", json=payload, headers=_auth()),
                )
                for response in responses:
                    self.assertNotIn(TOKEN, response.text)
                    self.assertNotIn(TOKEN, str(response.headers))
            self.assertNotIn(TOKEN, repr(settings))
            self.assertNotIn(TOKEN, str(settings))
            self.assertNotIn(TOKEN, repr(settings.VOIDTRACE_API_TOKEN))
        finally:
            root.removeHandler(handler)
            root.setLevel(previous_level)

        self.assertFalse(any(TOKEN in record for record in records))


if __name__ == "__main__":
    unittest.main()
