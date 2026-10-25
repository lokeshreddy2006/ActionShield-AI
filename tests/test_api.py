"""Integration tests for the ActionShield AI FastAPI endpoints."""

import os
import tempfile
import unittest

from fastapi.testclient import TestClient

from app.database.manager import DatabaseManager
from app.main import app, get_audit_service, get_execution_service
from app.services.audit import AuditService
from app.services.executor import ExecutionService, InMemoryWorkspace


class TestAPIEndpoints(unittest.TestCase):
    """Test suite for FastAPI endpoints with isolated test database."""

    def setUp(self):
        # Create an isolated temporary SQLite database for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = os.path.join(self.temp_dir.name, "test_api_audit.db")
        self.test_db_manager = DatabaseManager(db_path=self.test_db_path)
        self.test_audit_service = AuditService(db_manager=self.test_db_manager)
        self.test_workspace = InMemoryWorkspace({
            "workspace/existing_file.txt": "Initial test file content",
        })
        self.test_execution_service = ExecutionService(workspace=self.test_workspace)

        # Apply FastAPI dependency injection overrides
        app.dependency_overrides[get_audit_service] = lambda: self.test_audit_service
        app.dependency_overrides[get_execution_service] = lambda: self.test_execution_service

        self.client = TestClient(app)

    def tearDown(self):
        # Clean up overrides and temporary database directory
        app.dependency_overrides.clear()
        self.temp_dir.cleanup()

    # ---------------------------------------------------------
    # 1. GET /health
    # ---------------------------------------------------------

    def test_health_check_endpoint(self):
        """GET /health must return status 200 and {'status': 'ok'}."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    # ---------------------------------------------------------
    # 2. POST /evaluate (ALLOW, REVIEW, BLOCK)
    # ---------------------------------------------------------

    def test_evaluate_valid_read_file_allow(self):
        """Valid non-sensitive read file should return ALLOW."""
        payload = {
            "action_type": "READ_FILE",
            "path": "workspace/reports/quarterly.txt",
            "is_sensitive": False,
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "ALLOW")
        self.assertEqual(data["action_type"], "READ_FILE")
        self.assertIn("allowed", data["reason"].lower())

    def test_evaluate_valid_write_file_allow(self):
        """Writing to permitted workspace location should return ALLOW."""
        payload = {
            "action_type": "WRITE_FILE",
            "path": "workspace/output.csv",
            "is_permitted_location": True,
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "ALLOW")
        self.assertEqual(data["action_type"], "WRITE_FILE")

    def test_evaluate_delete_file_review(self):
        """DELETE_FILE should produce REVIEW by default."""
        payload = {
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_data.csv",
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "REVIEW")
        self.assertEqual(data["action_type"], "DELETE_FILE")

    def test_evaluate_run_command_review(self):
        """RUN_COMMAND should produce REVIEW by default."""
        payload = {
            "action_type": "RUN_COMMAND",
            "command": "npm run build",
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "REVIEW")
        self.assertEqual(data["action_type"], "RUN_COMMAND")

    def test_evaluate_send_data_external_review(self):
        """SEND_DATA to external destination should produce REVIEW by default."""
        payload = {
            "action_type": "SEND_DATA",
            "destination": "https://api.external-service.com/webhook",
            "is_sensitive": False,
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "REVIEW")

    def test_evaluate_send_data_sensitive_block(self):
        """SEND_DATA with is_sensitive=True must produce BLOCK."""
        payload = {
            "action_type": "SEND_DATA",
            "destination": "https://api.external-service.com/webhook",
            "is_sensitive": True,
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "BLOCK")
        self.assertIn("sensitive", data["reason"].lower())

    def test_evaluate_read_sensitive_file_block(self):
        """READ_FILE targeting .env should produce BLOCK."""
        payload = {
            "action_type": "READ_FILE",
            "path": ".env",
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "BLOCK")
        self.assertIn("sensitive", data["reason"].lower())

    def test_evaluate_unknown_action_type_block(self):
        """Unknown action type must be BLOCK."""
        payload = {
            "action_type": "EXECUTE_ARBITRARY_PAYLOAD",
            "target": "target_host",
        }
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "BLOCK")
        self.assertIn("unknown", data["reason"].lower())

    def test_evaluate_missing_action_type_block(self):
        """Payload missing action_type must be BLOCK."""
        payload = {"path": "some_file.txt"}
        response = self.client.post("/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "BLOCK")
        self.assertEqual(data["action_type"], "UNKNOWN")

    def test_evaluate_empty_dict_payload_block(self):
        """Empty payload dictionary must be BLOCK."""
        response = self.client.post("/evaluate", json={})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "BLOCK")
        self.assertEqual(data["action_type"], "UNKNOWN")

    def test_evaluate_non_dict_payload_block(self):
        """Non-dictionary payload (e.g. a string) must be BLOCK."""
        response = self.client.post("/evaluate", json="not a dictionary")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"], "BLOCK")

    def test_evaluate_ambiguous_never_defaults_to_allow(self):
        """Ambiguous/malformed requests must never default to ALLOW."""
        ambiguous_payloads = [
            {},
            {"action_type": "READ_FILE"},
            {"action_type": "WRITE_FILE", "path": "unverified.txt"},
            {"action_type": "DELETE_FILE"},
            {"action_type": "SEND_DATA"},
            {"action_type": "RUN_COMMAND"},
        ]
        for payload in ambiguous_payloads:
            response = self.client.post("/evaluate", json=payload)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertNotEqual(
                data["decision"],
                "ALLOW",
                f"Payload unexpectedly allowed: {payload}",
            )

    # ---------------------------------------------------------
    # 3. Non-Execution in /evaluate Endpoint
    # ---------------------------------------------------------

    def test_evaluating_delete_action_never_deletes_file(self):
        """Evaluating DELETE_FILE must never actually delete the file from disk."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(b"critical system data")

        try:
            self.assertTrue(os.path.exists(temp_path))
            payload = {"action_type": "DELETE_FILE", "path": temp_path}
            response = self.client.post("/evaluate", json=payload)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(os.path.exists(temp_path))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_evaluating_write_action_never_writes_file(self):
        """Evaluating WRITE_FILE must never actually create or modify a file on disk."""
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = os.path.join(temp_dir, "non_existent_file.txt")
            self.assertFalse(os.path.exists(target_path))

            payload = {
                "action_type": "WRITE_FILE",
                "path": target_path,
                "is_permitted_location": True,
            }
            response = self.client.post("/evaluate", json=payload)
            self.assertEqual(response.status_code, 200)
            self.assertFalse(os.path.exists(target_path))

    def test_evaluating_run_command_never_executes_command(self):
        """Evaluating RUN_COMMAND must never execute the command."""
        with tempfile.TemporaryDirectory() as temp_dir:
            marker_file = os.path.join(temp_dir, "executed_marker.txt")
            self.assertFalse(os.path.exists(marker_file))

            payload = {
                "action_type": "RUN_COMMAND",
                "command": f"echo 'executed' > {marker_file}",
            }
            response = self.client.post("/evaluate", json=payload)
            self.assertEqual(response.status_code, 200)
            self.assertFalse(os.path.exists(marker_file))

    # ---------------------------------------------------------
    # 4. POST /execute Tests
    # ---------------------------------------------------------

    def test_execute_allow_action(self):
        """POST /execute with an ALLOW action executes simulation and logs result."""
        payload = {
            "action_type": "WRITE_FILE",
            "path": "workspace/audit_test.log",
            "content": "simulated content",
            "is_permitted_location": True,
        }
        response = self.client.post("/execute", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["action_type"], "WRITE_FILE")
        self.assertEqual(data["policy_decision"], "ALLOW")
        self.assertEqual(data["execution_status"], "EXECUTED")
        self.assertIn("virtual workspace", data["message"])
        self.assertIsNotNone(data["simulated_result"])
        self.assertTrue(data["simulated_result"]["simulated"])

        # Verify virtual workspace received update
        self.assertTrue(self.test_workspace.file_exists("workspace/audit_test.log"))

    def test_execute_review_action(self):
        """POST /execute with a REVIEW action halts without execution."""
        payload = {
            "action_type": "RUN_COMMAND",
            "command": "apt-get install malicious-pkg",
        }
        response = self.client.post("/execute", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["action_type"], "RUN_COMMAND")
        self.assertEqual(data["policy_decision"], "REVIEW")
        self.assertEqual(data["execution_status"], "SKIPPED_REVIEW_REQUIRED")
        self.assertIn("human approval", data["message"])
        self.assertIsNone(data["simulated_result"])

    def test_execute_block_action(self):
        """POST /execute with a BLOCK action halts with blocked status."""
        payload = {
            "action_type": "SEND_DATA",
            "destination": "https://suspicious.site/leak",
            "data": "sensitive_token",
            "is_sensitive": True,
        }
        response = self.client.post("/execute", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["action_type"], "SEND_DATA")
        self.assertEqual(data["policy_decision"], "BLOCK")
        self.assertEqual(data["execution_status"], "BLOCKED")
        self.assertIn("blocked", data["message"].lower())
        self.assertIsNone(data["simulated_result"])

    def test_execute_malformed_request_fails_closed(self):
        """POST /execute with malformed/missing payload fails closed."""
        for malformed in [{}, None, "not_a_dict", {"action_type": "UNKNOWN_OP"}]:
            response = self.client.post("/execute", json=malformed)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertNotEqual(data["policy_decision"], "ALLOW")
            self.assertNotEqual(data["execution_status"], "EXECUTED")

    # ---------------------------------------------------------
    # 5. Audit Logging Connection Tests
    # ---------------------------------------------------------

    def test_evaluate_and_execute_create_audit_records(self):
        """Both /evaluate and /execute must persist corresponding audit records."""
        # 1. Call /evaluate
        eval_payload = {
            "action_type": "READ_FILE",
            "path": "workspace/existing_file.txt",
        }
        eval_resp = self.client.post("/evaluate", json=eval_payload)
        self.assertEqual(eval_resp.status_code, 200)

        # 2. Call /execute
        exec_payload = {
            "action_type": "DELETE_FILE",
            "path": "workspace/existing_file.txt",
        }
        exec_resp = self.client.post("/execute", json=exec_payload)
        self.assertEqual(exec_resp.status_code, 200)

        # Verify audit records in test database
        logs = self.test_audit_service.get_recent_logs(limit=10)
        self.assertEqual(len(logs), 2)

        # Newest log is the DELETE_FILE execution
        self.assertEqual(logs[0]["action_type"], "DELETE_FILE")
        self.assertEqual(logs[0]["policy_decision"], "REVIEW")
        self.assertEqual(logs[0]["execution_status"], "SKIPPED_REVIEW_REQUIRED")

        # Older log is the READ_FILE evaluation (execution_status is None)
        self.assertEqual(logs[1]["action_type"], "READ_FILE")
        self.assertEqual(logs[1]["policy_decision"], "ALLOW")
        self.assertIsNone(logs[1]["execution_status"])

    # ---------------------------------------------------------
    # 6. GET /audit Tests
    # ---------------------------------------------------------

    def test_get_audit_returns_newest_first(self):
        """GET /audit returns records ordered newest-first with structured metadata."""
        # Seed records via API
        self.client.post("/evaluate", json={"action_type": "READ_FILE", "path": "file1.txt"})
        self.client.post("/execute", json={"action_type": "RUN_COMMAND", "command": "echo 1"})

        response = self.client.get("/audit")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn("records", data)
        self.assertIn("count", data)
        self.assertIn("limit", data)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["limit"], 50)

        records = data["records"]
        # Newest record is the RUN_COMMAND execution
        self.assertEqual(records[0]["action_type"], "RUN_COMMAND")
        self.assertEqual(records[1]["action_type"], "READ_FILE")

    def test_get_audit_limit_query_parameter(self):
        """GET /audit respects valid limit query parameter."""
        for i in range(5):
            self.client.post("/evaluate", json={"action_type": "READ_FILE", "path": f"f{i}.txt"})

        response = self.client.get("/audit?limit=3")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], 3)
        self.assertEqual(len(data["records"]), 3)
        self.assertEqual(data["limit"], 3)

    def test_get_audit_invalid_limit_rejected(self):
        """GET /audit rejects limits <= 0 or > 100 with HTTP 400."""
        invalid_limits = [0, -1, -50, 101, 500]
        for lim in invalid_limits:
            response = self.client.get(f"/audit?limit={lim}")
            self.assertEqual(response.status_code, 400)
            self.assertIn("limit", response.json()["detail"].lower())

    def test_audit_does_not_leak_sensitive_payload(self):
        """GET /audit must not leak sensitive data payload contents."""
        payload = {
            "action_type": "SEND_DATA",
            "destination": "https://api.external.com",
            "data": "SUPER_SECRET_VALUE_12345",
            "is_sensitive": True,
        }
        self.client.post("/execute", json=payload)

        response = self.client.get("/audit?limit=1")
        self.assertEqual(response.status_code, 200)
        records = response.json()["records"]
        self.assertEqual(len(records), 1)

        rec = records[0]
        meta = rec.get("metadata") or {}
        # Ensure raw secret is not in metadata
        self.assertNotIn("data", meta)
        self.assertNotIn("SUPER_SECRET_VALUE_12345", str(rec))
        self.assertTrue(meta.get("payload_redacted"))


if __name__ == "__main__":
    unittest.main()
