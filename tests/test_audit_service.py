"""Tests for the ActionShield AI SQLite Audit Logging Service."""

from datetime import datetime, timezone
import os
import tempfile
import unittest

from app.database.manager import DatabaseManager
from app.policy.engine import PolicyResult
from app.services.audit import AuditService
from app.services.executor import (
    ExecutionResult,
    ExecutionService,
    ExecutionStatus,
    InMemoryWorkspace,
)


class TestAuditLogging(unittest.TestCase):
    """Test suite for SQLite DatabaseManager and AuditService."""

    def setUp(self):
        # Create an isolated temporary SQLite file for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_audit.db")
        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.audit_service = AuditService(db_manager=self.db_manager)

    def tearDown(self):
        self.temp_dir.cleanup()

    # ---------------------------------------------------------
    # 1. Database Initialization
    # ---------------------------------------------------------

    def test_database_initialization_creates_table_and_index(self):
        """Database initialization automatically creates audit_logs table and timestamp index."""
        self.assertTrue(os.path.exists(self.db_path))

        with self.db_manager.transaction() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs';"
            )
            table = cursor.fetchone()
            self.assertIsNotNone(table)
            self.assertEqual(table["name"], "audit_logs")

            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_audit_logs_timestamp';"
            )
            index = cursor.fetchone()
            self.assertIsNotNone(index)
            self.assertEqual(index["name"], "idx_audit_logs_timestamp")

    # ---------------------------------------------------------
    # 2. Recording Evaluation Outcome
    # ---------------------------------------------------------

    def test_record_evaluation_success(self):
        """Recording a policy evaluation stores all core fields without execution status."""
        policy_res = PolicyResult(
            decision="ALLOW",
            reason="Reading permitted non-sensitive file is allowed.",
            action_type="READ_FILE",
        )
        action_payload = {
            "action_type": "READ_FILE",
            "path": "workspace/reports/q1.txt",
            "is_sensitive": False,
        }

        record_id = self.audit_service.record_evaluation(policy_res, action=action_payload)
        self.assertIsNotNone(record_id)

        records = self.audit_service.get_recent_logs(limit=10)
        self.assertEqual(len(records), 1)

        rec = records[0]
        self.assertEqual(rec["id"], record_id)
        self.assertEqual(rec["action_type"], "READ_FILE")
        self.assertEqual(rec["policy_decision"], "ALLOW")
        self.assertIsNone(rec["execution_status"])  # Evaluation only, not executed yet
        self.assertIn("permitted", rec["message"].lower())
        self.assertEqual(rec["metadata"]["path"], "workspace/reports/q1.txt")
        self.assertIsNotNone(rec["timestamp"])

    # ---------------------------------------------------------
    # 3. Recording Execution Outcome (ALLOW, REVIEW, BLOCK)
    # ---------------------------------------------------------

    def test_record_execution_allow_executed(self):
        """Recording an executed ALLOW action stores execution_status == EXECUTED."""
        exec_res = ExecutionResult(
            action_type="WRITE_FILE",
            policy_decision="ALLOW",
            execution_status=ExecutionStatus.EXECUTED.value,
            message="Simulated write to virtual workspace succeeded.",
            simulated_result={"path": "workspace/out.txt", "simulated": True},
        )
        action_payload = {
            "action_type": "WRITE_FILE",
            "path": "workspace/out.txt",
            "content": "secret_data_should_not_leak",
            "is_permitted_location": True,
        }

        self.audit_service.record_execution(exec_res, action=action_payload)
        records = self.audit_service.get_recent_logs(limit=1)

        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["action_type"], "WRITE_FILE")
        self.assertEqual(rec["policy_decision"], "ALLOW")
        self.assertEqual(rec["execution_status"], ExecutionStatus.EXECUTED.value)
        self.assertEqual(rec["metadata"]["path"], "workspace/out.txt")

        # Crucial privacy assertion: 'content' must NOT be stored in metadata!
        self.assertNotIn("content", rec["metadata"])
        self.assertTrue(rec["metadata"].get("payload_redacted"))

    def test_record_execution_review_skipped(self):
        """Recording a REVIEW action stores execution_status == SKIPPED_REVIEW_REQUIRED."""
        exec_res = ExecutionResult(
            action_type="DELETE_FILE",
            policy_decision="REVIEW",
            execution_status=ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value,
            message="Action requires human approval before execution.",
            simulated_result=None,
        )
        action_payload = {
            "action_type": "DELETE_FILE",
            "path": "workspace/old_data.csv",
        }

        self.audit_service.record_execution(exec_res, action=action_payload)
        records = self.audit_service.get_recent_logs(limit=1)

        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["policy_decision"], "REVIEW")
        self.assertEqual(rec["execution_status"], "SKIPPED_REVIEW_REQUIRED")
        self.assertIn("approval", rec["message"])

    def test_record_execution_block_not_executed(self):
        """Recording a BLOCK action accurately reflects BLOCKED status."""
        exec_res = ExecutionResult(
            action_type="SEND_DATA",
            policy_decision="BLOCK",
            execution_status=ExecutionStatus.BLOCKED.value,
            message="Sending sensitive data to external destination is blocked.",
            simulated_result=None,
        )
        action_payload = {
            "action_type": "SEND_DATA",
            "destination": "https://api.external.com",
            "data": "SUPER_SECRET_TOKEN",
            "is_sensitive": True,
        }

        self.audit_service.record_execution(exec_res, action=action_payload)
        records = self.audit_service.get_recent_logs(limit=1)

        rec = records[0]
        self.assertEqual(rec["policy_decision"], "BLOCK")
        self.assertEqual(rec["execution_status"], "BLOCKED")
        self.assertEqual(rec["metadata"]["destination"], "https://api.external.com")
        self.assertNotIn("data", rec["metadata"])
        self.assertTrue(rec["metadata"].get("payload_redacted"))

    # ---------------------------------------------------------
    # 4. Ordering (Newest-First) and Limits
    # ---------------------------------------------------------

    def test_newest_first_ordering_and_limits(self):
        """Audit retrieval returns records ordered by timestamp descending, honoring limits."""
        timestamps = [
            "2026-10-25T10:00:00+00:00",
            "2026-10-25T11:00:00+00:00",
            "2026-10-25T12:00:00+00:00",
            "2026-10-25T13:00:00+00:00",
        ]

        for i, ts in enumerate(timestamps):
            res = PolicyResult(decision="ALLOW", reason=f"Action {i}", action_type="READ_FILE")
            self.audit_service.record_evaluation(res, timestamp=ts)

        # Retrieve with limit=2
        records = self.audit_service.get_recent_logs(limit=2)
        self.assertEqual(len(records), 2)
        # First record must be the newest (13:00:00)
        self.assertEqual(records[0]["timestamp"], "2026-10-25T13:00:00+00:00")
        self.assertEqual(records[0]["message"], "Action 3")
        # Second record must be the next newest (12:00:00)
        self.assertEqual(records[1]["timestamp"], "2026-10-25T12:00:00+00:00")
        self.assertEqual(records[1]["message"], "Action 2")

        # Retrieve all
        all_records = self.audit_service.get_recent_logs(limit=10)
        self.assertEqual(len(all_records), 4)
        self.assertEqual(all_records[-1]["timestamp"], "2026-10-25T10:00:00+00:00")

    # ---------------------------------------------------------
    # 5. Missing or Optional Fields Handling
    # ---------------------------------------------------------

    def test_safe_handling_with_missing_optional_metadata(self):
        """Recording without an action dictionary handles missing metadata safely."""
        policy_res = PolicyResult(decision="BLOCK", reason="Invalid action", action_type="UNKNOWN")
        record_id = self.audit_service.record_evaluation(policy_res, action=None)

        records = self.audit_service.get_recent_logs(limit=1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["id"], record_id)
        self.assertIsNone(records[0]["metadata"])

    # ---------------------------------------------------------
    # 6. Integration with ExecutionService Flow
    # ---------------------------------------------------------

    def test_full_flow_with_execution_service(self):
        """Simulate real evaluation and execution flow with audit recording."""
        workspace = InMemoryWorkspace({"workspace/test.txt": "data"})
        executor = ExecutionService(workspace=workspace)

        action = {
            "action_type": "WRITE_FILE",
            "path": "workspace/test.txt",
            "content": "updated",
            "is_permitted_location": True,
        }

        # Step 1: Policy evaluation
        policy_res = executor.policy_engine.evaluate(action)
        eval_id = self.audit_service.record_evaluation(policy_res, action=action)

        # Step 2: Execution
        exec_res = executor.execute(action)
        exec_id = self.audit_service.record_execution(exec_res, action=action)

        logs = self.audit_service.get_recent_logs(limit=10)
        self.assertEqual(len(logs), 2)
        # Newest record is the execution
        self.assertEqual(logs[0]["id"], exec_id)
        self.assertEqual(logs[0]["execution_status"], "EXECUTED")
        # Older record is the initial evaluation
        self.assertEqual(logs[1]["id"], eval_id)
        self.assertIsNone(logs[1]["execution_status"])

    # ---------------------------------------------------------
    # 7. Clearing Audit Logs
    # ---------------------------------------------------------

    def test_clear_audit_records_populated(self):
        """Clearing populated audit records deletes all entries and returns deleted_count."""
        for i in range(3):
            self.audit_service.record_evaluation(
                PolicyResult(decision="ALLOW", reason=f"Allowed {i}", action_type="READ_FILE")
            )

        self.assertEqual(len(self.audit_service.get_recent_logs(limit=10)), 3)

        deleted = self.audit_service.clear_logs()
        self.assertEqual(deleted, 3)
        self.assertEqual(len(self.audit_service.get_recent_logs(limit=10)), 0)

    def test_clear_audit_records_empty_returns_zero(self):
        """Clearing an already-empty audit table succeeds and returns 0."""
        self.assertEqual(len(self.audit_service.get_recent_logs(limit=10)), 0)
        deleted = self.audit_service.clear_logs()
        self.assertEqual(deleted, 0)
        self.assertEqual(len(self.audit_service.get_recent_logs(limit=10)), 0)

    def test_clear_audit_records_preserves_other_tables(self):
        """Clearing audit records does NOT affect approval_requests or crash_test_runs."""
        # 1. Add audit record
        self.audit_service.record_evaluation(
            PolicyResult(decision="ALLOW", reason="Safe read", action_type="READ_FILE")
        )

        # 2. Add an approval request
        appr_id = self.db_manager.insert_approval_request(
            action_type="DELETE_FILE",
            action_payload={"path": "sensitive.txt"},
            policy_decision="REVIEW",
            review_reason="Requires human approval",
        )

        # 3. Add a crash test run
        crash_id = self.db_manager.insert_crash_test_run(
            scenario_id="scenario_test",
            scenario_name="Test Scenario",
            status="PASSED",
            started_at="2026-10-28T00:00:00Z",
            completed_at="2026-10-28T00:01:00Z",
            passed_steps=1,
            failed_steps=0,
            total_steps=1,
            results=[],
        )

        # Verify initial counts
        self.assertEqual(len(self.audit_service.get_recent_logs(limit=10)), 1)
        self.assertIsNotNone(self.db_manager.get_approval_request(appr_id))
        self.assertIsNotNone(self.db_manager.get_crash_test_run(crash_id))

        # Clear audit logs
        deleted = self.audit_service.clear_logs()
        self.assertEqual(deleted, 1)

        # Verify audit logs are empty
        self.assertEqual(len(self.audit_service.get_recent_logs(limit=10)), 0)

        # Verify approval_requests and crash_test_runs remain completely intact
        saved_appr = self.db_manager.get_approval_request(appr_id)
        self.assertIsNotNone(saved_appr)
        self.assertEqual(saved_appr["id"], appr_id)
        self.assertEqual(saved_appr["status"], "PENDING")

        saved_crash = self.db_manager.get_crash_test_run(crash_id)
        self.assertIsNotNone(saved_crash)
        self.assertEqual(saved_crash["id"], crash_id)
        self.assertEqual(saved_crash["status"], "PASSED")


if __name__ == "__main__":
    unittest.main()

