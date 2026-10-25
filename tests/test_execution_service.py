"""Tests for the ActionShield AI Safe Execution Service."""

import os
import tempfile
import unittest

from app.policy.engine import (
    ActionCategory,
    ActionDecision,
    PolicyEngine,
    PolicyResult,
)
from app.services.executor import (
    ExecutionResult,
    ExecutionService,
    ExecutionStatus,
    InMemoryWorkspace,
)


class TestExecutionService(unittest.TestCase):
    """Test suite for ExecutionService and InMemoryWorkspace."""

    def setUp(self):
        self.workspace = InMemoryWorkspace({
            "workspace/existing_file.txt": "Hello from virtual workspace!",
        })
        self.service = ExecutionService(workspace=self.workspace)

    # ---------------------------------------------------------
    # 1. ALLOW Decision Executes Safe Simulation
    # ---------------------------------------------------------

    def test_allow_read_file_executes_simulation(self):
        """Permitted read operation executes simulated read and returns content."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": "workspace/existing_file.txt",
            "is_sensitive": False,
        }
        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.ALLOW.value)
        self.assertEqual(res.execution_status, ExecutionStatus.EXECUTED.value)
        self.assertIsNotNone(res.simulated_result)
        self.assertEqual(res.simulated_result["content"], "Hello from virtual workspace!")
        self.assertTrue(res.simulated_result["simulated"])

    def test_allow_write_file_modifies_only_in_memory_workspace(self):
        """Permitted write operation modifies virtual workspace and never writes to disk."""
        target_path = "workspace/new_output.log"
        content_to_write = "safe log entry"

        action = {
            "action_type": ActionCategory.WRITE_FILE.value,
            "path": target_path,
            "content": content_to_write,
            "is_permitted_location": True,
        }

        # Ensure target file does NOT exist on physical disk
        self.assertFalse(os.path.exists(target_path))

        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.ALLOW.value)
        self.assertEqual(res.execution_status, ExecutionStatus.EXECUTED.value)
        self.assertIn("virtual workspace", res.message)

        # Virtual workspace contains the written file
        self.assertTrue(self.workspace.file_exists(target_path))
        self.assertEqual(self.workspace.read_file(target_path), content_to_write)

        # Physical disk remains completely untouched
        self.assertFalse(os.path.exists(target_path))

    # ---------------------------------------------------------
    # 2. REVIEW Decision is NOT Executed
    # ---------------------------------------------------------

    def test_review_delete_file_is_not_executed(self):
        """DELETE_FILE (REVIEW) must not be executed; target must remain in workspace."""
        action = {
            "action_type": ActionCategory.DELETE_FILE.value,
            "path": "workspace/existing_file.txt",
        }
        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.REVIEW.value)
        self.assertEqual(res.execution_status, ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value)
        self.assertIn("requires human approval", res.message)
        self.assertIsNone(res.simulated_result)

        # The file in virtual workspace must NOT have been deleted
        self.assertTrue(self.workspace.file_exists("workspace/existing_file.txt"))

    def test_review_run_command_is_not_executed(self):
        """RUN_COMMAND (REVIEW) must not execute shell commands."""
        action = {
            "action_type": ActionCategory.RUN_COMMAND.value,
            "command": "rm -rf /",
        }
        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.REVIEW.value)
        self.assertEqual(res.execution_status, ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value)
        self.assertIn("requires human approval", res.message)
        self.assertIsNone(res.simulated_result)

    def test_review_send_data_is_not_executed(self):
        """SEND_DATA to external endpoint (REVIEW) must not dispatch network requests."""
        action = {
            "action_type": ActionCategory.SEND_DATA.value,
            "destination": "https://api.thirdparty.com/webhook",
            "is_sensitive": False,
        }
        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.REVIEW.value)
        self.assertEqual(res.execution_status, ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value)
        self.assertIsNone(res.simulated_result)

    # ---------------------------------------------------------
    # 3. BLOCK Decision is NOT Executed
    # ---------------------------------------------------------

    def test_block_sensitive_send_data_is_not_executed(self):
        """Sending sensitive data (BLOCK) must not execute."""
        action = {
            "action_type": ActionCategory.SEND_DATA.value,
            "destination": "https://api.thirdparty.com/webhook",
            "is_sensitive": True,
        }
        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.BLOCK.value)
        self.assertEqual(res.execution_status, ExecutionStatus.BLOCKED.value)
        self.assertIn("blocked", res.message.lower())
        self.assertIsNone(res.simulated_result)

    def test_block_sensitive_file_read_is_not_executed(self):
        """Reading .env (BLOCK) must not execute."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": ".env",
        }
        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.BLOCK.value)
        self.assertEqual(res.execution_status, ExecutionStatus.BLOCKED.value)
        self.assertIsNone(res.simulated_result)

    # ---------------------------------------------------------
    # 4. Malformed and Unknown Actions Fail Closed
    # ---------------------------------------------------------

    def test_unknown_action_type_blocked_and_not_executed(self):
        """Unknown action type returns BLOCKED and does not execute."""
        action = {
            "action_type": "DROP_DATABASE_CASCADE",
        }
        res = self.service.execute(action)

        self.assertEqual(res.policy_decision, ActionDecision.BLOCK.value)
        self.assertEqual(res.execution_status, ExecutionStatus.BLOCKED.value)
        self.assertIsNone(res.simulated_result)

    def test_malformed_empty_payload_fails_closed(self):
        """Empty or non-dict payloads fail closed."""
        res = self.service.execute({})
        self.assertEqual(res.policy_decision, ActionDecision.BLOCK.value)
        self.assertEqual(res.execution_status, ExecutionStatus.BLOCKED.value)
        self.assertIsNone(res.simulated_result)

        res_none = self.service.execute(None)
        self.assertEqual(res_none.policy_decision, ActionDecision.BLOCK.value)
        self.assertEqual(res_none.execution_status, ExecutionStatus.BLOCKED.value)

    def test_unrecognized_policy_decision_fails_closed(self):
        """If policy engine returns an abnormal decision, execution fails closed."""
        class MockEngine:
            def evaluate(self, _action):
                return PolicyResult(
                    decision="UNRECOGNIZED_STATE",
                    reason="Bypass attempt",
                    action_type="WRITE_FILE",
                )

        untrusted_service = ExecutionService(policy_engine=MockEngine())
        res = untrusted_service.execute({"action_type": "WRITE_FILE"})

        self.assertEqual(res.execution_status, ExecutionStatus.FAILED_CLOSED.value)
        self.assertIn("Safety guard", res.message)
        self.assertIsNone(res.simulated_result)

    # ---------------------------------------------------------
    # 5. Rejected Actions Cannot Modify Workspace
    # ---------------------------------------------------------

    def test_rejected_write_cannot_modify_simulated_workspace(self):
        """Unverified write (REVIEW) must not add or modify files in virtual workspace."""
        initial_files = dict(self.workspace.list_files())

        action = {
            "action_type": ActionCategory.WRITE_FILE.value,
            "path": "/etc/shadow",
            "content": "injected content",
        }
        res = self.service.execute(action)

        # Must be BLOCK or REVIEW (in this case sensitive path /etc/shadow -> BLOCK)
        self.assertNotEqual(res.policy_decision, ActionDecision.ALLOW.value)
        self.assertNotEqual(res.execution_status, ExecutionStatus.EXECUTED.value)

        # Workspace must remain identical to before
        self.assertEqual(self.workspace.list_files(), initial_files)

    # ---------------------------------------------------------
    # 6. Physical Filesystem and OS Integrity
    # ---------------------------------------------------------

    def test_physical_file_never_deleted_on_execute(self):
        """Real files on disk must never be deleted by execution service."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            real_path = tf.name
            tf.write(b"precious disk data")

        try:
            self.assertTrue(os.path.exists(real_path))

            action = {
                "action_type": ActionCategory.DELETE_FILE.value,
                "path": real_path,
            }
            res = self.service.execute(action)
            self.assertEqual(res.execution_status, ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value)

            # File must still exist on physical disk
            self.assertTrue(os.path.exists(real_path))
        finally:
            if os.path.exists(real_path):
                os.remove(real_path)

    # ---------------------------------------------------------
    # 7. Result Structure and Dict Access
    # ---------------------------------------------------------

    def test_execution_result_structure(self):
        """ExecutionResult provides both attribute and dict-like access."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": "workspace/existing_file.txt",
        }
        res = self.service.execute(action)
        self.assertIsInstance(res, ExecutionResult)
        self.assertEqual(res["execution_status"], ExecutionStatus.EXECUTED.value)
        d = res.to_dict()
        self.assertIn("action_type", d)
        self.assertIn("policy_decision", d)
        self.assertIn("execution_status", d)
        self.assertIn("message", d)
        self.assertIn("simulated_result", d)


if __name__ == "__main__":
    unittest.main()
