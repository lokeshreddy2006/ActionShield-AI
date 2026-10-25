"""Tests for the ActionShield AI rule-based policy engine."""

import unittest

from app.policy.engine import (
    ActionCategory,
    ActionDecision,
    PolicyEngine,
    PolicyResult,
    evaluate_action,
)


class TestPolicyEngine(unittest.TestCase):
    """Comprehensive test suite for ActionShield AI policy engine."""

    def setUp(self):
        self.engine = PolicyEngine()

    # ---------------------------------------------------------
    # 1. READ_FILE Tests
    # ---------------------------------------------------------

    def test_read_file_permitted_non_sensitive_allowed(self):
        """Rule: Reading a permitted, non-sensitive file is ALLOW."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": "workspace/reports/summary.txt",
            "is_sensitive": False,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.ALLOW.value)
        self.assertEqual(result.action_type, ActionCategory.READ_FILE.value)
        self.assertIn("allowed", result.reason.lower())

    def test_read_file_sensitive_path_blocked(self):
        """Reading known sensitive files (e.g. .env, credentials) must be BLOCK."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": "config/.env",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)
        self.assertIn("sensitive", result.reason.lower())

    def test_read_file_explicitly_sensitive_blocked(self):
        """Reading files explicitly flagged as sensitive must be BLOCK."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": "data/records.csv",
            "is_sensitive": True,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    def test_read_file_unpermitted_location_review(self):
        """Reading from unverified or non-permitted location must be REVIEW."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": "/external/system/config.json",
            "is_permitted_location": False,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.REVIEW.value)

    def test_read_file_missing_path_blocked(self):
        """Missing path for READ_FILE must be BLOCK (malformed input)."""
        action = {
            "action_type": ActionCategory.READ_FILE.value,
            "path": "",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    # ---------------------------------------------------------
    # 2. WRITE_FILE Tests
    # ---------------------------------------------------------

    def test_write_file_permitted_workspace_allowed(self):
        """Rule: Writing to an explicitly permitted workspace location is ALLOW."""
        action = {
            "action_type": ActionCategory.WRITE_FILE.value,
            "path": "workspace/output.log",
            "is_permitted_location": True,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.ALLOW.value)
        self.assertIn("allowed", result.reason.lower())

    def test_write_file_unverified_location_review(self):
        """Writing without verified permitted location must be REVIEW."""
        action = {
            "action_type": ActionCategory.WRITE_FILE.value,
            "path": "/var/tmp/data.txt",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.REVIEW.value)
        self.assertNotEqual(result.decision, ActionDecision.ALLOW.value)

    def test_write_file_sensitive_path_blocked(self):
        """Writing to sensitive location must be BLOCK."""
        action = {
            "action_type": ActionCategory.WRITE_FILE.value,
            "path": ".env",
            "is_permitted_location": True,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    def test_write_file_missing_path_blocked(self):
        """Missing path for WRITE_FILE must be BLOCK."""
        action = {
            "action_type": ActionCategory.WRITE_FILE.value,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    # ---------------------------------------------------------
    # 3. DELETE_FILE Tests
    # ---------------------------------------------------------

    def test_delete_file_defaults_to_review(self):
        """Rule: Deleting files is REVIEW by default."""
        action = {
            "action_type": ActionCategory.DELETE_FILE.value,
            "path": "workspace/old_cache.tmp",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.REVIEW.value)
        self.assertIn("review", result.reason.lower())

    def test_delete_file_missing_path_blocked(self):
        """Deleting files without target path is malformed and must be BLOCK."""
        action = {
            "action_type": ActionCategory.DELETE_FILE.value,
            "path": "",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    # ---------------------------------------------------------
    # 4. SEND_DATA Tests
    # ---------------------------------------------------------

    def test_send_data_external_destination_review(self):
        """Rule: Sending data to external destination is REVIEW by default."""
        action = {
            "action_type": ActionCategory.SEND_DATA.value,
            "destination": "https://api.partner.org/v1/ingest",
            "is_sensitive": False,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.REVIEW.value)
        self.assertIn("review", result.reason.lower())

    def test_send_sensitive_data_externally_blocked(self):
        """Rule: Sending data marked as sensitive to external destination is BLOCK."""
        action = {
            "action_type": ActionCategory.SEND_DATA.value,
            "destination": "https://api.partner.org/v1/ingest",
            "is_sensitive": True,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)
        self.assertIn("blocked", result.reason.lower())

    def test_send_data_missing_destination_blocked(self):
        """Missing destination for SEND_DATA must be BLOCK."""
        action = {
            "action_type": ActionCategory.SEND_DATA.value,
            "is_sensitive": False,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    # ---------------------------------------------------------
    # 5. RUN_COMMAND Tests
    # ---------------------------------------------------------

    def test_run_command_defaults_to_review(self):
        """Rule: Running a command is REVIEW by default."""
        action = {
            "action_type": ActionCategory.RUN_COMMAND.value,
            "command": "python -m pytest",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.REVIEW.value)
        self.assertIn("review", result.reason.lower())

    def test_run_command_missing_command_blocked(self):
        """Missing command string for RUN_COMMAND must be BLOCK."""
        action = {
            "action_type": ActionCategory.RUN_COMMAND.value,
            "command": "",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    # ---------------------------------------------------------
    # 6. Unknown and Malformed Action Tests
    # ---------------------------------------------------------

    def test_unknown_action_type_blocked(self):
        """Unknown action types must be BLOCK."""
        action = {
            "action_type": "DROP_DATABASE",
            "target": "users_table",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)
        self.assertIn("unknown", result.reason.lower())

    def test_missing_action_type_blocked(self):
        """Payload without action_type must be BLOCK."""
        action = {
            "path": "workspace/file.txt",
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)
        self.assertEqual(result.action_type, "UNKNOWN")

    def test_non_string_action_type_blocked(self):
        """Non-string action_type must be BLOCK."""
        action = {
            "action_type": 12345,
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)
        self.assertEqual(result.action_type, "UNKNOWN")

    def test_non_dict_payload_blocked(self):
        """Non-dictionary payload must be BLOCK."""
        for malformed in [None, "READ_FILE", ["READ_FILE"], 42]:
            result = self.engine.evaluate(malformed)
            self.assertEqual(result.decision, ActionDecision.BLOCK.value)
            self.assertEqual(result.action_type, "UNKNOWN")

    def test_empty_dict_payload_blocked(self):
        """Empty dictionary payload must be BLOCK."""
        result = self.engine.evaluate({})
        self.assertEqual(result.decision, ActionDecision.BLOCK.value)

    # ---------------------------------------------------------
    # 7. Safety Invariant: Ambiguous or Invalid Actions Never ALLOW
    # ---------------------------------------------------------

    def test_ambiguous_or_invalid_never_defaults_to_allow(self):
        """Test invariant: Malformed, missing, or ambiguous requests never return ALLOW."""
        ambiguous_cases = [
            None,
            {},
            {"action_type": "UNKNOWN_OP"},
            {"action_type": "READ_FILE"},  # missing path
            {"action_type": "WRITE_FILE"},  # missing path
            {"action_type": "WRITE_FILE", "path": "test.txt"},  # unverified location -> REVIEW
            {"action_type": "DELETE_FILE"},  # missing path
            {"action_type": "SEND_DATA"},  # missing destination
            {"action_type": "RUN_COMMAND"},  # missing command
        ]
        for case in ambiguous_cases:
            result = self.engine.evaluate(case)
            self.assertNotEqual(
                result.decision,
                ActionDecision.ALLOW.value,
                f"Failed safety invariant for case: {case}",
            )

    # ---------------------------------------------------------
    # 8. Nested Params and Result Interface Tests
    # ---------------------------------------------------------

    def test_nested_params_extraction(self):
        """Support actions structured with a nested 'params' dictionary."""
        action = {
            "action_type": "READ_FILE",
            "params": {
                "file_path": "docs/guide.md",
                "is_sensitive": False,
            },
        }
        result = self.engine.evaluate(action)
        self.assertEqual(result.decision, ActionDecision.ALLOW.value)

    def test_result_structure_and_access(self):
        """Ensure PolicyResult provides attribute, dict access, and to_dict()."""
        action = {
            "action_type": "RUN_COMMAND",
            "command": "git status",
        }
        result = self.engine.evaluate(action)
        self.assertIsInstance(result, PolicyResult)
        # Attribute access
        self.assertEqual(result.decision, "REVIEW")
        self.assertEqual(result.action_type, "RUN_COMMAND")
        self.assertIsInstance(result.reason, str)
        # Dict access
        self.assertEqual(result["decision"], "REVIEW")
        # to_dict conversion
        as_dict = result.to_dict()
        self.assertEqual(as_dict["decision"], "REVIEW")
        self.assertIn("reason", as_dict)
        self.assertIn("action_type", as_dict)

    def test_evaluate_action_helper_function(self):
        """Ensure module-level evaluate_action function behaves identically."""
        result = evaluate_action({
            "action_type": "READ_FILE",
            "path": "workspace/data.json",
        })
        self.assertEqual(result.decision, ActionDecision.ALLOW.value)


if __name__ == "__main__":
    unittest.main()
