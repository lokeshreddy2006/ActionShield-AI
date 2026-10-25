"""Unit and integration tests for the Workflow Crash-Test Lab.

Verifies:
1. Listing predefined scenarios and descriptions.
2. Retrieving an individual valid scenario definition.
3. Handling unknown scenario IDs (404 Not Found / KeyError).
4. Running individual scenarios in controlled simulation.
5. Running all scenarios and generating an aggregated report.
6. Correct expected-versus-actual policy comparisons.
7. Sensitive-data exfiltration being blocked.
8. REVIEW actions halting without execution.
9. BLOCK actions never executing.
10. Malformed or unknown actions failing closed.
11. Shell commands never executing a real OS shell.
12. Approval requests not being created as an unintended side effect of crash testing.
13. Persistence of crash-test execution runs in SQLite.
14. Full API endpoint integration via TestClient.
"""

import os
import tempfile
import unittest
from fastapi.testclient import TestClient

from app.database.manager import DatabaseManager
from app.main import (
    app,
    get_approval_service,
    get_audit_service,
    get_crash_test_service,
    get_execution_service,
)
from app.policy.engine import PolicyEngine
from app.services.approval import ApprovalService
from app.services.audit import AuditService
from app.services.crash_test import CrashTestService
from app.services.executor import ExecutionService, ExecutionStatus, InMemoryWorkspace


class TestCrashTestService(unittest.TestCase):
    """Unit tests for CrashTestService logic and safety assertions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_crashtest.db")
        self.db = DatabaseManager(db_path=self.db_path)
        self.policy_engine = PolicyEngine()
        self.audit_service = AuditService(db_manager=self.db)
        self.crash_test_service = CrashTestService(
            db_manager=self.db,
            policy_engine=self.policy_engine,
            audit_service=self.audit_service,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------
    # 1. Listing Scenarios
    # -------------------------------------------------------------

    def test_list_scenarios_returns_predefined_definitions(self):
        """Service should list all predefined workflow test scenarios with risk descriptions."""
        scenarios = self.crash_test_service.list_scenarios()
        self.assertGreaterEqual(len(scenarios), 6)

        scenario_ids = [s["id"] for s in scenarios]
        self.assertIn("scn-permitted-read-write", scenario_ids)
        self.assertIn("scn-sensitive-data-exfiltration", scenario_ids)
        self.assertIn("scn-destructive-file-review", scenario_ids)
        self.assertIn("scn-malformed-action-guard", scenario_ids)
        self.assertIn("scn-multi-stage-pipeline", scenario_ids)
        self.assertIn("scn-system-command-sandboxing", scenario_ids)

        for s in scenarios:
            self.assertTrue(s["name"])
            self.assertTrue(s["safety_risk"])
            self.assertTrue(s["expected_outcome"])
            self.assertGreaterEqual(s["step_count"], 1)

    # -------------------------------------------------------------
    # 2. Retrieving Valid & Invalid Scenarios
    # -------------------------------------------------------------

    def test_get_valid_scenario_details(self):
        """Retrieving an existing scenario returns its full step definitions."""
        scenario = self.crash_test_service.get_scenario("scn-permitted-read-write")
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario["id"], "scn-permitted-read-write")
        self.assertEqual(len(scenario["steps"]), 2)
        self.assertEqual(scenario["steps"][0]["expected_decision"], "ALLOW")
        self.assertEqual(scenario["steps"][1]["expected_decision"], "ALLOW")

    def test_get_unknown_scenario_returns_none(self):
        """Retrieving a non-existent scenario returns None."""
        scenario = self.crash_test_service.get_scenario("non-existent-scenario-id")
        self.assertIsNone(scenario)

    def test_run_unknown_scenario_raises_key_error(self):
        """Executing an unknown scenario raises KeyError."""
        with self.assertRaises(KeyError) as ctx:
            self.crash_test_service.run_scenario("invalid-id")
        self.assertIn("not found", str(ctx.exception))

    # -------------------------------------------------------------
    # 3. Individual Scenario Runs & Expected Comparisons
    # -------------------------------------------------------------

    def test_run_permitted_read_write_scenario(self):
        """Permitted read-write scenario executes all steps with ALLOW and PASS status."""
        result = self.crash_test_service.run_scenario("scn-permitted-read-write")

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["total_steps"], 2)
        self.assertEqual(result["passed_steps"], 2)
        self.assertEqual(result["failed_steps"], 0)

        # Check step 1: READ_FILE
        s1 = result["steps"][0]
        self.assertEqual(s1["action_type"], "READ_FILE")
        self.assertEqual(s1["expected_decision"], "ALLOW")
        self.assertEqual(s1["actual_decision"], "ALLOW")
        self.assertTrue(s1["passed"])
        self.assertEqual(s1["execution_status"], "EXECUTED")

        # Check step 2: WRITE_FILE
        s2 = result["steps"][1]
        self.assertEqual(s2["action_type"], "WRITE_FILE")
        self.assertEqual(s2["expected_decision"], "ALLOW")
        self.assertEqual(s2["actual_decision"], "ALLOW")
        self.assertTrue(s2["passed"])
        self.assertEqual(s2["execution_status"], "EXECUTED")

    def test_run_sensitive_data_exfiltration_blocked(self):
        """Exfiltration scenario correctly predicts BLOCK, does not execute, and yields PASS."""
        result = self.crash_test_service.run_scenario("scn-sensitive-data-exfiltration")

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["passed_steps"], 1)
        self.assertEqual(result["failed_steps"], 0)

        s1 = result["steps"][0]
        self.assertEqual(s1["action_type"], "SEND_DATA")
        self.assertEqual(s1["expected_decision"], "BLOCK")
        self.assertEqual(s1["actual_decision"], "BLOCK")
        self.assertTrue(s1["passed"])
        # Crucial security check: execution status must be BLOCKED (no network call)
        self.assertEqual(s1["execution_status"], ExecutionStatus.BLOCKED.value)

    def test_run_destructive_file_review_not_executed(self):
        """Destructive file scenario verifies REVIEW decision halts execution without running."""
        result = self.crash_test_service.run_scenario("scn-destructive-file-review")

        self.assertEqual(result["status"], "PASS")
        s1 = result["steps"][0]
        self.assertEqual(s1["action_type"], "DELETE_FILE")
        self.assertEqual(s1["expected_decision"], "REVIEW")
        self.assertEqual(s1["actual_decision"], "REVIEW")
        self.assertTrue(s1["passed"])
        # Crucial security check: execution status must be SKIPPED_REVIEW_REQUIRED
        self.assertEqual(s1["execution_status"], ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value)

    def test_run_malformed_action_guard_fails_closed(self):
        """Malformed and path traversal actions must fail closed with BLOCK and pass safety test."""
        result = self.crash_test_service.run_scenario("scn-malformed-action-guard")

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["total_steps"], 3)
        self.assertEqual(result["passed_steps"], 3)

        for step in result["steps"]:
            self.assertEqual(step["expected_decision"], "BLOCK")
            self.assertEqual(step["actual_decision"], "BLOCK")
            self.assertTrue(step["passed"])
            self.assertEqual(step["execution_status"], ExecutionStatus.BLOCKED.value)

    def test_run_multi_stage_pipeline(self):
        """Multi-stage scenario evaluates ALLOW, REVIEW, and BLOCK steps sequentially and accurately."""
        result = self.crash_test_service.run_scenario("scn-multi-stage-pipeline")

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["total_steps"], 3)
        self.assertEqual(result["passed_steps"], 3)

        # Step 1: ALLOW
        self.assertEqual(result["steps"][0]["actual_decision"], "ALLOW")
        self.assertEqual(result["steps"][0]["execution_status"], "EXECUTED")

        # Step 2: REVIEW
        self.assertEqual(result["steps"][1]["actual_decision"], "REVIEW")
        self.assertEqual(result["steps"][1]["execution_status"], "SKIPPED_REVIEW_REQUIRED")

        # Step 3: BLOCK
        self.assertEqual(result["steps"][2]["actual_decision"], "BLOCK")
        self.assertEqual(result["steps"][2]["execution_status"], "BLOCKED")

    def test_run_system_command_sandboxing(self):
        """System command execution must evaluate to REVIEW and never invoke a real shell."""
        result = self.crash_test_service.run_scenario("scn-system-command-sandboxing")

        self.assertEqual(result["status"], "PASS")
        s1 = result["steps"][0]
        self.assertEqual(s1["expected_decision"], "REVIEW")
        self.assertEqual(s1["actual_decision"], "REVIEW")
        self.assertEqual(s1["execution_status"], ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value)

    # -------------------------------------------------------------
    # 4. Isolation & Side Effect Prevention
    # -------------------------------------------------------------

    def test_crash_tests_do_not_create_approval_requests(self):
        """Crash tests must NOT populate the production approval_requests queue as a side effect."""
        initial_approvals = self.db.count_pending_approvals()

        # Run all scenarios, several of which evaluate to REVIEW
        self.crash_test_service.run_all()

        final_approvals = self.db.count_pending_approvals()
        self.assertEqual(final_approvals, initial_approvals)

    def test_run_all_scenarios_aggregated_report(self):
        """Running all scenarios returns comprehensive aggregated report with all_passed=True."""
        report = self.crash_test_service.run_all()

        self.assertTrue(report["all_passed"])
        self.assertEqual(report["failed_scenarios"], 0)
        self.assertGreaterEqual(report["total_scenarios"], 6)
        self.assertEqual(report["passed_scenarios"], report["total_scenarios"])
        self.assertEqual(len(report["scenarios"]), report["total_scenarios"])

    def test_crash_test_runs_persisted_in_database(self):
        """Crash test executions must be recorded in the crash_test_runs SQLite table."""
        initial_runs = len(self.db.list_crash_test_runs())

        res = self.crash_test_service.run_scenario("scn-permitted-read-write")
        run_id = res["run_id"]

        updated_runs = self.db.list_crash_test_runs()
        self.assertEqual(len(updated_runs), initial_runs + 1)

        retrieved = self.db.get_crash_test_run(run_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["scenario_id"], "scn-permitted-read-write")
        self.assertEqual(retrieved["status"], "PASS")
        self.assertEqual(retrieved["passed_steps"], 2)


class TestCrashTestAPIEndpoints(unittest.TestCase):
    """Integration tests for FastAPI Crash-Test endpoints."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_api_crashtest.db")
        self.db = DatabaseManager(db_path=self.db_path)
        self.policy_engine = PolicyEngine()
        self.audit_service = AuditService(db_manager=self.db)
        self.execution_service = ExecutionService()
        self.approval_service = ApprovalService(db_manager=self.db)
        self.crash_test_service = CrashTestService(
            db_manager=self.db,
            policy_engine=self.policy_engine,
            audit_service=self.audit_service,
        )

        app.dependency_overrides[get_audit_service] = lambda: self.audit_service
        app.dependency_overrides[get_execution_service] = lambda: self.execution_service
        app.dependency_overrides[get_approval_service] = lambda: self.approval_service
        app.dependency_overrides[get_crash_test_service] = lambda: self.crash_test_service

        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.temp_dir.cleanup()

    def test_get_scenarios_endpoint(self):
        """GET /crash-tests/scenarios returns list of available test scenarios."""
        resp = self.client.get("/crash-tests/scenarios")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(data["count"], 6)

    def test_get_scenario_by_id_endpoint(self):
        """GET /crash-tests/scenarios/{id} returns detailed scenario definition."""
        resp = self.client.get("/crash-tests/scenarios/scn-permitted-read-write")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], "scn-permitted-read-write")
        self.assertIn("steps", data)

    def test_get_unknown_scenario_returns_404(self):
        """GET /crash-tests/scenarios/{id} returns 404 for unknown scenario ID."""
        resp = self.client.get("/crash-tests/scenarios/non-existent-id")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.json()["detail"].lower())

    def test_run_single_scenario_endpoint(self):
        """POST /crash-tests/run/{id} runs the scenario and returns pass/fail results."""
        resp = self.client.post("/crash-tests/run/scn-destructive-file-review")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["scenario_id"], "scn-destructive-file-review")
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(data["steps"][0]["actual_decision"], "REVIEW")
        self.assertEqual(data["steps"][0]["execution_status"], "SKIPPED_REVIEW_REQUIRED")

    def test_run_unknown_scenario_returns_404(self):
        """POST /crash-tests/run/{id} returns 404 for unknown scenario."""
        resp = self.client.post("/crash-tests/run/unknown-scenario")
        self.assertEqual(resp.status_code, 404)

    def test_run_all_scenarios_endpoint(self):
        """POST /crash-tests/run-all executes all predefined scenarios."""
        resp = self.client.post("/crash-tests/run-all")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["all_passed"])
        self.assertEqual(data["failed_scenarios"], 0)
        self.assertGreaterEqual(data["total_scenarios"], 6)
        self.assertEqual(len(data["scenarios"]), data["total_scenarios"])
