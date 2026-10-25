"""Unit and integration tests for the ActionShield AI Human Approval Workflow.

Validates:
1. Creating a review request
2. Listing pending requests
3. Approving a valid pending request
4. Rejecting a pending request
5. Preventing approval of BLOCK actions (and preventing queuing of BLOCK actions)
6. Preventing repeated approval or rejection
7. Ensuring rejected actions cannot execute
8. Ensuring pending actions cannot execute
9. Revalidating policy at approval time (fails if action now returns BLOCK)
10. Preventing duplicate execution
11. Audit logging of approval and execution outcomes
12. Persistence across database connections / service restarts
13. API endpoints for approvals (/approvals, /approvals/pending, /approvals/{id}/approve, /approvals/{id}/reject)
"""

import os
import tempfile
import unittest
from fastapi.testclient import TestClient

from app.database.manager import DatabaseManager
from app.main import app, get_approval_service, get_audit_service, get_execution_service
from app.policy.engine import ActionDecision, PolicyEngine
from app.services.approval import ApprovalService
from app.services.audit import AuditService
from app.services.executor import ExecutionService, ExecutionStatus, InMemoryWorkspace


class TestApprovalService(unittest.TestCase):
    """Test suite for the ApprovalService logic and security constraints."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_approval.db")
        self.db = DatabaseManager(db_path=self.db_path)
        self.policy_engine = PolicyEngine()
        self.workspace = InMemoryWorkspace({
            "workspace/temp_cache.tmp": "Temporary cache to be deleted.",
            "workspace/existing.txt": "Existing content.",
        })
        self.execution_service = ExecutionService(
            policy_engine=self.policy_engine, workspace=self.workspace
        )
        self.audit_service = AuditService(db_manager=self.db)
        self.approval_service = ApprovalService(
            db_manager=self.db,
            policy_engine=self.policy_engine,
            execution_service=self.execution_service,
            audit_service=self.audit_service,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------
    # 1. Creating a review request
    # -------------------------------------------------------------

    def test_create_review_request_success(self):
        """Actions that evaluate to REVIEW can be queued into approval requests."""
        action = {
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        }
        req = self.approval_service.create_request(action)

        self.assertIsNotNone(req["id"])
        self.assertEqual(req["status"], "PENDING")
        self.assertEqual(req["action_type"], "DELETE_FILE")
        self.assertEqual(req["policy_decision"], "REVIEW")
        self.assertIn("requires review", req["review_reason"])
        self.assertIsNone(req["resolved_at"])
        self.assertIsNone(req["execution_status"])
        self.assertEqual(self.approval_service.count_pending(), 1)

    # -------------------------------------------------------------
    # 2. Listing pending requests
    # -------------------------------------------------------------

    def test_list_pending_requests(self):
        """Listing requests filtered by status PENDING returns only pending entries."""
        # Create 2 review requests
        req1 = self.approval_service.create_request({
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        })
        req2 = self.approval_service.create_request({
            "action_type": "RUN_COMMAND",
            "command": "git status",
        })

        pending_list = self.approval_service.list_requests(status="PENDING")
        self.assertEqual(len(pending_list), 2)
        req_ids = [r["id"] for r in pending_list]
        self.assertIn(req1["id"], req_ids)
        self.assertIn(req2["id"], req_ids)

    # -------------------------------------------------------------
    # 3. Approving a valid pending request
    # -------------------------------------------------------------

    def test_approve_valid_pending_request(self):
        """Approving a pending request safely executes it in the workspace and updates status."""
        action = {
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        }
        req = self.approval_service.create_request(action)
        self.assertTrue(self.workspace.file_exists("workspace/temp_cache.tmp"))

        res = self.approval_service.approve_request(req["id"], comment="Verified safe cleanup.")
        approval = res["approval"]
        execution = res["execution"]

        self.assertEqual(approval["status"], "APPROVED")
        self.assertIsNotNone(approval["resolved_at"])
        self.assertEqual(approval["resolution_comment"], "Verified safe cleanup.")
        self.assertEqual(execution["execution_status"], "EXECUTED")
        self.assertIn("Simulated deletion", execution["message"])

        # Virtual workspace file was safely deleted in simulation
        self.assertFalse(self.workspace.file_exists("workspace/temp_cache.tmp"))
        self.assertEqual(self.approval_service.count_pending(), 0)

    # -------------------------------------------------------------
    # 4. Rejecting a pending request
    # -------------------------------------------------------------

    def test_reject_pending_request(self):
        """Rejecting a pending request marks it REJECTED and never executes."""
        action = {
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        }
        req = self.approval_service.create_request(action)

        res = self.approval_service.reject_request(req["id"], comment="Denied by admin.")
        approval = res["approval"]

        self.assertEqual(approval["status"], "REJECTED")
        self.assertIsNotNone(approval["resolved_at"])
        self.assertEqual(approval["resolution_comment"], "Denied by admin.")
        self.assertEqual(approval["execution_status"], "NOT_EXECUTED")

        # The file in virtual workspace remains untouched
        self.assertTrue(self.workspace.file_exists("workspace/temp_cache.tmp"))
        self.assertEqual(self.approval_service.count_pending(), 0)

    # -------------------------------------------------------------
    # 5. Preventing approval / queuing of BLOCK actions
    # -------------------------------------------------------------

    def test_cannot_queue_block_actions(self):
        """BLOCK actions (e.g. accessing .env or sending sensitive tokens) must never enter the approval queue."""
        block_action = {
            "action_type": "READ_FILE",
            "path": ".env",
            "is_sensitive": True,
        }
        with self.assertRaises(ValueError) as ctx:
            self.approval_service.create_request(block_action)

        self.assertIn("REVIEW", str(ctx.exception))
        self.assertIn("BLOCK", str(ctx.exception))
        self.assertEqual(self.approval_service.count_pending(), 0)

    def test_cannot_queue_allow_actions(self):
        """ALLOW actions don't need approval and must not enter the approval queue."""
        allow_action = {
            "action_type": "READ_FILE",
            "path": "workspace/existing.txt",
            "is_sensitive": False,
            "is_permitted": True,
        }
        with self.assertRaises(ValueError) as ctx:
            self.approval_service.create_request(allow_action)

        self.assertIn("REVIEW", str(ctx.exception))
        self.assertIn("ALLOW", str(ctx.exception))

    # -------------------------------------------------------------
    # 6. Preventing repeated approval or rejection
    # -------------------------------------------------------------

    def test_prevent_repeated_approval_or_rejection(self):
        """A resolved request cannot be approved or rejected again (fail with ValueError)."""
        req = self.approval_service.create_request({
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        })

        # 1st approval succeeds
        self.approval_service.approve_request(req["id"], comment="Approved once.")

        # 2nd approval must fail
        with self.assertRaises(ValueError) as ctx:
            self.approval_service.approve_request(req["id"], comment="Approve second time.")
        self.assertIn("already been resolved", str(ctx.exception))

        # Rejection after approval must also fail
        with self.assertRaises(ValueError) as ctx:
            self.approval_service.reject_request(req["id"], comment="Reject after approve.")
        self.assertIn("already been resolved", str(ctx.exception))

    def test_prevent_approval_after_rejection(self):
        """A rejected request cannot subsequently be approved."""
        req = self.approval_service.create_request({
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        })

        self.approval_service.reject_request(req["id"], comment="First reject.")

        with self.assertRaises(ValueError) as ctx:
            self.approval_service.approve_request(req["id"], comment="Now approve.")
        self.assertIn("already been resolved with status 'REJECTED'", str(ctx.exception))

    # -------------------------------------------------------------
    # 7 & 8. Ensuring pending and rejected actions cannot execute
    # -------------------------------------------------------------

    def test_pending_action_cannot_execute_via_standard_execution_service(self):
        """An unapproved pending action evaluated directly with execute() halts with SKIPPED_REVIEW_REQUIRED."""
        action = {
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        }
        req = self.approval_service.create_request(action)

        # Standard execution must halt and never simulate execution
        result = self.execution_service.execute(action)
        self.assertEqual(result.execution_status, ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value)
        self.assertIsNone(result.simulated_result)
        self.assertTrue(self.workspace.file_exists("workspace/temp_cache.tmp"))

    def test_rejected_action_cannot_execute(self):
        """A rejected approval request leaves the resource untouched."""
        action = {
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        }
        req = self.approval_service.create_request(action)
        self.approval_service.reject_request(req["id"])

        self.assertTrue(self.workspace.file_exists("workspace/temp_cache.tmp"))

    # -------------------------------------------------------------
    # 9. Revalidating policy at approval time
    # -------------------------------------------------------------

    def test_revalidating_policy_refuses_approval_if_now_block(self):
        """If policy changes or action is modified to evaluate to BLOCK, approval is refused."""
        # Create a dynamic policy engine where sensitive_patterns can be changed
        dynamic_engine = PolicyEngine(sensitive_patterns=[r"\.env"])
        exec_svc = ExecutionService(policy_engine=dynamic_engine, workspace=self.workspace)
        approval_svc = ApprovalService(
            db_manager=self.db,
            policy_engine=dynamic_engine,
            execution_service=exec_svc,
            audit_service=self.audit_service,
        )

        # Initially, 'custom_secret.key' is not in sensitive_patterns, but writing to it requires review
        action = {
            "action_type": "WRITE_FILE",
            "path": "workspace/custom_secret.key",
            "content": "new secret",
            "is_permitted_location": False,
        }
        # It is REVIEW
        req = approval_svc.create_request(action)

        # Now suppose security policy is updated to include .key patterns
        dynamic_engine.sensitive_patterns.append(r"\.key$")

        # Approval revalidation MUST detect that this now evaluates to BLOCK!
        with self.assertRaises(PermissionError) as ctx:
            approval_svc.approve_request(req["id"], comment="Attempting to approve blocked item.")

        self.assertIn("BLOCK", str(ctx.exception))
        # Status should remain PENDING or not approved
        refreshed = approval_svc.get_request(req["id"])
        self.assertEqual(refreshed["status"], "PENDING")

    # -------------------------------------------------------------
    # 10. Audit logging of approval and execution outcomes
    # -------------------------------------------------------------

    def test_audit_logging_of_approval_and_execution(self):
        """Both approval with execution and rejection write detailed audit records."""
        # 1. Create and approve
        req1 = self.approval_service.create_request({
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        })
        self.approval_service.approve_request(req1["id"], comment="Approved cleanup.")

        # 2. Create and reject
        req2 = self.approval_service.create_request({
            "action_type": "RUN_COMMAND",
            "command": "reboot",
        })
        self.approval_service.reject_request(req2["id"], comment="Dangerous command.")

        logs = self.audit_service.get_recent_logs(limit=10)
        messages = [log["message"] for log in logs]
        statuses = [log["execution_status"] for log in logs]

        # Check approval execution logged
        self.assertIn("EXECUTED", statuses)
        # Check rejection logged
        self.assertIn("REJECTED", statuses)

    # -------------------------------------------------------------
    # 11. Persistence across database instances / service restarts
    # -------------------------------------------------------------

    def test_persistence_across_database_instances(self):
        """Approval requests persist across new DatabaseManager connections."""
        req = self.approval_service.create_request({
            "action_type": "DELETE_FILE",
            "path": "workspace/temp_cache.tmp",
        })

        # Instantiate brand-new DatabaseManager and ApprovalService on the same SQLite file
        new_db = DatabaseManager(db_path=self.db_path)
        new_svc = ApprovalService(db_manager=new_db)

        persisted = new_svc.get_request(req["id"])
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted["id"], req["id"])
        self.assertEqual(persisted["status"], "PENDING")
        self.assertEqual(persisted["action_type"], "DELETE_FILE")


class TestApprovalAPIEndpoints(unittest.TestCase):
    """Test suite for FastAPI approval endpoints."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_api_approval.db")
        self.db = DatabaseManager(db_path=self.db_path)
        self.workspace = InMemoryWorkspace({
            "workspace/delete_me.tmp": "To be removed.",
        })
        self.execution_service = ExecutionService(workspace=self.workspace)
        self.audit_service = AuditService(db_manager=self.db)
        self.approval_service = ApprovalService(
            db_manager=self.db,
            execution_service=self.execution_service,
            audit_service=self.audit_service,
        )

        app.dependency_overrides[get_audit_service] = lambda: self.audit_service
        app.dependency_overrides[get_execution_service] = lambda: self.execution_service
        app.dependency_overrides[get_approval_service] = lambda: self.approval_service

        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.temp_dir.cleanup()

    def test_post_approval_creates_pending_request(self):
        """POST /approvals with a REVIEW action creates a 201 pending request."""
        payload = {
            "action_type": "DELETE_FILE",
            "path": "workspace/delete_me.tmp",
        }
        response = self.client.post("/approvals", json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["status"], "PENDING")
        self.assertEqual(data["action_type"], "DELETE_FILE")
        self.assertEqual(data["policy_decision"], "REVIEW")
        self.assertIsNotNone(data["id"])

    def test_post_approval_rejects_block_action(self):
        """POST /approvals with a BLOCK action returns 400 Bad Request."""
        payload = {
            "action_type": "READ_FILE",
            "path": ".env",
            "is_sensitive": True,
        }
        response = self.client.post("/approvals", json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("REVIEW", response.json()["detail"])

    def test_get_approvals_list_and_pending(self):
        """GET /approvals and GET /approvals/pending return queued requests."""
        # Create a pending request
        self.client.post("/approvals", json={
            "action_type": "DELETE_FILE",
            "path": "workspace/delete_me.tmp",
        })

        resp = self.client.get("/approvals")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["pending_count"], 1)
        self.assertEqual(len(data["requests"]), 1)

        pending_resp = self.client.get("/approvals/pending")
        self.assertEqual(pending_resp.status_code, 200)
        self.assertEqual(pending_resp.json()["pending_count"], 1)

    def test_get_individual_approval_detail(self):
        """GET /approvals/{id} retrieves specific request or 404 if not found."""
        create_resp = self.client.post("/approvals", json={
            "action_type": "DELETE_FILE",
            "path": "workspace/delete_me.tmp",
        })
        req_id = create_resp.json()["id"]

        detail_resp = self.client.get(f"/approvals/{req_id}")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertEqual(detail_resp.json()["id"], req_id)

        # Unknown ID returns 404
        not_found = self.client.get("/approvals/unknown-uuid-123")
        self.assertEqual(not_found.status_code, 404)

    def test_approve_endpoint_executes_and_resolves(self):
        """POST /approvals/{id}/approve approves, executes simulation, and updates status."""
        create_resp = self.client.post("/approvals", json={
            "action_type": "DELETE_FILE",
            "path": "workspace/delete_me.tmp",
        })
        req_id = create_resp.json()["id"]

        approve_resp = self.client.post(
            f"/approvals/{req_id}/approve",
            json={"comment": "Approved by security team"},
        )
        self.assertEqual(approve_resp.status_code, 200)
        data = approve_resp.json()
        self.assertEqual(data["approval"]["status"], "APPROVED")
        self.assertEqual(data["execution"]["execution_status"], "EXECUTED")

        # Subsequent approval returns 409 Conflict
        repeat_resp = self.client.post(f"/approvals/{req_id}/approve")
        self.assertEqual(repeat_resp.status_code, 409)

    def test_reject_endpoint_resolves_without_execution(self):
        """POST /approvals/{id}/reject marks request REJECTED and does not execute."""
        create_resp = self.client.post("/approvals", json={
            "action_type": "DELETE_FILE",
            "path": "workspace/delete_me.tmp",
        })
        req_id = create_resp.json()["id"]

        reject_resp = self.client.post(
            f"/approvals/{req_id}/reject",
            json={"comment": "Operation unauthorized"},
        )
        self.assertEqual(reject_resp.status_code, 200)
        data = reject_resp.json()
        self.assertEqual(data["approval"]["status"], "REJECTED")

        # Subsequent rejection returns 409 Conflict
        repeat_reject = self.client.post(f"/approvals/{req_id}/reject")
        self.assertEqual(repeat_reject.status_code, 409)

        # File was not deleted
        self.assertTrue(self.workspace.file_exists("workspace/delete_me.tmp"))
