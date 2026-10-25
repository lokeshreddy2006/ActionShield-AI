"""ActionShield AI - Human Approval Service.

Manages persistent approval requests for actions evaluated as REVIEW.
Enforces security guarantees:
- Only actions evaluated as REVIEW by the policy engine can be queued.
- BLOCK actions can NEVER be queued, approved, or executed.
- Requests can only be resolved once (atomic state transition).
- Revalidates against the active policy engine at approval time.
- Approvals never bypass a BLOCK decision.
- Approved executions are strictly simulated in the in-memory virtual workspace.
- Auditing records all approval and execution outcomes.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.database.manager import DatabaseManager
from app.policy.engine import ActionDecision, PolicyEngine
from app.services.audit import AuditService
from app.services.executor import ExecutionResult, ExecutionService


class ApprovalService:
    """Service orchestrating approval lifecycle, policy revalidation, and controlled execution."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        policy_engine: Optional[PolicyEngine] = None,
        execution_service: Optional[ExecutionService] = None,
        audit_service: Optional[AuditService] = None,
    ) -> None:
        self.db = db_manager or DatabaseManager()
        self.policy_engine = policy_engine or PolicyEngine()
        self.execution_service = execution_service or ExecutionService(policy_engine=self.policy_engine)
        self.audit_service = audit_service or AuditService(db_manager=self.db)

    def create_request(
        self,
        action: Dict[str, Any],
        record_audit: bool = True,
        request_id: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit an action payload into the persistent approval queue.

        CRITICAL SECURITY CHECKS:
        1. Action payload must be a dictionary.
        2. Action is evaluated by the backend PolicyEngine.
        3. Only actions that evaluate to REVIEW are admitted.
        4. BLOCK or ALLOW actions are rejected from entering the queue.
        """
        if not isinstance(action, dict):
            raise ValueError("Invalid action payload: expected a dictionary.")

        policy_res = self.policy_engine.evaluate(action)
        decision = getattr(policy_res, "decision", None)
        action_type = getattr(policy_res, "action_type", "UNKNOWN")
        reason = getattr(policy_res, "reason", "No reason provided.")

        if decision != ActionDecision.REVIEW.value:
            raise ValueError(
                f"Only actions receiving a REVIEW decision can enter the approval queue. "
                f"Action evaluated to '{decision}': {reason}"
            )

        uid = request_id or str(uuid.uuid4())
        ts = created_at or datetime.now(timezone.utc).isoformat()

        self.db.insert_approval_request(
            action_type=action_type,
            action_payload=action,
            policy_decision=decision,
            review_reason=reason,
            request_id=uid,
            created_at=ts,
            status="PENDING",
        )

        if record_audit:
            self.audit_service.record_evaluation(
                policy_res,
                action=action,
                record_id=str(uuid.uuid4()),
                timestamp=ts,
            )

        created_record = self.get_request(uid)
        if not created_record:
            raise RuntimeError("Failed to retrieve newly created approval request.")

        return created_record

    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an individual approval request with sanitized metadata details."""
        req = self.db.get_approval_request(request_id)
        if not req:
            return None

        # Add sanitized metadata details for safe frontend display
        req["sanitized_details"] = self.audit_service._sanitize_action_metadata(
            req.get("action_payload")
        )
        return req

    def list_requests(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve recent approval requests with sanitized metadata, newest-first."""
        records = self.db.list_approval_requests(status=status, limit=limit)
        for record in records:
            record["sanitized_details"] = self.audit_service._sanitize_action_metadata(
                record.get("action_payload")
            )
        return records

    def count_pending(self) -> int:
        """Count active pending approval requests."""
        return self.db.count_pending_approvals()

    def approve_request(
        self, request_id: str, comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Approve a pending request and safely simulate execution.

        SECURITY GUARANTEES:
        1. Verifies request exists and status is PENDING.
        2. Revalidates original action payload against the current PolicyEngine.
        3. If current policy returns BLOCK, approval is permanently refused.
        4. Atomically transitions status to APPROVED to prevent duplicate approvals/races.
        5. Executes only through the controlled in-memory simulation service.
        6. Persists execution outcome and logs to the audit trail.
        """
        existing = self.get_request(request_id)
        if not existing:
            raise KeyError(f"Approval request '{request_id}' not found.")

        current_status = existing["status"]
        if current_status != "PENDING":
            raise ValueError(
                f"Approval request '{request_id}' has already been resolved with status '{current_status}'."
            )

        action_payload = existing["action_payload"]

        # Step 1: Revalidate against current policy
        reval_res = self.policy_engine.evaluate(action_payload)
        if reval_res.decision == ActionDecision.BLOCK.value:
            raise PermissionError(
                f"Cannot approve action: Active policy evaluated action to BLOCK: {reval_res.reason}"
            )

        # Step 2: Atomic state transition
        resolved_ts = datetime.now(timezone.utc).isoformat()
        transitioned = self.db.resolve_approval_request(
            request_id=request_id,
            new_status="APPROVED",
            resolved_at=resolved_ts,
            comment=comment,
        )

        if not transitioned:
            # Race condition caught: another thread/request resolved this concurrently
            refreshed = self.get_request(request_id)
            latest_status = refreshed["status"] if refreshed else "UNKNOWN"
            raise ValueError(
                f"Approval request '{request_id}' has already been resolved with status '{latest_status}'."
            )

        # Step 3: Controlled simulation execution
        exec_res: ExecutionResult = self.execution_service.execute_approved_action(
            action_payload, approval_id=request_id
        )

        # Step 4: Persist execution outcome to approval record
        self.db.update_approval_execution_result(
            request_id=request_id,
            execution_status=exec_res.execution_status,
            execution_result=exec_res.to_dict(),
        )

        # Step 5: Audit logging
        self.audit_service.record_execution(
            exec_res,
            action=action_payload,
            timestamp=resolved_ts,
        )

        updated_request = self.get_request(request_id)
        return {
            "approval": updated_request,
            "execution": exec_res.to_dict(),
        }

    def reject_request(
        self, request_id: str, comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Reject a pending approval request.

        SECURITY GUARANTEES:
        1. Verifies request exists and status is PENDING.
        2. Atomically transitions status to REJECTED.
        3. Never executes the action.
        4. Logs the rejection to the persistent audit trail.
        """
        existing = self.get_request(request_id)
        if not existing:
            raise KeyError(f"Approval request '{request_id}' not found.")

        current_status = existing["status"]
        if current_status != "PENDING":
            raise ValueError(
                f"Approval request '{request_id}' has already been resolved with status '{current_status}'."
            )

        resolved_ts = datetime.now(timezone.utc).isoformat()
        transitioned = self.db.resolve_approval_request(
            request_id=request_id,
            new_status="REJECTED",
            resolved_at=resolved_ts,
            comment=comment,
            execution_status="NOT_EXECUTED",
        )

        if not transitioned:
            refreshed = self.get_request(request_id)
            latest_status = refreshed["status"] if refreshed else "UNKNOWN"
            raise ValueError(
                f"Approval request '{request_id}' has already been resolved with status '{latest_status}'."
            )

        # Record rejection in audit log
        self.audit_service.db.insert_audit_record(
            action_type=existing["action_type"],
            policy_decision="REVIEW",
            execution_status="REJECTED",
            message=f"Action rejected by reviewer: {comment or 'No review comment provided.'}",
            metadata=self.audit_service._sanitize_action_metadata(existing.get("action_payload")),
            timestamp=resolved_ts,
        )

        updated_request = self.get_request(request_id)
        return {
            "approval": updated_request,
            "message": "Action rejected successfully.",
        }
