"""ActionShield AI - Audit Logging Service.

Provides a clean interface for logging evaluation and execution outcomes.
Sanitizes metadata to prevent logging secrets, sensitive payloads, or external transmission contents.
"""

from typing import Any, Dict, List, Optional

from app.database.manager import DatabaseManager
from app.policy.engine import PolicyResult
from app.services.executor import ExecutionResult


class AuditService:
    """Manages audit trail recording and retrieval with privacy and security sanitization."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db = db_manager or DatabaseManager()

    def _sanitize_action_metadata(
        self, action: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Extract only safe, non-sensitive action parameters.

        Excludes sensitive data payloads, tokens, passwords, and file contents.
        """
        if not action or not isinstance(action, dict):
            return None

        safe_metadata: Dict[str, Any] = {}

        # Safe non-sensitive fields to retain
        for safe_key in (
            "path",
            "file_path",
            "destination",
            "url",
            "command",
            "is_permitted_location",
            "is_sensitive",
        ):
            if safe_key in action:
                val = action[safe_key]
                # If path or command mentions sensitive keys, do not redact the path, but flag
                safe_metadata[safe_key] = val

        # Handle nested params if present
        params = action.get("params") or action.get("parameters")
        if isinstance(params, dict):
            for safe_key in (
                "path",
                "file_path",
                "destination",
                "url",
                "command",
                "is_permitted_location",
                "is_sensitive",
            ):
                if safe_key in params and safe_key not in safe_metadata:
                    safe_metadata[safe_key] = params[safe_key]

        # Explicitly REDACT/OMIT sensitive payloads, data contents, and tokens
        for forbidden_key in ("data", "payload", "content", "token", "password", "secret"):
            if forbidden_key in action or (isinstance(params, dict) and forbidden_key in params):
                safe_metadata["payload_redacted"] = True

        return safe_metadata or None

    def record_evaluation(
        self,
        policy_result: PolicyResult,
        action: Optional[Dict[str, Any]] = None,
        record_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> str:
        """Record an evaluation outcome before any execution."""
        action_type = getattr(policy_result, "action_type", "UNKNOWN")
        decision = getattr(policy_result, "decision", "UNKNOWN")
        reason = getattr(policy_result, "reason", "Evaluation completed.")

        metadata = self._sanitize_action_metadata(action)

        return self.db.insert_audit_record(
            action_type=action_type,
            policy_decision=decision,
            execution_status=None,  # No execution attempt at evaluation phase
            message=reason,
            metadata=metadata,
            record_id=record_id,
            timestamp=timestamp,
        )

    def record_execution(
        self,
        execution_result: ExecutionResult,
        action: Optional[Dict[str, Any]] = None,
        record_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> str:
        """Record an execution outcome (EXECUTED, SKIPPED_REVIEW_REQUIRED, BLOCKED, or FAILED_CLOSED)."""
        action_type = getattr(execution_result, "action_type", "UNKNOWN")
        decision = getattr(execution_result, "policy_decision", "UNKNOWN")
        status = getattr(execution_result, "execution_status", "UNKNOWN")
        message = getattr(execution_result, "message", "Execution processed.")

        metadata = self._sanitize_action_metadata(action)

        return self.db.insert_audit_record(
            action_type=action_type,
            policy_decision=decision,
            execution_status=status,
            message=message,
            metadata=metadata,
            record_id=record_id,
            timestamp=timestamp,
        )

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent audit logs in newest-first order."""
        return self.db.get_recent_audit_records(limit=limit)
