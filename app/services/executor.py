"""ActionShield AI - Safe Execution Service.

Provides controlled, simulated execution of agent actions.
Every action MUST first be evaluated by the PolicyEngine.
Only actions with decision == ALLOW are executed via safe in-memory simulation.
Actions with REVIEW or BLOCK, or invalid actions, fail closed and are never executed.
No real shell commands, real file modifications, or real network calls are ever made.
"""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional

from app.policy.engine import (
    ActionCategory,
    ActionDecision,
    PolicyEngine,
    PolicyResult,
)


class ExecutionStatus(str, Enum):
    """Possible outcomes of an execution request."""

    EXECUTED = "EXECUTED"
    SKIPPED_REVIEW_REQUIRED = "SKIPPED_REVIEW_REQUIRED"
    BLOCKED = "BLOCKED"
    FAILED_CLOSED = "FAILED_CLOSED"


@dataclass
class ExecutionResult:
    """Structured result returned by the execution service."""

    action_type: str
    policy_decision: str
    execution_status: str
    message: str
    simulated_result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return asdict(self)

    def __getitem__(self, item: str) -> Any:
        """Allow dict-style key access."""
        return getattr(self, item)


class InMemoryWorkspace:
    """Isolated, in-memory virtual workspace preventing any real filesystem access."""

    def __init__(self, initial_files: Optional[Dict[str, str]] = None) -> None:
        self._files: Dict[str, str] = dict(initial_files) if initial_files else {}

    def normalize_path(self, path: str) -> str:
        """Normalize path separators for consistent in-memory storage."""
        return path.replace("\\", "/").strip().lstrip("/")

    def read_file(self, path: str) -> str:
        norm_path = self.normalize_path(path)
        if norm_path not in self._files:
            raise FileNotFoundError(f"File '{path}' not found in virtual workspace.")
        return self._files[norm_path]

    def write_file(self, path: str, content: str = "") -> None:
        norm_path = self.normalize_path(path)
        self._files[norm_path] = content

    def delete_file(self, path: str) -> bool:
        norm_path = self.normalize_path(path)
        if norm_path in self._files:
            del self._files[norm_path]
            return True
        return False

    def file_exists(self, path: str) -> bool:
        norm_path = self.normalize_path(path)
        return norm_path in self._files

    def list_files(self) -> Dict[str, str]:
        return dict(self._files)


class ExecutionService:
    """Controls and safely simulates action execution based on PolicyEngine decisions."""

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        workspace: Optional[InMemoryWorkspace] = None,
    ) -> None:
        self.policy_engine = policy_engine or PolicyEngine()
        self.workspace = workspace or InMemoryWorkspace()

    def _extract_field(
        self, action: Dict[str, Any], *field_names: str, default: Any = None
    ) -> Any:
        """Helper to extract a field from top-level keys or nested 'params' dictionary."""
        for field in field_names:
            if field in action and action[field] is not None:
                return action[field]

        params = action.get("params") or action.get("parameters") or {}
        if isinstance(params, dict):
            for field in field_names:
                if field in params and params[field] is not None:
                    return params[field]

        return default

    def execute(self, action: Any) -> ExecutionResult:
        """Evaluate and, if permitted, safely simulate action execution.

        Step 1: Consult PolicyEngine.
        Step 2: Handle policy decision:
          - ALLOW: execute safe simulation only.
          - REVIEW: do not execute; require human approval.
          - BLOCK: do not execute; blocked.
          - Any unknown/missing decision: fail closed and do not execute.
        """
        # Step 1: Policy consultation
        policy_res: PolicyResult = self.policy_engine.evaluate(action)

        decision = getattr(policy_res, "decision", None)
        action_type = getattr(policy_res, "action_type", "UNKNOWN")
        reason = getattr(policy_res, "reason", "No reason provided.")

        # Step 2: Decision handling
        if decision == ActionDecision.ALLOW.value:
            return self._execute_safe_simulation(action, action_type, policy_res)

        elif decision == ActionDecision.REVIEW.value:
            return ExecutionResult(
                action_type=action_type,
                policy_decision=decision,
                execution_status=ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value,
                message=f"Action '{action_type}' requires human approval before execution. {reason}",
                simulated_result=None,
            )

        elif decision == ActionDecision.BLOCK.value:
            return ExecutionResult(
                action_type=action_type,
                policy_decision=decision,
                execution_status=ExecutionStatus.BLOCKED.value,
                message=f"Action '{action_type}' is blocked by policy: {reason}",
                simulated_result=None,
            )

        else:
            # Ambiguous, unrecognized or missing decision -> Fail Closed
            return ExecutionResult(
                action_type=action_type if action_type else "UNKNOWN",
                policy_decision=str(decision),
                execution_status=ExecutionStatus.FAILED_CLOSED.value,
                message=f"Safety guard: Ambiguous or invalid policy decision '{decision}'. Execution halted.",
                simulated_result=None,
            )

    def _execute_safe_simulation(
        self, action: Dict[str, Any], action_type: str, policy_res: PolicyResult
    ) -> ExecutionResult:
        """Safely simulate permitted operations inside isolated in-memory workspace."""
        if not isinstance(action, dict):
            return ExecutionResult(
                action_type=action_type,
                policy_decision=policy_res.decision,
                execution_status=ExecutionStatus.FAILED_CLOSED.value,
                message="Action payload is malformed.",
                simulated_result=None,
            )

        if action_type == ActionCategory.READ_FILE.value:
            path = self._extract_field(action, "path", "file_path", "target")
            if not self.workspace.file_exists(path):
                # Auto-populate a safe mock content for simulated reading if not pre-seeded
                self.workspace.write_file(path, f"Simulated content for {path}")

            content = self.workspace.read_file(path)
            return ExecutionResult(
                action_type=action_type,
                policy_decision=policy_res.decision,
                execution_status=ExecutionStatus.EXECUTED.value,
                message=f"Simulated read of '{path}' completed safely.",
                simulated_result={
                    "path": path,
                    "content": content,
                    "simulated": True,
                },
            )

        elif action_type == ActionCategory.WRITE_FILE.value:
            path = self._extract_field(action, "path", "file_path", "target")
            content = self._extract_field(action, "content", "data", default="")
            self.workspace.write_file(path, str(content))

            return ExecutionResult(
                action_type=action_type,
                policy_decision=policy_res.decision,
                execution_status=ExecutionStatus.EXECUTED.value,
                message=f"Simulated write to '{path}' in virtual workspace succeeded.",
                simulated_result={
                    "path": path,
                    "bytes_written": len(str(content).encode("utf-8")),
                    "simulated": True,
                },
            )

        elif action_type == ActionCategory.DELETE_FILE.value:
            # If ever ALLOWed by a custom policy:
            path = self._extract_field(action, "path", "file_path", "target")
            deleted = self.workspace.delete_file(path)
            return ExecutionResult(
                action_type=action_type,
                policy_decision=policy_res.decision,
                execution_status=ExecutionStatus.EXECUTED.value,
                message=f"Simulated deletion of '{path}' completed in virtual workspace.",
                simulated_result={
                    "path": path,
                    "deleted": deleted,
                    "simulated": True,
                },
            )

        elif action_type == ActionCategory.SEND_DATA.value:
            # Safe mock of outbound transmission
            dest = self._extract_field(action, "destination", "url", "endpoint", "target")
            payload_data = self._extract_field(action, "data", "payload", default="")
            return ExecutionResult(
                action_type=action_type,
                policy_decision=policy_res.decision,
                execution_status=ExecutionStatus.EXECUTED.value,
                message=f"Simulated data dispatch to '{dest}' recorded (no network request sent).",
                simulated_result={
                    "destination": dest,
                    "payload_preview": str(payload_data)[:100],
                    "simulated": True,
                },
            )

        elif action_type == ActionCategory.RUN_COMMAND.value:
            # Safe mock of command execution without using shell or eval/exec
            cmd = self._extract_field(action, "command", "cmd")
            return ExecutionResult(
                action_type=action_type,
                policy_decision=policy_res.decision,
                execution_status=ExecutionStatus.EXECUTED.value,
                message=f"Simulated command '{cmd}' evaluated without shell invocation.",
                simulated_result={
                    "command": cmd,
                    "exit_code": 0,
                    "stdout": f"[SIMULATED OUTPUT] Command '{cmd}' simulated successfully.",
                    "stderr": "",
                    "simulated": True,
                },
            )

        # Unhandled action type fail closed
        return ExecutionResult(
            action_type=action_type,
            policy_decision=policy_res.decision,
            execution_status=ExecutionStatus.FAILED_CLOSED.value,
            message=f"Unknown action category '{action_type}' cannot be simulated.",
            simulated_result=None,
        )

    def execute_approved_action(
        self, action: Dict[str, Any], approval_id: Optional[str] = None
    ) -> ExecutionResult:
        """Safely execute an action that has received verified human approval.

        SECURITY GUARANTEES:
        1. Action is strictly revalidated against the current active PolicyEngine.
        2. If active policy returns BLOCK, execution is permanently REFUSED.
           Approval NEVER bypasses a BLOCK decision.
        3. Only actions that evaluate to REVIEW (or ALLOW) are permitted to execute.
        4. Real shell commands, network requests, or real filesystem operations are NEVER run.
           Simulations are confined strictly to the in-memory virtual workspace.
        5. Invalid or ambiguous states FAIL CLOSED.
        """
        if not isinstance(action, dict):
            return ExecutionResult(
                action_type="UNKNOWN",
                policy_decision=ActionDecision.BLOCK.value,
                execution_status=ExecutionStatus.FAILED_CLOSED.value,
                message="Cannot execute approved action: payload is malformed.",
                simulated_result=None,
            )

        # 1. Revalidate against current policy
        policy_res = self.policy_engine.evaluate(action)
        decision = getattr(policy_res, "decision", None)
        action_type = getattr(policy_res, "action_type", "UNKNOWN")
        reason = getattr(policy_res, "reason", "No reason provided.")

        # 2. BLOCK actions must NEVER execute, even if an approval was attempted
        if decision == ActionDecision.BLOCK.value:
            return ExecutionResult(
                action_type=action_type,
                policy_decision=decision,
                execution_status=ExecutionStatus.BLOCKED.value,
                message=f"Approved execution refused: Current policy returns BLOCK. {reason}",
                simulated_result=None,
            )

        # 3. Permitted for approved actions (REVIEW authorized by human, or ALLOW)
        if decision in (ActionDecision.REVIEW.value, ActionDecision.ALLOW.value):
            sim_res = self._execute_safe_simulation(action, action_type, policy_res)
            # Annotate message that this was an authorized simulation execution
            sim_res.message = f"[APPROVED EXECUTION] {sim_res.message}"
            return sim_res

        # 4. Fail closed on any unrecognized state
        return ExecutionResult(
            action_type=action_type,
            policy_decision=str(decision),
            execution_status=ExecutionStatus.FAILED_CLOSED.value,
            message=f"Safety guard: Ambiguous policy decision '{decision}' during approved execution.",
            simulated_result=None,
        )

