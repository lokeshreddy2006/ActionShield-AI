"""ActionShield AI - Initial Rule-Based Policy Engine.

Evaluates proposed actions against deterministic safety policies
before execution. Actions are categorized and evaluated as:
- ALLOW: Safe, permitted actions
- REVIEW: High-risk or sensitive actions requiring human/supervisor review
- BLOCK: Explicitly forbidden or unsafe actions
"""

from dataclasses import asdict, dataclass
from enum import Enum
import re
from typing import Any, Dict, List, Optional


class ActionDecision(str, Enum):
    """Possible policy decisions."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ActionCategory(str, Enum):
    """Supported action categories."""

    READ_FILE = "READ_FILE"
    WRITE_FILE = "WRITE_FILE"
    DELETE_FILE = "DELETE_FILE"
    SEND_DATA = "SEND_DATA"
    RUN_COMMAND = "RUN_COMMAND"


# Common sensitive file patterns that should not be accessed without restriction
SENSITIVE_FILE_PATTERNS: List[str] = [
    r"\.env",
    r"credentials",
    r"id_rsa",
    r"id_ed25519",
    r"shadow",
    r"passwd",
    r"secret",
    r"\.pem$",
    r"\.key$",
]


@dataclass
class PolicyResult:
    """Structured evaluation result for a proposed action."""

    decision: str
    reason: str
    action_type: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return asdict(self)

    def __getitem__(self, item: str) -> Any:
        """Allow dict-style key access like result['decision']."""
        return getattr(self, item)


class PolicyEngine:
    """Deterministic, rule-based policy evaluator for proposed agent actions."""

    def __init__(self, sensitive_patterns: Optional[List[str]] = None) -> None:
        self.sensitive_patterns = (
            sensitive_patterns if sensitive_patterns is not None else SENSITIVE_FILE_PATTERNS
        )

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

    def _is_sensitive_path(self, path: str) -> bool:
        """Check if a file path matches common sensitive filename patterns."""
        normalized = path.replace("\\", "/").lower()
        for pattern in self.sensitive_patterns:
            if re.search(pattern, normalized):
                return True
        return False

    def evaluate(self, action: Any) -> PolicyResult:
        """Evaluate a proposed action and return a structured PolicyResult.

        Ensures invalid, missing, or ambiguous actions never default to ALLOW.
        """
        # Validate that input is a dictionary
        if not isinstance(action, dict):
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason="Invalid action payload: expected a dictionary of action parameters.",
                action_type="UNKNOWN",
            )

        # Extract and validate action_type
        raw_action_type = action.get("action_type")
        if not raw_action_type or not isinstance(raw_action_type, str):
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason="Action payload missing or invalid 'action_type'.",
                action_type="UNKNOWN",
            )

        action_type = raw_action_type.strip().upper()

        # Handle unknown action types
        supported_types = {cat.value for cat in ActionCategory}
        if action_type not in supported_types:
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason=f"Unknown or unsupported action type: '{raw_action_type}'.",
                action_type=raw_action_type,
            )

        # Dispatch to specific rule evaluators
        if action_type == ActionCategory.READ_FILE.value:
            return self._evaluate_read_file(action, action_type)
        elif action_type == ActionCategory.WRITE_FILE.value:
            return self._evaluate_write_file(action, action_type)
        elif action_type == ActionCategory.DELETE_FILE.value:
            return self._evaluate_delete_file(action, action_type)
        elif action_type == ActionCategory.SEND_DATA.value:
            return self._evaluate_send_data(action, action_type)
        elif action_type == ActionCategory.RUN_COMMAND.value:
            return self._evaluate_run_command(action, action_type)

        # Safety fallback
        return PolicyResult(
            decision=ActionDecision.BLOCK.value,
            reason="Unrecognized evaluation state.",
            action_type=action_type,
        )

    def _evaluate_read_file(self, action: Dict[str, Any], action_type: str) -> PolicyResult:
        """Rule: Reading a permitted, non-sensitive file: ALLOW."""
        path = self._extract_field(action, "path", "file_path", "target")
        if not path or not isinstance(path, str) or not path.strip():
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason="Missing or invalid file path for READ_FILE action.",
                action_type=action_type,
            )

        is_sensitive = self._extract_field(action, "is_sensitive", default=False)
        is_permitted = self._extract_field(
            action, "is_permitted", "is_permitted_location", default=True
        )

        if is_sensitive or self._is_sensitive_path(path):
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason=f"Access to sensitive file '{path}' is blocked.",
                action_type=action_type,
            )

        if is_permitted is False:
            return PolicyResult(
                decision=ActionDecision.REVIEW.value,
                reason=f"Reading file from unverified or non-permitted location '{path}' requires review.",
                action_type=action_type,
            )

        return PolicyResult(
            decision=ActionDecision.ALLOW.value,
            reason=f"Reading permitted, non-sensitive file '{path}' is allowed.",
            action_type=action_type,
        )

    def _evaluate_write_file(self, action: Dict[str, Any], action_type: str) -> PolicyResult:
        """Rule: Writing to an explicitly permitted workspace location: ALLOW."""
        path = self._extract_field(action, "path", "file_path", "target")
        if not path or not isinstance(path, str) or not path.strip():
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason="Missing or invalid file path for WRITE_FILE action.",
                action_type=action_type,
            )

        is_sensitive = self._extract_field(action, "is_sensitive", default=False)
        if is_sensitive or self._is_sensitive_path(path):
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason=f"Writing to sensitive target '{path}' is blocked.",
                action_type=action_type,
            )

        # Check explicit workspace permission
        is_permitted = self._extract_field(
            action,
            "is_permitted_location",
            "is_permitted",
            "is_workspace",
            default=None,
        )

        if is_permitted is True:
            return PolicyResult(
                decision=ActionDecision.ALLOW.value,
                reason=f"Writing to explicitly permitted workspace location '{path}' is allowed.",
                action_type=action_type,
            )

        # Ambiguous or unpermitted location must never default to ALLOW
        return PolicyResult(
            decision=ActionDecision.REVIEW.value,
            reason=f"Writing to location '{path}' is not explicitly verified as permitted; requires review.",
            action_type=action_type,
        )

    def _evaluate_delete_file(self, action: Dict[str, Any], action_type: str) -> PolicyResult:
        """Rule: Deleting files: REVIEW by default."""
        path = self._extract_field(action, "path", "file_path", "target")
        if not path or not isinstance(path, str) or not path.strip():
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason="Missing or invalid file path for DELETE_FILE action.",
                action_type=action_type,
            )

        return PolicyResult(
            decision=ActionDecision.REVIEW.value,
            reason=f"Deleting file '{path}' requires review by default.",
            action_type=action_type,
        )

    def _evaluate_send_data(self, action: Dict[str, Any], action_type: str) -> PolicyResult:
        """Rule: Sending data to an external destination: REVIEW by default.

        Sending data explicitly marked as sensitive to an external destination: BLOCK.
        """
        destination = self._extract_field(action, "destination", "url", "endpoint", "target")
        if not destination or not isinstance(destination, str) or not destination.strip():
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason="Missing or invalid destination for SEND_DATA action.",
                action_type=action_type,
            )

        is_sensitive = self._extract_field(action, "is_sensitive", default=False)
        if is_sensitive:
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason=f"Sending sensitive data to external destination '{destination}' is blocked.",
                action_type=action_type,
            )

        return PolicyResult(
            decision=ActionDecision.REVIEW.value,
            reason=f"Sending data to external destination '{destination}' requires review by default.",
            action_type=action_type,
        )

    def _evaluate_run_command(self, action: Dict[str, Any], action_type: str) -> PolicyResult:
        """Rule: Running a command: REVIEW by default."""
        command = self._extract_field(action, "command", "cmd")
        if not command or not isinstance(command, str) or not command.strip():
            return PolicyResult(
                decision=ActionDecision.BLOCK.value,
                reason="Missing or invalid command for RUN_COMMAND action.",
                action_type=action_type,
            )

        return PolicyResult(
            decision=ActionDecision.REVIEW.value,
            reason=f"Running system command '{command}' requires review by default.",
            action_type=action_type,
        )


def evaluate_action(action: Any) -> PolicyResult:
    """Convenience functional interface for evaluating a proposed action."""
    return PolicyEngine().evaluate(action)
