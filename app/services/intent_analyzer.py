"""ActionShield AI - AI-Assisted Intent Analysis Service.

Translates natural language task descriptions into structured proposed actions
for evaluation by the deterministic PolicyEngine.

IMPORTANT ARCHITECTURE NOTE:
- This is an intent-analysis assistant, NOT an autonomous execution agent.
- Actions are NEVER executed; simulations, shell calls, and network calls are NOT run.
- Policy decisions are calculated strictly by the server-side PolicyEngine.
- In this prototype, a rule-based NLP heuristic parser is implemented without external
  paid API dependencies or hidden keys.
- Modular design allows drop-in replacement with an LLM engine in the future.
"""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, List, Optional, Tuple

from app.policy.engine import (
    ActionCategory,
    ActionDecision,
    PolicyEngine,
    PolicyResult,
)


@dataclass
class ProposedAction:
    """Structured action proposal extracted from natural language input."""

    action_type: str
    params: Dict[str, Any]
    explanation: str
    ambiguities: List[str]
    risk_level: str  # "LOW", "MEDIUM", "HIGH"
    policy_decision: str  # "ALLOW", "REVIEW", "BLOCK"
    policy_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntentAnalysisResult:
    """Complete structured intent analysis report."""

    task_description: str
    analyzer_type: str
    actions: List[ProposedAction]
    total_actions: int
    has_ambiguities: bool
    has_blocked_actions: bool
    has_review_actions: bool
    executed: bool = False
    notice: str = (
        "Intent analysis produces proposals only for security policy evaluation. "
        "Real-world operations, host commands, network transmissions, and file modifications "
        "were NOT executed."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_description": self.task_description,
            "analyzer_type": self.analyzer_type,
            "total_actions": self.total_actions,
            "has_ambiguities": self.has_ambiguities,
            "has_blocked_actions": self.has_blocked_actions,
            "has_review_actions": self.has_review_actions,
            "executed": self.executed,
            "notice": self.notice,
            "actions": [a.to_dict() for a in self.actions],
        }


class IntentAnalyzerService:
    """Extracts proposed agent actions from natural language and verifies policy bounds."""

    def __init__(self, policy_engine: Optional[PolicyEngine] = None) -> None:
        self.policy_engine = policy_engine or PolicyEngine()
        self.analyzer_type = "heuristic-rule-based-nlp-v1"

    def analyze(self, text: str) -> IntentAnalysisResult:
        """Parse natural language task description and evaluate proposed actions against PolicyEngine."""
        if not text or not isinstance(text, str) or not text.strip():
            raise ValueError("Task description cannot be empty.")

        cleaned = text.strip()
        if len(cleaned) > 2000:
            raise ValueError("Task description exceeds maximum permitted length of 2000 characters.")

        # Split input into discrete intent clauses (preserving sequence)
        clauses = self._segment_clauses(cleaned)
        proposed_actions: List[ProposedAction] = []

        for clause in clauses:
            extracted_actions = self._parse_clause(clause)
            for action_dict, explanation, ambiguities, risk_level in extracted_actions:
                # Strictly evaluate via the PolicyEngine (never trust client or NLP model)
                policy_res: PolicyResult = self.policy_engine.evaluate(action_dict)
                decision = getattr(policy_res, "decision", ActionDecision.BLOCK.value)
                reason = getattr(policy_res, "reason", "No reason provided.")

                # If policy blocked it, ensure risk is marked HIGH
                if decision == ActionDecision.BLOCK.value:
                    risk_level = "HIGH"
                elif decision == ActionDecision.REVIEW.value and risk_level != "HIGH":
                    risk_level = "MEDIUM"

                proposed_actions.append(
                    ProposedAction(
                        action_type=action_dict.get("action_type", "UNKNOWN"),
                        params=action_dict,
                        explanation=explanation,
                        ambiguities=ambiguities,
                        risk_level=risk_level,
                        policy_decision=decision,
                        policy_reason=reason,
                    )
                )

        # If no recognized actions could be parsed from any clause
        if not proposed_actions:
            unknown_action = {
                "action_type": "UNKNOWN",
                "raw_text": cleaned[:100],
            }
            policy_res = self.policy_engine.evaluate(unknown_action)
            proposed_actions.append(
                ProposedAction(
                    action_type="UNKNOWN",
                    params=unknown_action,
                    explanation="Unable to discern a supported action type from the provided description.",
                    ambiguities=[
                        "No recognized action pattern (file I/O, data transmission, or command execution) detected in task description."
                    ],
                    risk_level="HIGH",
                    policy_decision=policy_res.decision,
                    policy_reason=policy_res.reason,
                )
            )

        has_ambiguities = any(len(a.ambiguities) > 0 for a in proposed_actions)
        has_blocked_actions = any(a.policy_decision == "BLOCK" for a in proposed_actions)
        has_review_actions = any(a.policy_decision == "REVIEW" for a in proposed_actions)

        return IntentAnalysisResult(
            task_description=cleaned,
            analyzer_type=self.analyzer_type,
            actions=proposed_actions,
            total_actions=len(proposed_actions),
            has_ambiguities=has_ambiguities,
            has_blocked_actions=has_blocked_actions,
            has_review_actions=has_review_actions,
            executed=False,
        )

    def _segment_clauses(self, text: str) -> List[str]:
        """Split compound multi-step instructions into sequential clauses."""
        # Split on explicit clause delimiters: ';' or '\n'
        raw_chunks = re.split(r"[;\n]+", text)
        clauses: List[str] = []

        for chunk in raw_chunks:
            c_strip = chunk.strip()
            if not c_strip:
                continue

            # Split on sentence boundaries (. ! ?)
            sentences = re.split(r"(?<=[.!?])\s+", c_strip)
            for sentence in sentences:
                s_strip = sentence.strip()
                if not s_strip:
                    continue

                # Split on sequential connectors:
                # 'and then', 'then', 'followed by', 'after that', 'afterwards', 'next', 'and finally', 'finally'
                # or ', and' / 'and' / ',' immediately preceding an action verb
                split_pattern = (
                    r"(?:,\s*and\s+(?:then|finally)\s+|\s+and\s+(?:then|finally)\s+|"
                    r",\s*(?:then|finally)\s+|\s+(?:then|finally)\s+|"
                    r",?\s*(?:followed\s+by|after\s+that|afterwards|next)\s+|"
                    r",?\s*and\s+(?=(?:read|inspect|load|write|create|save|delete|remove|erase|send|transmit|upload|run|execute)\b)|"
                    r",\s*(?=(?:read|inspect|load|write|create|save|delete|remove|erase|send|transmit|upload|run|execute)\b))"
                )
                sub_parts = re.split(split_pattern, s_strip, flags=re.IGNORECASE)
                for part in sub_parts:
                    p_clean = part.strip()
                    # Remove trailing punctuation or whitespace
                    p_clean = re.sub(r"^[,.\s]+|[,.\s]+$", "", p_clean).strip()
                    if p_clean:
                        clauses.append(p_clean)

        return clauses if clauses else [text]

    def _extract_path(self, text: str) -> Optional[str]:
        """Extract a file path from a text snippet."""
        # Look for paths with slashes or extensions
        path_match = re.search(
            r"['\"]?([a-zA-Z0-9_\-./\\]+\.[a-zA-Z0-9_\-]+|workspace[/\\][a-zA-Z0-9_\-./\\]*)['\"]?",
            text,
        )
        if path_match:
            candidate = path_match.group(1).strip("'\"")
            # Filter out URLs
            if not candidate.startswith("http://") and not candidate.startswith("https://"):
                return candidate

        # Look after words like 'file', 'from', 'to', 'path'
        after_word = re.search(
            r"\b(?:file|path|from|to|into)\s+['\"]?([a-zA-Z0-9_\-./\\]+)['\"]?",
            text,
            flags=re.IGNORECASE,
        )
        if after_word:
            cand = after_word.group(1).strip("'\"")
            if not cand.startswith("http"):
                return cand

        return None

    def _extract_url(self, text: str) -> Optional[str]:
        """Extract a destination URL or endpoint from text."""
        url_match = re.search(r"https?://[^\s'\",]+", text)
        if url_match:
            return url_match.group(0).rstrip(".,;")

        # Look for domain patterns like api.service.com
        domain_match = re.search(r"\b([a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z]{2,}(?:/[^\s'\",]*)?)", text)
        if domain_match:
            return "https://" + domain_match.group(1).rstrip(".,;")

        return None

    def _extract_command(self, text: str) -> Optional[str]:
        """Extract shell command from text."""
        # Check quoted commands
        quoted = re.search(r"['\"`]([^'\"`]{2,})['\"`]", text)
        if quoted:
            return quoted.group(1).strip()

        # Check after words like "run", "execute", "command", "cmd"
        cmd_match = re.search(
            r"\b(?:run|execute|command|cmd)\s+(?:(?:system|shell|terminal)\s+)?(?:command\s+)?([a-zA-Z0-9_\-./\\ ]+)",
            text,
            flags=re.IGNORECASE,
        )
        if cmd_match:
            cand = cmd_match.group(1).strip()
            # Clean trailing punctuation
            cand = re.sub(r"[.!?]+$", "", cand).strip()
            if cand:
                return cand

        return None

    def _check_sensitive_keywords(self, text: str) -> bool:
        """Check if clause mentions credentials, secrets, tokens, or passwords."""
        sensitive_kw = (
            r"\b(?:secrets?|passwords?|tokens?|credentials?|keys?|api[_-]?keys?|private[_-]?keys?|"
            r"id_rsa|shadow|passwd|\.env|confidential|exfiltrat[a-z]*|sensitive|"
            r"pii|ssn|credit[_-]?cards?|malicious|attacker|evil)\b"
        )
        return bool(re.search(sensitive_kw, text, flags=re.IGNORECASE))

    def _is_permitted_workspace_path(self, path: str) -> bool:
        """Verify whether a path is safely contained within permitted workspace boundaries.

        Returns False for:
        - Empty or non-string paths
        - Absolute paths (leading / or \ or drive letters C:)
        - Directory traversal patterns (..)
        """
        if not path or not isinstance(path, str) or not path.strip():
            return False

        norm = path.replace("\\", "/").strip()
        # Reject absolute paths
        if norm.startswith("/") or re.match(r"^[a-zA-Z]:", norm):
            return False

        # Reject path traversal
        parts = [p for p in norm.split("/") if p]
        if ".." in parts:
            return False

        return True

    def _parse_clause(
        self, clause: str
    ) -> List[Tuple[Dict[str, Any], str, List[str], str]]:
        """Parse a single clause into candidate action, explanation, ambiguities, and risk level."""
        lower = clause.lower()
        extracted: List[Tuple[Dict[str, Any], str, List[str], str]] = []

        has_sensitive_kw = self._check_sensitive_keywords(clause)

        # Check for command execution indicators
        is_command_explicit = bool(
            re.search(
                r"\b(?:run|execute|launch|invoke)\s+(?:a\s+|the\s+)?(?:system\s+)?(?:command|cmd|shell|script|bash|powershell|terminal)\b|"
                r"\b(?:system command|shell command|run command|execute command|powershell|bash)\b",
                lower,
            )
        )
        is_command_general = bool(
            re.search(r"\b(?:run|execute|launch|invoke|powershell|bash|shell|cmd)\b", lower)
        )
        is_delete = bool(
            re.search(r"\b(?:delete|remove|erase|clean|clear|purge|unlink|destroy)\b", lower)
            or (re.search(r"\brm\s+", lower) and not is_command_explicit)
        )
        is_send = bool(re.search(r"\b(?:send|transmit|upload|exfiltrate|post|dispatch|leak|transfer)\b", lower))
        is_write = bool(re.search(r"\b(?:write|create|save|append|dump|store into|record to|output to)\b", lower))
        is_read = bool(re.search(r"\b(?:read|inspect|load|fetch|view|open|parse|scan|cat|examine)\b", lower))

        # 1. COMMAND EXECUTION (takes precedence when explicitly mentioned as command)
        if is_command_explicit or (is_command_general and not (is_delete or is_send or is_write or is_read)):
            command = self._extract_command(clause)
            ambiguities: List[str] = []
            if not command:
                ambiguities.append("System command or executable string is not specified.")
                command = ""

            action = {
                "action_type": ActionCategory.RUN_COMMAND.value,
                "command": command,
            }
            # High risk if dangerous destructive command
            is_high_risk = bool(
                re.search(r"\b(?:rm\s+-rf|del\s+/f|format|shutdown|drop|mkfs)\b", command.lower())
            )
            risk = "HIGH" if is_high_risk else "MEDIUM"
            explanation = f"Proposed system command execution: '{command or '[UNSPECIFIED]'}'."
            extracted.append((action, explanation, ambiguities, risk))

        # 2. DELETE FILE
        elif is_delete:
            path = self._extract_path(clause)
            ambiguities = []
            if not path:
                ambiguities.append("Target file path to delete is not specified in the description.")
                path = ""

            action = {
                "action_type": ActionCategory.DELETE_FILE.value,
                "path": path,
            }
            explanation = f"Proposed deletion of file '{path or '[UNSPECIFIED]'}'."
            extracted.append((action, explanation, ambiguities, "MEDIUM"))

        # 3. SEND DATA
        elif is_send:
            destination = self._extract_url(clause)
            ambiguities = []
            if not destination:
                ambiguities.append("External destination URL or network endpoint is not specified.")
                destination = ""

            # Check if transmitting credentials/tokens or targeting suspicious endpoint
            is_sensitive = has_sensitive_kw or bool(
                re.search(r"(?:malicious|attacker|evil|darkweb|exfil)", destination.lower())
            )
            action = {
                "action_type": ActionCategory.SEND_DATA.value,
                "destination": destination,
                "data": "Extracted payload from task description",
                "is_sensitive": is_sensitive,
            }
            risk = "HIGH" if is_sensitive else "MEDIUM"
            explanation = f"Proposed outbound transmission to destination '{destination or '[UNSPECIFIED]'}'."
            extracted.append((action, explanation, ambiguities, risk))

        # 4. WRITE FILE
        elif is_write:
            path = self._extract_path(clause)
            ambiguities = []
            if not path:
                ambiguities.append("Target destination file path to write is not specified.")
                path = ""

            is_permitted = self._is_permitted_workspace_path(path)
            action = {
                "action_type": ActionCategory.WRITE_FILE.value,
                "path": path,
                "content": "Generated content from intent",
                "is_permitted_location": is_permitted,
                "is_sensitive": has_sensitive_kw,
            }
            if not is_permitted:
                ambiguities.append("File path is not explicitly verified within permitted workspace boundaries.")

            risk = "HIGH" if has_sensitive_kw else ("LOW" if is_permitted else "MEDIUM")
            explanation = f"Proposed file write to location '{path or '[UNSPECIFIED]'}'."
            extracted.append((action, explanation, ambiguities, risk))

        # 5. RUN COMMAND (general fallback if not matched above)
        elif is_command_general:
            command = self._extract_command(clause)
            ambiguities = []
            if not command:
                ambiguities.append("System command or executable string is not specified.")
                command = ""

            action = {
                "action_type": ActionCategory.RUN_COMMAND.value,
                "command": command,
            }
            is_high_risk = bool(
                re.search(r"\b(?:rm\s+-rf|del\s+/f|format|shutdown|drop|mkfs)\b", command.lower())
            )
            risk = "HIGH" if is_high_risk else "MEDIUM"
            explanation = f"Proposed system command execution: '{command or '[UNSPECIFIED]'}'."
            extracted.append((action, explanation, ambiguities, risk))

        # 6. READ FILE
        elif is_read:
            path = self._extract_path(clause)
            ambiguities = []
            if not path:
                ambiguities.append("Source file path to read is not specified.")
                path = ""

            is_permitted = self._is_permitted_workspace_path(path)
            is_sensitive = has_sensitive_kw or ("env" in path.lower()) or ("secret" in path.lower())

            action = {
                "action_type": ActionCategory.READ_FILE.value,
                "path": path,
                "is_permitted_location": is_permitted,
                "is_sensitive": is_sensitive,
            }
            if not is_permitted:
                ambiguities.append("File path is not explicitly verified within permitted workspace boundaries.")

            risk = "HIGH" if is_sensitive else ("LOW" if is_permitted else "MEDIUM")
            explanation = f"Proposed read of file '{path or '[UNSPECIFIED]'}'."
            extracted.append((action, explanation, ambiguities, risk))

        return extracted

