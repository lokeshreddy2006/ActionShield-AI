"""ActionShield AI - FastAPI Backend Application.

Provides endpoints for:
- Deterministic action evaluation
- Controlled simulation execution
- Persistent audit log retrieval
- Human approval queue management
- Workflow crash-test lab and safety bounds verification
"""

from typing import Any, Dict, List, Optional
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Response
from pydantic import BaseModel

from app.database.manager import DatabaseManager
from app.policy.engine import PolicyEngine
from app.services.approval import ApprovalService
from app.services.audit import AuditService
from app.services.crash_test import CrashTestService
from app.services.executor import ExecutionResult, ExecutionService, ExecutionStatus
from app.services.intent_analyzer import IntentAnalyzerService

app = FastAPI(
    title="ActionShield AI",
    description="Safety layer for AI agent action evaluation, human approval workflow, crash-testing, and intent analysis.",
)

# Lazy singletons for production runtime
_default_policy_engine: Optional[PolicyEngine] = None
_default_db_manager: Optional[DatabaseManager] = None
_default_audit_service: Optional[AuditService] = None
_default_execution_service: Optional[ExecutionService] = None
_default_approval_service: Optional[ApprovalService] = None
_default_crash_test_service: Optional[CrashTestService] = None
_default_intent_analyzer: Optional[IntentAnalyzerService] = None



def get_policy_engine() -> PolicyEngine:
    global _default_policy_engine
    if _default_policy_engine is None:
        _default_policy_engine = PolicyEngine()
    return _default_policy_engine


def get_db_manager() -> DatabaseManager:
    global _default_db_manager
    if _default_db_manager is None:
        _default_db_manager = DatabaseManager()
    return _default_db_manager


def get_audit_service(
    db: DatabaseManager = Depends(get_db_manager),
) -> AuditService:
    global _default_audit_service
    if _default_audit_service is None:
        _default_audit_service = AuditService(db_manager=db)
    return _default_audit_service


def get_execution_service(
    policy_engine: PolicyEngine = Depends(get_policy_engine),
) -> ExecutionService:
    global _default_execution_service
    if _default_execution_service is None:
        _default_execution_service = ExecutionService(policy_engine=policy_engine)
    return _default_execution_service


def get_approval_service(
    db: DatabaseManager = Depends(get_db_manager),
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    execution_service: ExecutionService = Depends(get_execution_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> ApprovalService:
    global _default_approval_service
    # If running with injected overrides (such as in unit tests)
    if (
        audit_service is not _default_audit_service
        or execution_service is not _default_execution_service
    ):
        return ApprovalService(
            db_manager=audit_service.db,
            policy_engine=policy_engine,
            execution_service=execution_service,
            audit_service=audit_service,
        )
    if _default_approval_service is None:
        _default_approval_service = ApprovalService(
            db_manager=db,
            policy_engine=policy_engine,
            execution_service=execution_service,
            audit_service=audit_service,
        )
    return _default_approval_service


def get_crash_test_service(
    db: DatabaseManager = Depends(get_db_manager),
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    audit_service: AuditService = Depends(get_audit_service),
) -> CrashTestService:
    global _default_crash_test_service
    if audit_service is not _default_audit_service:
        return CrashTestService(
            db_manager=audit_service.db,
            policy_engine=policy_engine,
            audit_service=audit_service,
        )
    if _default_crash_test_service is None:
        _default_crash_test_service = CrashTestService(
            db_manager=db,
            policy_engine=policy_engine,
            audit_service=audit_service,
        )
    return _default_crash_test_service


def get_intent_analyzer_service(
    policy_engine: PolicyEngine = Depends(get_policy_engine),
) -> IntentAnalyzerService:
    global _default_intent_analyzer
    if _default_intent_analyzer is None:
        _default_intent_analyzer = IntentAnalyzerService(policy_engine=policy_engine)
    return _default_intent_analyzer



# -------------------------------------------------------------
# Base Models
# -------------------------------------------------------------


class EvaluationResponse(BaseModel):
    decision: str
    reason: str
    action_type: str


class ExecutionResponse(BaseModel):
    action_type: str
    policy_decision: str
    execution_status: str
    message: str
    approval_request_id: Optional[str] = None
    simulated_result: Optional[Dict[str, Any]] = None


class AuditRecordResponse(BaseModel):
    id: str
    timestamp: str
    action_type: str
    policy_decision: str
    execution_status: Optional[str] = None
    message: str
    metadata: Optional[Dict[str, Any]] = None


class AuditLogsResponse(BaseModel):
    records: List[AuditRecordResponse]
    count: int
    limit: int


class ApprovalResolutionRequest(BaseModel):
    comment: Optional[str] = None


class ApprovalRequestResponse(BaseModel):
    id: str
    created_at: str
    action_type: str
    policy_decision: str
    review_reason: str
    status: str
    resolved_at: Optional[str] = None
    resolution_comment: Optional[str] = None
    execution_status: Optional[str] = None
    sanitized_details: Optional[Dict[str, Any]] = None
    action_payload: Optional[Dict[str, Any]] = None
    execution_result: Optional[Dict[str, Any]] = None


class ApprovalListResponse(BaseModel):
    requests: List[ApprovalRequestResponse]
    count: int
    pending_count: int


class ApprovalActionResponse(BaseModel):
    approval: ApprovalRequestResponse
    execution: Optional[Dict[str, Any]] = None
    message: Optional[str] = None


# -------------------------------------------------------------
# Crash Test Models
# -------------------------------------------------------------


class ScenarioStepItem(BaseModel):
    step_number: int
    action: Dict[str, Any]
    expected_decision: str
    description: str


class ScenarioDefinitionItem(BaseModel):
    id: str
    name: str
    safety_risk: str
    expected_outcome: str
    step_count: int
    steps: Optional[List[ScenarioStepItem]] = None


class ScenarioListResponse(BaseModel):
    scenarios: List[ScenarioDefinitionItem]
    count: int


class StepResultItem(BaseModel):
    step_number: int
    action_type: str
    description: str
    expected_decision: str
    actual_decision: str
    decision_matches: bool
    execution_status: str
    passed: bool
    message: str
    sanitized_details: Optional[Dict[str, Any]] = None
    simulation_result: Optional[Dict[str, Any]] = None


class ScenarioRunResponse(BaseModel):
    run_id: str
    scenario_id: str
    scenario_name: str
    safety_risk: str
    expected_outcome: str
    status: str
    started_at: str
    completed_at: str
    total_steps: int
    passed_steps: int
    failed_steps: int
    steps: List[StepResultItem]


class AggregatedCrashTestReport(BaseModel):
    started_at: str
    completed_at: str
    total_scenarios: int
    passed_scenarios: int
    failed_scenarios: int
    all_passed: bool
    scenarios: List[ScenarioRunResponse]


# -------------------------------------------------------------
# Intent Analysis Models
# -------------------------------------------------------------


class IntentAnalysisRequest(BaseModel):
    text: str


class ProposedActionItem(BaseModel):
    action_type: str
    params: Dict[str, Any]
    explanation: str
    ambiguities: List[str]
    risk_level: str
    policy_decision: str
    policy_reason: str


class IntentAnalysisResponse(BaseModel):
    task_description: str
    analyzer_type: str
    total_actions: int
    has_ambiguities: bool
    has_blocked_actions: bool
    has_review_actions: bool
    executed: bool
    notice: str
    actions: List[ProposedActionItem]


# -------------------------------------------------------------
# Core Action Interception & Execution Endpoints
# -------------------------------------------------------------



@app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint to verify backend service status."""
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluationResponse)
def evaluate_action_endpoint(
    payload: Any = Body(default=None),
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    audit_service: AuditService = Depends(get_audit_service),
) -> Dict[str, Any]:
    """Evaluate a proposed action without executing it.

    Accepts a structured action payload, evaluates it through the deterministic
    policy engine, records the evaluation in the audit log, and returns the decision.
    Real-world operations (file I/O, network requests, commands) are NEVER executed.
    """
    action_data = payload if payload is not None else {}
    result = policy_engine.evaluate(action_data)

    try:
        audit_service.record_evaluation(
            result, action=payload if isinstance(payload, dict) else None
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Audit persistence failure.")

    return result.to_dict()


@app.post("/execute", response_model=ExecutionResponse)
def execute_action_endpoint(
    payload: Any = Body(default=None),
    execution_service: ExecutionService = Depends(get_execution_service),
    audit_service: AuditService = Depends(get_audit_service),
    approval_service: ApprovalService = Depends(get_approval_service),
) -> Dict[str, Any]:
    """Safely evaluate and execute a proposed action in simulation mode.

    Consults the PolicyEngine before execution.
    - ALLOW: Safe in-memory simulation only.
    - REVIEW: Halts execution, requiring approval, and queues for human review.
    - BLOCK / Malformed: Fails closed.
    Audit log records the exact execution outcome.
    """
    action_data = payload if payload is not None else {}
    result: ExecutionResult = execution_service.execute(action_data)

    try:
        audit_service.record_execution(
            result, action=payload if isinstance(payload, dict) else None
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Audit persistence failure.")

    resp_data = result.to_dict()

    # Automatically register into persistent approval queue if REVIEW required
    if (
        result.execution_status == ExecutionStatus.SKIPPED_REVIEW_REQUIRED.value
        and isinstance(payload, dict)
    ):
        try:
            approval_entry = approval_service.create_request(payload, record_audit=False)
            resp_data["approval_request_id"] = approval_entry["id"]
        except Exception:
            pass

    return resp_data


@app.get("/audit", response_model=AuditLogsResponse)
def get_audit_logs(
    response: Response,
    limit: Optional[int] = Query(default=50, description="Max records to retrieve (1-100)"),
    audit_service: AuditService = Depends(get_audit_service),
) -> Dict[str, Any]:
    """Retrieve recent audit records in newest-first order.

    Supports bounded limit (1-100, default 50).
    Sensitive data payloads and credentials are redacted from stored metadata.
    """
    if limit is None or limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Invalid limit parameter: limit must be an integer between 1 and 100.",
        )

    # Prevent client/proxy caching of dynamic audit records
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    try:
        records = audit_service.get_recent_logs(limit=limit)
        return {
            "records": records,
            "count": len(records),
            "limit": limit,
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to retrieve audit logs.")


# -------------------------------------------------------------
# Human Approval Workflow Endpoints
# -------------------------------------------------------------


@app.get("/approvals", response_model=ApprovalListResponse)
def list_approvals_endpoint(
    response: Response,
    status: Optional[str] = Query(
        default=None, description="Filter by status (PENDING, APPROVED, REJECTED)"
    ),
    limit: Optional[int] = Query(
        default=50, description="Max records to retrieve (1-100)"
    ),
    approval_service: ApprovalService = Depends(get_approval_service),
) -> Dict[str, Any]:
    """List approval requests ordered newest-first, optionally filtered by status."""
    if limit is None or limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Invalid limit parameter: limit must be an integer between 1 and 100.",
        )

    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    try:
        records = approval_service.list_requests(status=status, limit=limit)
        pending_count = approval_service.count_pending()
        return {
            "requests": records,
            "count": len(records),
            "pending_count": pending_count,
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to retrieve approval requests.")


@app.get("/approvals/pending", response_model=ApprovalListResponse)
def list_pending_approvals_endpoint(
    response: Response,
    limit: Optional[int] = Query(
        default=50, description="Max pending records to retrieve (1-100)"
    ),
    approval_service: ApprovalService = Depends(get_approval_service),
) -> Dict[str, Any]:
    """Direct convenience endpoint to list all PENDING approval requests."""
    return list_approvals_endpoint(
        response=response,
        status="PENDING",
        limit=limit,
        approval_service=approval_service,
    )


@app.get("/approvals/{request_id}", response_model=ApprovalRequestResponse)
def get_approval_details_endpoint(
    request_id: str,
    approval_service: ApprovalService = Depends(get_approval_service),
) -> Dict[str, Any]:
    """Retrieve details for a single approval request."""
    req = approval_service.get_request(request_id)
    if not req:
        raise HTTPException(
            status_code=404,
            detail=f"Approval request '{request_id}' not found.",
        )
    return req


@app.post("/approvals", response_model=ApprovalRequestResponse, status_code=201)
def create_approval_request_endpoint(
    payload: Any = Body(default=None),
    approval_service: ApprovalService = Depends(get_approval_service),
) -> Dict[str, Any]:
    """Create a persistent approval request for an action requiring human review.

    SECURITY REQUIREMENT:
    Only actions that evaluate to REVIEW under the active PolicyEngine can enter the queue.
    BLOCK or ALLOW actions are rejected.
    """
    if isinstance(payload, dict) and "action" in payload and isinstance(payload["action"], dict):
        action_data = payload["action"]
    elif isinstance(payload, dict):
        action_data = payload
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid action payload: expected a dictionary of action parameters.",
        )

    try:
        return approval_service.create_request(action_data, record_audit=True)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to create approval request.")


@app.post("/approvals/{request_id}/approve", response_model=ApprovalActionResponse)
def approve_action_endpoint(
    request_id: str,
    resolution: Optional[ApprovalResolutionRequest] = Body(default=None),
    approval_service: ApprovalService = Depends(get_approval_service),
) -> Dict[str, Any]:
    """Approve a pending action and safely execute it in the simulation workspace.

    SECURITY CHECKS:
    - Verifies request is in PENDING state.
    - Revalidates the action against the active PolicyEngine.
    - If current policy returns BLOCK, approval and execution are permanently REFUSED.
    - Atomic transition prevents duplicate execution or race conditions.
    """
    comment = resolution.comment if resolution else None
    try:
        return approval_service.approve_request(request_id, comment=comment)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Approval request '{request_id}' not found.",
        )
    except PermissionError as e:
        # Revalidation returned BLOCK
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        # Already resolved
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Approval processing failure: {str(e)}"
        )


@app.post("/approvals/{request_id}/reject", response_model=ApprovalActionResponse)
def reject_action_endpoint(
    request_id: str,
    resolution: Optional[ApprovalResolutionRequest] = Body(default=None),
    approval_service: ApprovalService = Depends(get_approval_service),
) -> Dict[str, Any]:
    """Reject a pending approval request. The action is never executed."""
    comment = resolution.comment if resolution else None
    try:
        return approval_service.reject_request(request_id, comment=comment)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Approval request '{request_id}' not found.",
        )
    except ValueError as e:
        # Already resolved
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Rejection processing failure: {str(e)}"
        )


# -------------------------------------------------------------
# Workflow Crash-Test Lab Endpoints
# -------------------------------------------------------------


@app.get("/crash-tests/scenarios", response_model=ScenarioListResponse)
def list_crash_test_scenarios_endpoint(
    response: Response,
    crash_test_service: CrashTestService = Depends(get_crash_test_service),
) -> Dict[str, Any]:
    """List available predefined workflow test scenarios and risk descriptions."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    scenarios = crash_test_service.list_scenarios()
    return {
        "scenarios": scenarios,
        "count": len(scenarios),
    }


@app.get("/crash-tests/scenarios/{scenario_id}", response_model=ScenarioDefinitionItem)
def get_crash_test_scenario_endpoint(
    scenario_id: str,
    crash_test_service: CrashTestService = Depends(get_crash_test_service),
) -> Dict[str, Any]:
    """Retrieve full details and steps for a specific scenario."""
    scenario = crash_test_service.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=404,
            detail=f"Crash-test scenario '{scenario_id}' not found.",
        )
    return scenario


@app.post("/crash-tests/run/{scenario_id}", response_model=ScenarioRunResponse)
def run_single_crash_test_scenario_endpoint(
    scenario_id: str,
    crash_test_service: CrashTestService = Depends(get_crash_test_service),
) -> Dict[str, Any]:
    """Execute a single scenario in controlled in-memory simulation and return step results."""
    try:
        return crash_test_service.run_scenario(scenario_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Crash-test scenario '{scenario_id}' not found.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Crash-test run failed for scenario '{scenario_id}': {str(e)}",
        )


@app.post("/crash-tests/run-all", response_model=AggregatedCrashTestReport)
def run_all_crash_test_scenarios_endpoint(
    crash_test_service: CrashTestService = Depends(get_crash_test_service),
) -> Dict[str, Any]:
    """Execute all predefined scenarios and return an aggregated safety verification report."""
    try:
        return crash_test_service.run_all()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Aggregated crash-test run failed: {str(e)}",
        )


# -------------------------------------------------------------
# Intent Analysis Endpoint
# -------------------------------------------------------------


@app.post("/intent/analyze", response_model=IntentAnalysisResponse)
def analyze_intent_endpoint(
    payload: IntentAnalysisRequest,
    intent_analyzer: IntentAnalyzerService = Depends(get_intent_analyzer_service),
) -> Dict[str, Any]:
    """Parse natural language task description into structured proposed actions.

    SECURITY ASSURANCE:
    - Zero execution: Real-world file I/O, network requests, and shell commands are never run.
    - Zero approval creation: Does NOT automatically push items to the approval queue.
    - Policy evaluation: Every proposed action is strictly evaluated via PolicyEngine.
    """
    if not payload or not payload.text or not payload.text.strip():
        raise HTTPException(
            status_code=400,
            detail="Task description cannot be empty.",
        )

    try:
        result = intent_analyzer.analyze(payload.text)
        return result.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Intent analysis failure: {str(e)}",
        )

