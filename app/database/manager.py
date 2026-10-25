"""ActionShield AI - SQLite Database Manager for Audit Logging.

Handles connection management, table initialization, and parameterized queries.
Uses Python's built-in sqlite3 module.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any, Dict, Generator, List, Optional
import uuid

DEFAULT_DB_PATH = os.path.join("app", "database", "actionshield.db")

CREATE_AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action_type TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    execution_status TEXT,
    message TEXT NOT NULL,
    metadata_json TEXT
);
"""

CREATE_INDEX_TIMESTAMP = """
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
"""

CREATE_APPROVAL_REQUESTS_TABLE = """
CREATE TABLE IF NOT EXISTS approval_requests (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    action_type TEXT NOT NULL,
    action_payload_json TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    review_reason TEXT NOT NULL,
    status TEXT NOT NULL,
    resolved_at TEXT,
    resolution_comment TEXT,
    execution_status TEXT,
    execution_result_json TEXT
);
"""

CREATE_INDEX_APPROVAL_STATUS = """
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
"""

CREATE_INDEX_APPROVAL_CREATED_AT = """
CREATE INDEX IF NOT EXISTS idx_approval_requests_created_at ON approval_requests(created_at DESC);
"""

CREATE_CRASH_TEST_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS crash_test_runs (
    id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    passed_steps INTEGER NOT NULL,
    failed_steps INTEGER NOT NULL,
    total_steps INTEGER NOT NULL,
    results_json TEXT NOT NULL
);
"""

CREATE_INDEX_CRASH_TEST_SCENARIO = """
CREATE INDEX IF NOT EXISTS idx_crash_test_runs_scenario ON crash_test_runs(scenario_id);
"""

CREATE_INDEX_CRASH_TEST_STARTED_AT = """
CREATE INDEX IF NOT EXISTS idx_crash_test_runs_started_at ON crash_test_runs(started_at DESC);
"""




class DatabaseManager:
    """Manages SQLite connections and schema initialization."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        # Ensure parent directory exists if using a custom path
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.initialize_schema()

    def get_connection(self) -> sqlite3.Connection:
        """Create a new SQLite connection with foreign keys and dict-like row access."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing transactional execution with automatic commit/rollback."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        """Create database tables and indices if they do not exist."""
        with self.transaction() as conn:
            conn.execute(CREATE_AUDIT_LOG_TABLE)
            conn.execute(CREATE_INDEX_TIMESTAMP)
            conn.execute(CREATE_APPROVAL_REQUESTS_TABLE)
            conn.execute(CREATE_INDEX_APPROVAL_STATUS)
            conn.execute(CREATE_INDEX_APPROVAL_CREATED_AT)
            conn.execute(CREATE_CRASH_TEST_RUNS_TABLE)
            conn.execute(CREATE_INDEX_CRASH_TEST_SCENARIO)
            conn.execute(CREATE_INDEX_CRASH_TEST_STARTED_AT)


    def insert_audit_record(
        self,
        action_type: str,
        policy_decision: str,
        execution_status: Optional[str],
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        record_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> str:
        """Insert a sanitized audit log record using parameterized SQL."""
        uid = record_id or str(uuid.uuid4())
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        meta_str = json.dumps(metadata) if metadata is not None else None

        query = """
        INSERT INTO audit_logs (id, timestamp, action_type, policy_decision, execution_status, message, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """

        with self.transaction() as conn:
            conn.execute(
                query,
                (
                    uid,
                    ts,
                    action_type,
                    policy_decision,
                    execution_status,
                    message,
                    meta_str,
                ),
            )

        return uid

    def get_recent_audit_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent audit records ordered newest-first (timestamp DESC)."""
        if limit <= 0:
            limit = 50

        query = """
        SELECT id, timestamp, action_type, policy_decision, execution_status, message, metadata_json
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT ?;
        """

        with self.transaction() as conn:
            cursor = conn.execute(query, (limit,))
            rows = cursor.fetchall()

        records = []
        for row in rows:
            meta = None
            if row["metadata_json"]:
                try:
                    meta = json.loads(row["metadata_json"])
                except Exception:
                    meta = {}

            records.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "action_type": row["action_type"],
                "policy_decision": row["policy_decision"],
                "execution_status": row["execution_status"],
                "message": row["message"],
                "metadata": meta,
            })

        return records

    def insert_approval_request(
        self,
        action_type: str,
        action_payload: Dict[str, Any],
        policy_decision: str,
        review_reason: str,
        request_id: Optional[str] = None,
        created_at: Optional[str] = None,
        status: str = "PENDING",
    ) -> str:
        """Insert a persistent approval request using parameterized SQL."""
        uid = request_id or str(uuid.uuid4())
        ts = created_at or datetime.now(timezone.utc).isoformat()
        payload_str = json.dumps(action_payload)

        query = """
        INSERT INTO approval_requests (
            id, created_at, action_type, action_payload_json,
            policy_decision, review_reason, status, resolved_at,
            resolution_comment, execution_status, execution_result_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL);
        """

        with self.transaction() as conn:
            conn.execute(
                query,
                (
                    uid,
                    ts,
                    action_type,
                    payload_str,
                    policy_decision,
                    review_reason,
                    status,
                ),
            )

        return uid

    def _row_to_approval_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a database row into an approval request dictionary."""
        payload: Dict[str, Any] = {}
        if row["action_payload_json"]:
            try:
                payload = json.loads(row["action_payload_json"])
            except Exception:
                payload = {}

        exec_result: Optional[Dict[str, Any]] = None
        if row["execution_result_json"]:
            try:
                exec_result = json.loads(row["execution_result_json"])
            except Exception:
                exec_result = None

        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "action_type": row["action_type"],
            "action_payload": payload,
            "policy_decision": row["policy_decision"],
            "review_reason": row["review_reason"],
            "status": row["status"],
            "resolved_at": row["resolved_at"],
            "resolution_comment": row["resolution_comment"],
            "execution_status": row["execution_status"],
            "execution_result": exec_result,
        }

    def get_approval_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific approval request by ID."""
        query = """
        SELECT id, created_at, action_type, action_payload_json, policy_decision,
               review_reason, status, resolved_at, resolution_comment,
               execution_status, execution_result_json
        FROM approval_requests
        WHERE id = ?;
        """
        with self.transaction() as conn:
            cursor = conn.execute(query, (request_id,))
            row = cursor.fetchone()

        if not row:
            return None

        return self._row_to_approval_dict(row)

    def list_approval_requests(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve approval requests, optionally filtered by status, ordered newest-first."""
        if limit <= 0:
            limit = 50

        if status:
            query = """
            SELECT id, created_at, action_type, action_payload_json, policy_decision,
                   review_reason, status, resolved_at, resolution_comment,
                   execution_status, execution_result_json
            FROM approval_requests
            WHERE status = ?
            ORDER BY created_at DESC
            LIMIT ?;
            """
            params: tuple = (status.upper(), limit)
        else:
            query = """
            SELECT id, created_at, action_type, action_payload_json, policy_decision,
                   review_reason, status, resolved_at, resolution_comment,
                   execution_status, execution_result_json
            FROM approval_requests
            ORDER BY created_at DESC
            LIMIT ?;
            """
            params = (limit,)

        with self.transaction() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        return [self._row_to_approval_dict(row) for row in rows]

    def count_pending_approvals(self) -> int:
        """Count how many approval requests are currently in PENDING state."""
        query = "SELECT COUNT(*) FROM approval_requests WHERE status = 'PENDING';"
        with self.transaction() as conn:
            cursor = conn.execute(query)
            row = cursor.fetchone()
            return int(row[0]) if row else 0

    def resolve_approval_request(
        self,
        request_id: str,
        new_status: str,
        resolved_at: Optional[str] = None,
        comment: Optional[str] = None,
        execution_status: Optional[str] = None,
        execution_result: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Atomically transition a request from PENDING to APPROVED or REJECTED.

        Guarantees idempotency and race condition prevention:
        If request is not in PENDING state, update will affect 0 rows and return False.
        """
        ts = resolved_at or datetime.now(timezone.utc).isoformat()
        exec_result_str = json.dumps(execution_result) if execution_result is not None else None

        query = """
        UPDATE approval_requests
        SET status = ?, resolved_at = ?, resolution_comment = ?, execution_status = ?, execution_result_json = ?
        WHERE id = ? AND status = 'PENDING';
        """

        with self.transaction() as conn:
            cursor = conn.execute(
                query,
                (new_status, ts, comment, execution_status, exec_result_str, request_id),
            )
            return cursor.rowcount > 0

    def update_approval_execution_result(
        self,
        request_id: str,
        execution_status: str,
        execution_result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update execution outcome details on an approved request."""
        exec_result_str = json.dumps(execution_result) if execution_result is not None else None
        query = """
        UPDATE approval_requests
        SET execution_status = ?, execution_result_json = ?
        WHERE id = ?;
        """
        with self.transaction() as conn:
            conn.execute(query, (execution_status, exec_result_str, request_id))

    def insert_crash_test_run(
        self,
        scenario_id: str,
        scenario_name: str,
        status: str,
        started_at: str,
        completed_at: str,
        passed_steps: int,
        failed_steps: int,
        total_steps: int,
        results: List[Dict[str, Any]],
        run_id: Optional[str] = None,
    ) -> str:
        """Persist a completed crash test execution run."""
        uid = run_id or str(uuid.uuid4())
        results_str = json.dumps(results)
        query = """
        INSERT INTO crash_test_runs (
            id, scenario_id, scenario_name, status, started_at, completed_at,
            passed_steps, failed_steps, total_steps, results_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self.transaction() as conn:
            conn.execute(
                query,
                (
                    uid,
                    scenario_id,
                    scenario_name,
                    status,
                    started_at,
                    completed_at,
                    passed_steps,
                    failed_steps,
                    total_steps,
                    results_str,
                ),
            )
        return uid

    def get_crash_test_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a crash test run by ID."""
        query = """
        SELECT id, scenario_id, scenario_name, status, started_at, completed_at,
               passed_steps, failed_steps, total_steps, results_json
        FROM crash_test_runs
        WHERE id = ?;
        """
        with self.transaction() as conn:
            cursor = conn.execute(query, (run_id,))
            row = cursor.fetchone()

        if not row:
            return None

        results = []
        if row["results_json"]:
            try:
                results = json.loads(row["results_json"])
            except Exception:
                results = []

        return {
            "id": row["id"],
            "scenario_id": row["scenario_id"],
            "scenario_name": row["scenario_name"],
            "status": row["status"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "passed_steps": row["passed_steps"],
            "failed_steps": row["failed_steps"],
            "total_steps": row["total_steps"],
            "results": results,
        }

    def list_crash_test_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List past crash test runs, ordered newest-first."""
        if limit <= 0:
            limit = 50
        query = """
        SELECT id, scenario_id, scenario_name, status, started_at, completed_at,
               passed_steps, failed_steps, total_steps, results_json
        FROM crash_test_runs
        ORDER BY started_at DESC
        LIMIT ?;
        """
        with self.transaction() as conn:
            cursor = conn.execute(query, (limit,))
            rows = cursor.fetchall()

        runs = []
        for row in rows:
            results = []
            if row["results_json"]:
                try:
                    results = json.loads(row["results_json"])
                except Exception:
                    results = []
            runs.append({
                "id": row["id"],
                "scenario_id": row["scenario_id"],
                "scenario_name": row["scenario_name"],
                "status": row["status"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "passed_steps": row["passed_steps"],
                "failed_steps": row["failed_steps"],
                "total_steps": row["total_steps"],
                "results": results,
            })
        return runs


