"""
SQLite persistence storage for TraceGuard AI.
Stores policy configurations, test runs, and structured audit events.
"""

from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.models.schemas import AuditEvent, PolicySet, TestRun, TestSuite, TestCase


DB_FILE = (Path(__file__).resolve().parent.parent.parent / "data" / "traceguard.db").resolve()


class Storage:
    """Manages SQLite schema and queries for TraceGuard AI."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_FILE
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Policies table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 0,
                    data_json TEXT NOT NULL
                )
                """
            )

            # 2. Test Runs table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS test_runs (
                    id TEXT PRIMARY KEY,
                    suite_id TEXT NOT NULL,
                    suite_name TEXT NOT NULL,
                    policy_set_id TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    metrics_json TEXT NOT NULL,
                    results_json TEXT NOT NULL
                )
                """
            )

            # 3. Audit Events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    test_run_id TEXT,
                    test_case_id TEXT,
                    agent_type TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    raw_arguments_hash TEXT NOT NULL,
                    redacted_arguments_json TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    policy_id TEXT,
                    rule_id TEXT,
                    reason TEXT NOT NULL,
                    violations_json TEXT NOT NULL,
                    attempted INTEGER NOT NULL DEFAULT 1,
                    executed INTEGER NOT NULL DEFAULT 0,
                    data_exposure_detected INTEGER NOT NULL DEFAULT 0,
                    exposure_details_json TEXT NOT NULL,
                    execution_output_redacted_json TEXT,
                    context_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    # Policy operations
    def save_policy_set(self, policy_set: PolicySet) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if policy_set.is_active:
                cursor.execute("UPDATE policies SET is_active = 0")
            cursor.execute(
                """
                INSERT INTO policies (id, name, description, is_active, data_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    is_active = excluded.is_active,
                    data_json = excluded.data_json
                """,
                (
                    policy_set.id,
                    policy_set.name,
                    policy_set.description,
                    1 if policy_set.is_active else 0,
                    policy_set.model_dump_json(),
                ),
            )
            conn.commit()

    def get_policy_set(self, policy_id: str) -> Optional[PolicySet]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM policies WHERE id = ?", (policy_id,))
            row = cursor.fetchone()
            if row:
                return PolicySet.model_validate_json(row["data_json"])
            return None

    def get_active_policy_set(self) -> Optional[PolicySet]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM policies WHERE is_active = 1 LIMIT 1")
            row = cursor.fetchone()
            if row:
                return PolicySet.model_validate_json(row["data_json"])
            return None

    def list_policy_sets(self) -> List[PolicySet]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM policies ORDER BY is_active DESC, name ASC")
            rows = cursor.fetchall()
            return [PolicySet.model_validate_json(row["data_json"]) for row in rows]

    def set_active_policy(self, policy_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE policies SET is_active = 0")
            cursor.execute("UPDATE policies SET is_active = 1 WHERE id = ?", (policy_id,))
            conn.commit()
            return cursor.rowcount > 0

    # Test Run operations
    def save_test_run(self, test_run: TestRun) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO test_runs (
                    id, suite_id, suite_name, policy_set_id, agent_type, status,
                    started_at, completed_at, metrics_json, results_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    metrics_json = excluded.metrics_json,
                    results_json = excluded.results_json
                """,
                (
                    test_run.id,
                    test_run.suite_id,
                    test_run.suite_name,
                    test_run.policy_set_id,
                    test_run.agent_type,
                    test_run.status,
                    test_run.started_at,
                    test_run.completed_at,
                    test_run.metrics.model_dump_json(),
                    json.dumps([r.model_dump() for r in test_run.results]),
                ),
            )
            conn.commit()

    def get_test_run(self, run_id: str) -> Optional[TestRun]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM test_runs WHERE id = ?", (run_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_test_run(row)

    def list_test_runs(self, limit: int = 50) -> List[TestRun]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM test_runs ORDER BY started_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [self._row_to_test_run(row) for row in rows]

    def _row_to_test_run(self, row: sqlite3.Row) -> TestRun:
        results_data = json.loads(row["results_json"])
        metrics_data = json.loads(row["metrics_json"])
        return TestRun(
            id=row["id"],
            suite_id=row["suite_id"],
            suite_name=row["suite_name"],
            policy_set_id=row["policy_set_id"],
            agent_type=row["agent_type"],
            status=row["status"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            metrics=metrics_data,
            results=results_data,
        )

    # Audit Event operations
    def save_audit_event(self, event: AuditEvent) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, test_run_id, test_case_id, agent_type, tool_name,
                    raw_arguments_hash, redacted_arguments_json, decision, policy_id, rule_id,
                    reason, violations_json, attempted, executed, data_exposure_detected,
                    exposure_details_json, execution_output_redacted_json, context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.test_run_id,
                    event.test_case_id,
                    event.agent_type,
                    event.tool_name,
                    event.raw_arguments_hash,
                    json.dumps(event.redacted_arguments),
                    str(event.decision.value if hasattr(event.decision, "value") else event.decision),
                    event.policy_id,
                    event.rule_id,
                    event.reason,
                    json.dumps(event.violations),
                    1 if event.attempted else 0,
                    1 if event.executed else 0,
                    1 if event.data_exposure_detected else 0,
                    json.dumps(event.exposure_details),
                    json.dumps(event.execution_output_redacted) if event.execution_output_redacted is not None else None,
                    json.dumps(event.context),
                ),
            )
            conn.commit()

    def list_audit_events(
        self,
        test_run_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        decision: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        query = "SELECT * FROM audit_events WHERE 1=1"
        params: List[Any] = []

        if test_run_id:
            query += " AND test_run_id = ?"
            params.append(test_run_id)
        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)
        if decision:
            query += " AND decision = ?"
            params.append(decision)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            events = []
            for row in rows:
                events.append(
                    AuditEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        test_run_id=row["test_run_id"],
                        test_case_id=row["test_case_id"],
                        agent_type=row["agent_type"],
                        tool_name=row["tool_name"],
                        raw_arguments_hash=row["raw_arguments_hash"],
                        redacted_arguments=json.loads(row["redacted_arguments_json"]),
                        decision=row["decision"],
                        policy_id=row["policy_id"],
                        rule_id=row["rule_id"],
                        reason=row["reason"],
                        violations=json.loads(row["violations_json"]),
                        attempted=bool(row["attempted"]),
                        executed=bool(row["executed"]),
                        data_exposure_detected=bool(row["data_exposure_detected"]),
                        exposure_details=json.loads(row["exposure_details_json"]),
                        execution_output_redacted=json.loads(row["execution_output_redacted_json"])
                        if row["execution_output_redacted_json"]
                        else None,
                        context=json.loads(row["context_json"]),
                    )
                )
            return events
