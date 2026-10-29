"""
SQLite persistence storage for TraceGuard AI.
Stores policy configurations, test runs, and structured audit events.
"""

from __future__ import annotations
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.models.schemas import (
    AgentRecord,
    AgentRegistrationRequest,
    AuditChainVerificationResult,
    AuditEvent,
    PolicySet,
    TestRun,
    TestSuite,
    TestCase,
    User,
)


DB_FILE = (Path(__file__).resolve().parent.parent.parent / "data" / "traceguard.db").resolve()


class Storage:
    """Manages SQLite schema and queries for TraceGuard AI."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_FILE
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Enable Write-Ahead Logging (WAL) and busy timeout for safe concurrent writes
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA synchronous=NORMAL")

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
                    agent_role TEXT DEFAULT 'standard_agent',
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
                    execution_success INTEGER,
                    execution_error TEXT,
                    data_exposure_detected INTEGER NOT NULL DEFAULT 0,
                    exposure_details_json TEXT NOT NULL,
                    execution_output_redacted_json TEXT,
                    context_json TEXT NOT NULL
                )
                """
            )

            # Migration for existing DB tables
            cursor.execute("PRAGMA table_info(audit_events)")
            cols = {row["name"] for row in cursor.fetchall()}
            if "agent_role" not in cols:
                cursor.execute("ALTER TABLE audit_events ADD COLUMN agent_role TEXT DEFAULT 'standard_agent'")
            if "execution_success" not in cols:
                cursor.execute("ALTER TABLE audit_events ADD COLUMN execution_success INTEGER")
            if "execution_error" not in cols:
                cursor.execute("ALTER TABLE audit_events ADD COLUMN execution_error TEXT")
            if "previous_event_hash" not in cols:
                cursor.execute("ALTER TABLE audit_events ADD COLUMN previous_event_hash TEXT")
            if "event_hash" not in cols:
                cursor.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT")

            # 4. Users table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'operator',
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

            # 5. Sessions table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_revoked INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")

            # 6. Agents table (Connect & Agent Registry)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    role TEXT NOT NULL DEFAULT 'standard_agent',
                    allowed_tools_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    last_active TEXT,
                    api_key_hash TEXT
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)")

            # Seed default agents if registry is empty
            cursor.execute("SELECT COUNT(*) AS cnt FROM agents")
            if cursor.fetchone()["cnt"] == 0:
                now_str = datetime.now(timezone.utc).isoformat()
                default_agents = [
                    (
                        "catalog_agent",
                        "Product Catalog Explorer",
                        "Autonomous agent scoped strictly to read-only product and inventory queries.",
                        "catalog_agent",
                        json.dumps(["query_database"]),
                        "active",
                        now_str,
                        None,
                        None,
                    ),
                    (
                        "readonly_agent",
                        "Read-Only Research Bot",
                        "Scrapes public files, queries read-only database views, and searches web research.",
                        "readonly_agent",
                        json.dumps(["read_file", "query_database", "web_search"]),
                        "active",
                        now_str,
                        None,
                        None,
                    ),
                    (
                        "standard_agent",
                        "Enterprise Operations Agent",
                        "Standard agent with balanced operational access across files, DB, search, and internal email.",
                        "standard_agent",
                        json.dumps(["read_file", "query_database", "send_email", "web_search"]),
                        "active",
                        now_str,
                        None,
                        None,
                    ),
                    (
                        "demo_external_agent",
                        "External Partner Agent",
                        "External integration agent authenticating via API tokens into TraceGuard gateway.",
                        "standard_agent",
                        json.dumps(["read_file", "query_database", "web_search"]),
                        "active",
                        now_str,
                        None,
                        None,
                    ),
                ]
                cursor.executemany(
                    """
                    INSERT INTO agents (agent_id, name, description, role, allowed_tools_json, status, created_at, last_active, api_key_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    default_agents,
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

            # Hash-linking calculation for tamper-evident audit ledger
            cursor.execute("SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1")
            prev_row = cursor.fetchone()
            prev_keys = prev_row.keys() if prev_row and hasattr(prev_row, "keys") else []
            prev_hash = prev_row["event_hash"] if (prev_row and "event_hash" in prev_keys and prev_row["event_hash"]) else "0" * 64

            decision_str = str(event.decision.value if hasattr(event.decision, "value") else event.decision)
            payload_str = f"{prev_hash}:{event.event_id}:{event.timestamp}:{event.agent_type}:{event.tool_name}:{decision_str}:{1 if event.executed else 0}:{event.raw_arguments_hash}"
            cur_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
            event.previous_event_hash = prev_hash
            event.event_hash = cur_hash

            cursor.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, test_run_id, test_case_id, agent_type, agent_role, tool_name,
                    raw_arguments_hash, redacted_arguments_json, decision, policy_id, rule_id,
                    reason, violations_json, attempted, executed, execution_success, execution_error,
                    data_exposure_detected, exposure_details_json, execution_output_redacted_json, context_json,
                    previous_event_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.test_run_id,
                    event.test_case_id,
                    event.agent_type,
                    getattr(event, "agent_role", "standard_agent"),
                    event.tool_name,
                    event.raw_arguments_hash,
                    json.dumps(event.redacted_arguments),
                    decision_str,
                    event.policy_id,
                    event.rule_id,
                    event.reason,
                    json.dumps(event.violations),
                    1 if event.attempted else 0,
                    1 if event.executed else 0,
                    1 if event.execution_success else (0 if event.execution_success is False else None),
                    event.execution_error,
                    1 if event.data_exposure_detected else 0,
                    json.dumps(event.exposure_details),
                    json.dumps(event.execution_output_redacted) if event.execution_output_redacted is not None else None,
                    json.dumps(event.context),
                    prev_hash,
                    cur_hash,
                ),
            )
            conn.commit()

    def list_audit_events(
        self,
        test_run_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        decision: Optional[str] = None,
        agent_type: Optional[str] = None,
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
        if agent_type:
            query += " AND agent_type = ?"
            params.append(agent_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            events = []
            for row in rows:
                row_keys = row.keys() if hasattr(row, "keys") else []
                events.append(
                    AuditEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        test_run_id=row["test_run_id"],
                        test_case_id=row["test_case_id"],
                        agent_type=row["agent_type"],
                        agent_role=row["agent_role"] if "agent_role" in row_keys else "standard_agent",
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
                        execution_success=bool(row["execution_success"]) if ("execution_success" in row_keys and row["execution_success"] is not None) else None,
                        execution_error=row["execution_error"] if "execution_error" in row_keys else None,
                        data_exposure_detected=bool(row["data_exposure_detected"]),
                        exposure_details=json.loads(row["exposure_details_json"]),
                        execution_output_redacted=json.loads(row["execution_output_redacted_json"])
                        if row["execution_output_redacted_json"]
                        else None,
                        context=json.loads(row["context_json"]),
                        previous_event_hash=row["previous_event_hash"] if "previous_event_hash" in row_keys else None,
                        event_hash=row["event_hash"] if "event_hash" in row_keys else None,
                    )
                )
            return events

    def verify_audit_chain(self) -> AuditChainVerificationResult:
        """
        Cryptographically verifies the hash-linked audit chain.
        Detects out-of-band modifications, record tampering, deletions, or insertions.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT rowid, * FROM audit_events ORDER BY rowid ASC")
            rows = cursor.fetchall()

            if not rows:
                return AuditChainVerificationResult(
                    total_events=0,
                    verified_events=0,
                    is_valid=True,
                    message="Audit log is empty. Chain is intact.",
                )

            expected_prev_hash = "0" * 64
            verified_count = 0
            for idx, row in enumerate(rows):
                row_keys = row.keys() if hasattr(row, "keys") else []
                stored_prev = row["previous_event_hash"] if "previous_event_hash" in row_keys else None
                stored_hash = row["event_hash"] if "event_hash" in row_keys else None

                # For legacy records created before hashing was enabled
                if not stored_hash:
                    continue

                if stored_prev != expected_prev_hash:
                    return AuditChainVerificationResult(
                        total_events=len(rows),
                        verified_events=verified_count,
                        is_valid=False,
                        tampered_event_id=row["event_id"],
                        tampered_index=idx,
                        message=f"Audit chain broken at event '{row['event_id']}': predecessor hash mismatch (expected {expected_prev_hash[:8]}..., got {str(stored_prev)[:8]}...).",
                    )

                decision_val = str(row["decision"])
                executed_val = 1 if row["executed"] else 0
                calc_payload = f"{stored_prev}:{row['event_id']}:{row['timestamp']}:{row['agent_type']}:{row['tool_name']}:{decision_val}:{executed_val}:{row['raw_arguments_hash']}"
                calculated_hash = hashlib.sha256(calc_payload.encode("utf-8")).hexdigest()

                if calculated_hash != stored_hash:
                    return AuditChainVerificationResult(
                        total_events=len(rows),
                        verified_events=verified_count,
                        is_valid=False,
                        tampered_event_id=row["event_id"],
                        tampered_index=idx,
                        message=f"Cryptographic signature mismatch at event '{row['event_id']}': contents modified out-of-band.",
                    )

                expected_prev_hash = stored_hash
                verified_count += 1

            return AuditChainVerificationResult(
                total_events=len(rows),
                verified_events=verified_count,
                is_valid=True,
                message=f"All {verified_count} cryptographic audit block signatures verified. Chain is fully intact.",
            )

    # -------------------------------------------------------------
    # Agent Connect & Identity Registry
    # -------------------------------------------------------------
    def list_agents(self) -> List[AgentRecord]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents ORDER BY created_at ASC")
            rows = cursor.fetchall()
            return [
                AgentRecord(
                    agent_id=row["agent_id"],
                    name=row["name"],
                    description=row["description"],
                    role=row["role"],
                    allowed_tools=json.loads(row["allowed_tools_json"]),
                    status=row["status"],
                    created_at=row["created_at"],
                    last_active=row["last_active"],
                    api_key_prefix=row["api_key_hash"][:8] if row["api_key_hash"] else None,
                )
                for row in rows
            ]

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return AgentRecord(
                agent_id=row["agent_id"],
                name=row["name"],
                description=row["description"],
                role=row["role"],
                allowed_tools=json.loads(row["allowed_tools_json"]),
                status=row["status"],
                created_at=row["created_at"],
                last_active=row["last_active"],
                api_key_prefix=row["api_key_hash"][:8] if row["api_key_hash"] else None,
            )

    def create_agent(self, req: AgentRegistrationRequest, api_key_hash: Optional[str] = None) -> AgentRecord:
        now = datetime.now(timezone.utc).isoformat()
        default_tools_by_role = {
            "guest": ["query_database"],
            "catalog_agent": ["query_database"],
            "readonly_agent": ["read_file", "query_database", "web_search"],
            "standard_agent": ["read_file", "query_database", "send_email", "web_search"],
            "admin_agent": ["read_file", "query_database", "send_email", "web_search"],
        }
        allowed = req.allowed_tools if req.allowed_tools is not None else default_tools_by_role.get(req.role, ["query_database"])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO agents (agent_id, name, description, role, allowed_tools_json, status, created_at, api_key_hash)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    role = excluded.role,
                    allowed_tools_json = excluded.allowed_tools_json
                """,
                (req.agent_id, req.name, req.description, req.role, json.dumps(allowed), now, api_key_hash),
            )
            conn.commit()
        return self.get_agent(req.agent_id)  # type: ignore

    def update_agent_permissions(
        self,
        agent_id: str,
        allowed_tools: List[str],
        role: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Optional[AgentRecord]:
        agent = self.get_agent(agent_id)
        if not agent:
            return None
        new_role = role or agent.role
        new_status = status or agent.status
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE agents SET allowed_tools_json = ?, role = ?, status = ? WHERE agent_id = ?",
                (json.dumps(allowed_tools), new_role, new_status, agent_id),
            )
            conn.commit()
        return self.get_agent(agent_id)

    def record_agent_activity(self, agent_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE agents SET last_active = ? WHERE agent_id = ?", (now, agent_id))
            conn.commit()

    # User & Session Management
    def create_user(
        self,
        user_id: str,
        email: str,
        password_hash: str,
        salt: str,
        full_name: str,
        role: str = "operator",
        created_at: Optional[str] = None,
    ) -> User:
        now = created_at or datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (id, email, password_hash, salt, full_name, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, email.strip().lower(), password_hash, salt, full_name.strip(), role, now),
            )
            conn.commit()
        return User(
            id=user_id,
            email=email.strip().lower(),
            full_name=full_name.strip(),
            role=role,
            created_at=now,
        )

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip().lower(),))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, full_name, role, created_at FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                return User(
                    id=row["id"],
                    email=row["email"],
                    full_name=row["full_name"],
                    role=row["role"],
                    created_at=row["created_at"],
                )
            return None

    def update_user_role(self, user_id: str, new_role: str) -> Optional[User]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            conn.commit()
        return self.get_user_by_id(user_id)

    def update_user_password(self, user_id: str, password_hash: str, salt: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                (password_hash, salt, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def create_session(
        self,
        token_hash: str,
        user_id: str,
        expires_at: str,
        created_at: Optional[str] = None,
    ) -> None:
        now = created_at or datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO sessions (token_hash, user_id, created_at, expires_at, is_revoked)
                VALUES (?, ?, ?, ?, 0)
                """,
                (token_hash, user_id, now, expires_at),
            )
            conn.commit()

    def get_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def revoke_session(self, token_hash: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE sessions SET is_revoked = 1 WHERE token_hash = ?", (token_hash,))
            conn.commit()

    def revoke_all_user_sessions(self, user_id: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE sessions SET is_revoked = 1 WHERE user_id = ?", (user_id,))
            conn.commit()
