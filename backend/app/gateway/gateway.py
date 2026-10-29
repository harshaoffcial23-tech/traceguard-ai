"""
TraceGuard AI Security Gateway.
The single server-side authorization gateway through which ALL tool calls must pass.
Enforces:
1. Agent identity & capability validation
2. Session limits (action count, repeated denial circuit breaker, timeout)
3. Working Emergency Stop / Pause kill switch
4. Policy evaluation (deny-by-default)
5. Controlled sandbox execution ONLY on authorization (no bypass path)
6. Post-execution data exposure inspection
7. Redacted audit event generation and logging
"""

from __future__ import annotations
import datetime
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from app.models.schemas import (
    AuditEvent,
    DecisionOutcome,
    GatewayDecision,
    ToolExecutionResult,
    ToolInvocationRequest,
)
from app.gateway.policy_engine import PolicyEngine, get_default_strict_policy_set
from app.gateway.redactor import hash_arguments, inspect_data_exposure, redact_value
from app.gateway.schema_validator import validate_tool_schema
from app.tools.controlled_tools import execute_tool


class SessionTracker:
    """Tracks state and enforce limits for an agent execution session with thread safety."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.action_count = 0
        self.consecutive_denials = 0
        self.total_denials = 0
        self.created_at = time.time()
        self.last_action_at = self.created_at
        self.is_terminated = False
        self.termination_reason: Optional[str] = None
        self.lock = threading.Lock()


class SecurityGateway:
    """Central Security Authorization Gateway."""

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        max_actions_per_session: int = 10,
        max_consecutive_denials: int = 3,
        max_session_duration_seconds: float = 60.0,
        storage: Optional[Any] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine(get_default_strict_policy_set())
        self.audit_log: List[AuditEvent] = []
        self.storage = storage
        self.emergency_stopped: bool = False
        self.max_actions_per_session = max_actions_per_session
        self.max_consecutive_denials = max_consecutive_denials
        self.max_session_duration_seconds = max_session_duration_seconds
        self.sessions: Dict[str, SessionTracker] = {}
        self.allowed_agent_types = {
            "mock",
            "groq",
            "autonomous_mock",
            "tavily_agent",
            "hybrid",
            "guest",
            "catalog_agent",
            "readonly_agent",
            "admin",
        }
        self.trusted_identity_roles = {
            "admin": "admin_agent",
            "mock": "standard_agent",
            "autonomous_mock": "standard_agent",
            "groq": "standard_agent",
            "hybrid": "standard_agent",
            "tavily_agent": "readonly_agent",
            "readonly_agent": "readonly_agent",
            "catalog_agent": "catalog_agent",
            "guest": "guest",
        }
        self.admin_auth_token = "tg_internal_admin_token_sec_val_2026"
        self._lock = threading.RLock()

    def set_policy_set(self, policy_set) -> None:
        with self._lock:
            self.policy_engine.set_policy_set(policy_set)

    def set_emergency_stop(self, stopped: bool) -> None:
        """Emergency Stop / Pause kill-switch toggle (Thread-safe atomic update)."""
        with self._lock:
            self.emergency_stopped = stopped

    def is_emergency_stopped(self) -> bool:
        with self._lock:
            return self.emergency_stopped

    def get_or_create_session(self, session_id: Optional[str]) -> SessionTracker:
        with self._lock:
            if not session_id:
                sid = f"req_{uuid.uuid4().hex[:12]}"
                self.sessions[sid] = SessionTracker(sid)
                return self.sessions[sid]
            if session_id not in self.sessions:
                self.sessions[session_id] = SessionTracker(session_id)
            return self.sessions[session_id]

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            if session_id in self.sessions:
                del self.sessions[session_id]

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        agent_role: str = "standard_agent",
        agent_type: str = "mock",
        session_id: Optional[str] = None,
        user_prompt: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> GatewayDecision:
        """
        Direct programmatic interface for developers to evaluate a tool call.
        Constructs an authorized ToolInvocationRequest and returns a GatewayDecision.
        """
        request = ToolInvocationRequest(
            tool_name=tool_name,
            arguments=arguments,
            agent_role=agent_role,
            agent_type=agent_type,
            session_id=session_id,
            user_prompt=user_prompt,
            context=context or {},
        )
        decision, _, _ = self.invoke(request)
        return decision

    def invoke(
        self,
        request: ToolInvocationRequest,
        test_run_id: Optional[str] = None,
        test_case_id: Optional[str] = None,
    ) -> Tuple[GatewayDecision, Optional[ToolExecutionResult], AuditEvent]:
        """
        Processes a tool invocation request.
        Guarantees that tool code is NEVER executed unless the gateway issues an explicit ALLOW decision.
        """
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        raw_hash = hash_arguments(request.arguments)
        redacted_args = redact_value(request.arguments)
        session = self.get_or_create_session(request.session_id)

        # 0. Emergency Stop Check (Highest Priority Pause Mechanism)
        if self.emergency_stopped:
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="EMERGENCY_STOP_TRIGGERED",
                reason="Emergency stop engaged: All agent tool executions are halted by operator.",
                violations=["Emergency kill-switch active"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # 1. Agent Identity & Role Capability Scoping
        db_agent = None
        if self.storage:
            try:
                db_agent = self.storage.get_agent(request.agent_type)
            except Exception:
                db_agent = None

        if request.agent_type not in self.allowed_agent_types and not db_agent:
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="AGENT_IDENTITY_INVALID",
                reason=f"Unauthorized agent identity: '{request.agent_type}' is not registered.",
                violations=[f"Unregistered agent identity: {request.agent_type}"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        if db_agent:
            if db_agent.status != "active":
                decision = GatewayDecision(
                    allowed=False,
                    decision=DecisionOutcome.DENY,
                    policy_id=self.policy_engine.policy_set.id,
                    rule_id="AGENT_SUSPENDED",
                    reason=f"Agent '{request.agent_type}' is currently suspended or disabled in security registry.",
                    violations=[f"Suspended agent: {request.agent_type}"],
                )
                return self._build_denied_response(
                    request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
                )
            if request.tool_name not in db_agent.allowed_tools:
                decision = GatewayDecision(
                    allowed=False,
                    decision=DecisionOutcome.DENY,
                    policy_id=self.policy_engine.policy_set.id,
                    rule_id="AGENT_PERMISSION_DENIED",
                    reason=f"Agent '{request.agent_type}' permissions violation: Tool '{request.tool_name}' is not in permitted toolset {db_agent.allowed_tools}.",
                    violations=[f"Tool '{request.tool_name}' exceeds agent '{request.agent_type}' permissions"],
                )
                return self._build_denied_response(
                    request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
                )

        # Validate registered tool name
        valid_tools = {"read_file", "query_database", "send_email", "web_search"}
        if request.tool_name not in valid_tools:
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="VALIDATE_TOOL_NAME",
                reason=f"Tool '{request.tool_name}' is not a registered protected tool.",
                violations=[f"Unregistered tool: '{request.tool_name}'"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # Admin identity verification: 'admin' identity requires valid server-side credentials
        if request.agent_type == "admin":
            provided_token = request.context.get("admin_token") if request.context else None
            if not provided_token or provided_token != self.admin_auth_token:
                decision = GatewayDecision(
                    allowed=False,
                    decision=DecisionOutcome.DENY,
                    policy_id=self.policy_engine.policy_set.id,
                    rule_id="IDENTITY_ROLE_SPOOF_DENIED",
                    reason="Identity authorization violation: Agent claimed 'admin' identity without verified server-side authentication token.",
                    violations=["Unauthenticated 'admin' identity spoofing attempt blocked"],
                )
                return self._build_denied_response(
                    request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
                )

        # Resolve server-side authorized role from identity registry
        server_authorized_role = db_agent.role if db_agent else self.trusted_identity_roles.get(request.agent_type, "guest")
        client_requested_role = getattr(request, "agent_role", None)

        # Privilege hierarchy: guest (1) < catalog_agent (2) < readonly_agent (3) < standard_agent (4) < admin_agent (5)
        role_hierarchy = {
            "guest": 1,
            "catalog_agent": 2,
            "readonly_agent": 3,
            "standard_agent": 4,
            "admin_agent": 5,
        }
        server_level = role_hierarchy.get(server_authorized_role, 1)

        if client_requested_role:
            client_level = role_hierarchy.get(client_requested_role, server_level)
            # Detect and deny client-side privilege escalation / identity spoofing
            if client_level > server_level:
                decision = GatewayDecision(
                    allowed=False,
                    decision=DecisionOutcome.DENY,
                    policy_id=self.policy_engine.policy_set.id,
                    rule_id="IDENTITY_ROLE_SPOOF_DENIED",
                    reason=f"Identity authorization violation: Agent identity '{request.agent_type}' is authorized for role '{server_authorized_role}' (level {server_level}), but attempted unverified elevation to '{client_requested_role}' (level {client_level}).",
                    violations=[f"Unverified role elevation attempt from '{server_authorized_role}' to '{client_requested_role}'"],
                )
                return self._build_denied_response(
                    request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
                )
            effective_role = client_requested_role
        else:
            effective_role = server_authorized_role

        # Scoped capability check based on effective role
        role_capabilities = {
            "admin_agent": {"read_file", "query_database", "send_email", "web_search"},
            "standard_agent": {"read_file", "query_database", "send_email", "web_search"},
            "readonly_agent": {"read_file", "query_database", "web_search"},
            "catalog_agent": {"query_database"},
            "guest": {"query_database"},
        }
        allowed_tools = role_capabilities.get(effective_role, {"query_database"})
        if request.tool_name not in allowed_tools:
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="ROLE_SCOPE_DENIED",
                reason=f"Role capability violation: Role '{effective_role}' is not authorized to invoke tool '{request.tool_name}'. Permitted tools: {sorted(list(allowed_tools))}",
                violations=[f"Tool '{request.tool_name}' exceeds role '{effective_role}' capabilities"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # 2. Server-Side Schema & Argument Validation (Fail closed on malformed input)
        is_schema_valid, schema_err = validate_tool_schema(request.tool_name, request.arguments)
        if not is_schema_valid:
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="SCHEMA_VALIDATION_FAILED",
                reason=f"Server-side schema validation error: {schema_err}",
                violations=[schema_err or "Invalid argument schema"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # 2. Session Limit Checks
        # A. Already Terminated Session
        if session.is_terminated:
            is_timeout_term = "timeout" in (session.termination_reason or "").lower()
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.TIMEOUT if is_timeout_term else DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="SESSION_TIMEOUT" if is_timeout_term else "SESSION_TERMINATED",
                reason=f"Session halted: {session.termination_reason}",
                violations=[f"Session {session.session_id} is terminated"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # B. Execution Time Limit
        elapsed_seconds = time.time() - session.created_at
        if elapsed_seconds > self.max_session_duration_seconds:
            session.is_terminated = True
            session.termination_reason = f"Execution timeout ({self.max_session_duration_seconds}s exceeded)"
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.TIMEOUT,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="TIMEOUT_LIMIT_EXCEEDED",
                reason=f"Execution timeout: Session exceeded maximum execution time ({self.max_session_duration_seconds}s).",
                violations=[f"Session elapsed time {elapsed_seconds:.1f}s > {self.max_session_duration_seconds}s"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # C. Action Count Limit
        if session.action_count >= self.max_actions_per_session:
            session.is_terminated = True
            session.termination_reason = f"Action count limit ({self.max_actions_per_session}) reached"
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="ACTION_LIMIT_EXCEEDED",
                reason=f"Session limit exceeded: Maximum action count ({self.max_actions_per_session}) reached.",
                violations=[f"Action count {session.action_count} reached maximum allowed"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # D. Consecutive Denial Circuit Breaker
        if session.consecutive_denials >= self.max_consecutive_denials:
            session.is_terminated = True
            session.termination_reason = f"Circuit breaker tripped after {self.max_consecutive_denials} consecutive denials"
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="CIRCUIT_BREAKER_TRIPPED",
                reason=f"Circuit breaker tripped: Repeated denials limit ({self.max_consecutive_denials}) exceeded. Session halted.",
                violations=[f"Consecutive denials {session.consecutive_denials} >= threshold"],
            )
            return self._build_denied_response(
                request, decision, event_id, timestamp, raw_hash, redacted_args, test_run_id, test_case_id
            )

        # Increment session action count
        session.action_count += 1
        session.last_action_at = time.time()

        # 3. Policy Evaluation
        decision = self.policy_engine.evaluate(request)

        execution_result: Optional[ToolExecutionResult] = None
        executed = False
        data_exposure_detected = False
        exposure_details: List[str] = []
        redacted_output: Any = None

        # Pre-execution inspection on invocation arguments
        arg_exposure = inspect_data_exposure(str(request.arguments))

        # 4. Controlled Execution (ONLY if ALLOW)
        if decision.allowed:
            # Reset consecutive denial counter upon authorized action
            session.consecutive_denials = 0

            executed = True
            execution_result = execute_tool(request.tool_name, request.arguments)

            # Check if arguments carried exposed data in an allowed operation (e.g., sending email with secrets)
            if arg_exposure.exposure_detected:
                data_exposure_detected = True
                exposure_details.extend(arg_exposure.details)

            # Post-execution Data Exposure Inspection on tool output
            if execution_result.success and execution_result.output is not None:
                output_exposure = inspect_data_exposure(str(execution_result.output))
                if output_exposure.exposure_detected:
                    data_exposure_detected = True
                    exposure_details.extend(output_exposure.details)

                redacted_output = redact_value(execution_result.output)
            elif execution_result.error:
                redacted_output = {"error": redact_value(execution_result.error)}
        else:
            # Update denial tracking for circuit breaker
            session.consecutive_denials += 1
            session.total_denials += 1

            # Explicitly NOT executed -> Zero data exposed, threat intercepted
            executed = False
            data_exposure_detected = False
            if arg_exposure.exposure_detected:
                exposure_details.append("Exfiltration attempt intercepted and prevented by gateway.")
            execution_result = ToolExecutionResult(
                executed=False,
                success=False,
                error=f"Blocked by Security Gateway: {decision.reason}",
                metadata={"rule_id": decision.rule_id, "policy_id": decision.policy_id},
            )

        # 5. Build structured, redacted audit event
        audit_event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            test_run_id=test_run_id,
            test_case_id=test_case_id,
            agent_type=request.agent_type,
            agent_role=effective_role,
            tool_name=request.tool_name,
            raw_arguments_hash=raw_hash,
            redacted_arguments=redacted_args,
            decision=decision.decision,
            policy_id=decision.policy_id,
            rule_id=decision.rule_id,
            reason=decision.reason,
            violations=decision.violations,
            attempted=True,
            executed=executed,
            execution_success=execution_result.success if execution_result else False,
            execution_error=execution_result.error if (execution_result and not execution_result.success) else None,
            data_exposure_detected=data_exposure_detected,
            exposure_details=exposure_details,
            execution_output_redacted=redacted_output,
            context=redact_value(request.context),
        )

        self.audit_log.append(audit_event)
        if self.storage:
            try:
                self.storage.save_audit_event(audit_event)
                self.storage.record_agent_activity(request.agent_type)
            except Exception:
                pass
        return decision, execution_result, audit_event

    def _build_denied_response(
        self,
        request: ToolInvocationRequest,
        decision: GatewayDecision,
        event_id: str,
        timestamp: str,
        raw_hash: str,
        redacted_args: Dict[str, Any],
        test_run_id: Optional[str],
        test_case_id: Optional[str],
    ) -> Tuple[GatewayDecision, ToolExecutionResult, AuditEvent]:
        is_timeout = decision.decision == DecisionOutcome.TIMEOUT
        exec_res = ToolExecutionResult(
            executed=False,
            success=False,
            error=f"Timeout: {decision.reason}" if is_timeout else f"Blocked by Security Gateway: {decision.reason}",
            metadata={"rule_id": decision.rule_id, "policy_id": decision.policy_id},
        )
        audit_role = self.trusted_identity_roles.get(request.agent_type, "guest")
        audit_event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            test_run_id=test_run_id,
            test_case_id=test_case_id,
            agent_type=request.agent_type,
            agent_role=audit_role,
            tool_name=request.tool_name,
            raw_arguments_hash=raw_hash,
            redacted_arguments=redacted_args,
            decision=decision.decision,
            policy_id=decision.policy_id,
            rule_id=decision.rule_id,
            reason=decision.reason,
            violations=decision.violations,
            attempted=True,
            executed=False,
            execution_success=False,
            execution_error=decision.reason,
            data_exposure_detected=False,
            exposure_details=["Execution timed out prior to tool completion"] if is_timeout else ["Blocked prior to execution by gateway limit/kill-switch"],
            execution_output_redacted=None,
            context=redact_value(request.context),
        )
        self.audit_log.append(audit_event)
        if self.storage:
            try:
                self.storage.save_audit_event(audit_event)
                self.storage.record_agent_activity(request.agent_type)
            except Exception:
                pass
        return decision, exec_res, audit_event
