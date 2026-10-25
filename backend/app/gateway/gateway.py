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
from app.tools.controlled_tools import execute_tool


class SessionTracker:
    """Tracks state and enforce limits for an agent execution session."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.action_count = 0
        self.consecutive_denials = 0
        self.total_denials = 0
        self.created_at = time.time()
        self.last_action_at = self.created_at
        self.is_terminated = False
        self.termination_reason: Optional[str] = None


class SecurityGateway:
    """Central Security Authorization Gateway."""

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        max_actions_per_session: int = 10,
        max_consecutive_denials: int = 3,
        max_session_duration_seconds: float = 60.0,
    ):
        self.policy_engine = policy_engine or PolicyEngine(get_default_strict_policy_set())
        self.audit_log: List[AuditEvent] = []
        self.emergency_stopped: bool = False
        self.max_actions_per_session = max_actions_per_session
        self.max_consecutive_denials = max_consecutive_denials
        self.max_session_duration_seconds = max_session_duration_seconds
        self.sessions: Dict[str, SessionTracker] = {}
        self.allowed_agent_types = {"mock", "groq", "autonomous_mock", "tavily_agent", "hybrid"}

    def set_policy_set(self, policy_set) -> None:
        self.policy_engine.set_policy_set(policy_set)

    def set_emergency_stop(self, stopped: bool) -> None:
        """Emergency Stop / Pause kill-switch toggle."""
        self.emergency_stopped = stopped

    def is_emergency_stopped(self) -> bool:
        return self.emergency_stopped

    def get_or_create_session(self, session_id: Optional[str]) -> SessionTracker:
        sid = session_id or "default_session"
        if sid not in self.sessions:
            self.sessions[sid] = SessionTracker(sid)
        return self.sessions[sid]

    def reset_session(self, session_id: str) -> None:
        if session_id in self.sessions:
            del self.sessions[session_id]

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

        # 1. Agent Identity Validation
        if request.agent_type not in self.allowed_agent_types:
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

        # 2. Session Limit Checks
        # A. Already Terminated Session
        if session.is_terminated:
            decision = GatewayDecision(
                allowed=False,
                decision=DecisionOutcome.DENY,
                policy_id=self.policy_engine.policy_set.id,
                rule_id="SESSION_TERMINATED",
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
                decision=DecisionOutcome.DENY,
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
            data_exposure_detected=data_exposure_detected,
            exposure_details=exposure_details,
            execution_output_redacted=redacted_output,
            context=redact_value(request.context),
        )

        self.audit_log.append(audit_event)
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
        exec_res = ToolExecutionResult(
            executed=False,
            success=False,
            error=f"Blocked by Security Gateway: {decision.reason}",
            metadata={"rule_id": decision.rule_id, "policy_id": decision.policy_id},
        )
        audit_event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            test_run_id=test_run_id,
            test_case_id=test_case_id,
            agent_type=request.agent_type,
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
            data_exposure_detected=False,
            exposure_details=["Blocked prior to execution by gateway limit/kill-switch"],
            execution_output_redacted=None,
            context=redact_value(request.context),
        )
        self.audit_log.append(audit_event)
        return decision, exec_res, audit_event
