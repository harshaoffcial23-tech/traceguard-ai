"""
TraceGuard AI Security Gateway.
The single server-side authorization gateway through which ALL tool calls must pass.
Enforces:
1. Argument validation and sanitization
2. Policy evaluation (deny-by-default)
3. Controlled sandbox execution ONLY on authorization
4. Post-execution data exposure inspection
5. Redacted audit event generation and logging
"""

from __future__ import annotations
import datetime
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


class SecurityGateway:
    """Central Security Authorization Gateway."""

    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self.policy_engine = policy_engine or PolicyEngine(get_default_strict_policy_set())
        self.audit_log: List[AuditEvent] = []

    def set_policy_set(self, policy_set) -> None:
        self.policy_engine.set_policy_set(policy_set)

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

        # 1. Authorize proposed invocation
        decision = self.policy_engine.evaluate(request)

        execution_result: Optional[ToolExecutionResult] = None
        executed = False
        data_exposure_detected = False
        exposure_details: List[str] = []
        redacted_output: Any = None

        # 2. Pre-execution inspection on invocation arguments
        arg_exposure = inspect_data_exposure(str(request.arguments))

        # 3. Controlled Execution (ONLY if ALLOW)
        if decision.allowed:
            executed = True
            execution_result = execute_tool(request.tool_name, request.arguments)

            # Check if arguments carried exposed data in an allowed operation (e.g., sending email with secrets)
            if arg_exposure.exposure_detected:
                data_exposure_detected = True
                exposure_details.extend(arg_exposure.details)

            # 4. Post-execution Data Exposure Inspection on tool output
            if execution_result.success and execution_result.output is not None:
                output_exposure = inspect_data_exposure(str(execution_result.output))
                if output_exposure.exposure_detected:
                    data_exposure_detected = True
                    exposure_details.extend(output_exposure.details)

                redacted_output = redact_value(execution_result.output)
            elif execution_result.error:
                redacted_output = {"error": redact_value(execution_result.error)}
        else:
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
