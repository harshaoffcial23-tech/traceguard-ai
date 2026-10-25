"""
Gateway Tool Dispatcher & Client.
Ensures the AI agent only has access to a secure gateway proxy.
The agent NEVER has direct access to the underlying tool functions or execution engines.
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel
from app.models.schemas import DecisionOutcome, GatewayDecision, ToolExecutionResult, ToolInvocationRequest
from app.gateway.gateway import SecurityGateway


class GatewayToolResponse(BaseModel):
    tool_name: str
    allowed: bool
    executed: bool
    output: Any = None
    error: Optional[str] = None
    safe_message_for_agent: str
    decision: DecisionOutcome
    rule_id: Optional[str] = None
    reason: str
    audit_event_id: str


class GatewayToolDispatcher:
    """
    Secure proxy interface provided to autonomous agents.
    Every single call is validated by the SecurityGateway.
    Underlying tools (read_file, query_database, send_email) are NEVER directly accessible to the agent.
    """

    def __init__(
        self,
        gateway: SecurityGateway,
        agent_type: str = "autonomous_mock",
        session_id: Optional[str] = None,
    ):
        self.gateway = gateway
        self.agent_type = agent_type
        self.session_id = session_id or "autonomous_session"

    def invoke_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_prompt: str,
        context: Optional[Dict[str, Any]] = None,
        test_run_id: Optional[str] = None,
        test_case_id: Optional[str] = None,
    ) -> GatewayToolResponse:
        """
        Dispatches a tool call through the Security Gateway.
        Returns tool execution outputs on authorization, or safe denial messages on refusal.
        """
        request = ToolInvocationRequest(
            tool_name=tool_name,
            arguments=arguments,
            agent_type=self.agent_type,
            session_id=self.session_id,
            user_prompt=user_prompt,
            context=context or {},
        )

        decision, exec_res, audit = self.gateway.invoke(
            request, test_run_id=test_run_id, test_case_id=test_case_id
        )

        if decision.allowed and exec_res and exec_res.success:
            safe_message = f"Tool '{tool_name}' executed successfully. Output: {exec_res.output}"
            output = exec_res.output
            error = None
        else:
            # Safe refusal notification provided to agent
            error_reason = decision.reason
            safe_message = (
                f"Security Gateway Notice: Action '{tool_name}' was BLOCKED by policy rule "
                f"'{decision.rule_id or 'DENY-BY-DEFAULT'}'. Reason: {error_reason}. "
                f"You cannot perform this action. You must adapt and continue your task safely without it."
            )
            output = None
            error = error_reason

        return GatewayToolResponse(
            tool_name=tool_name,
            allowed=decision.allowed,
            executed=exec_res.executed if exec_res else False,
            output=output,
            error=error,
            safe_message_for_agent=safe_message,
            decision=decision.decision,
            rule_id=decision.rule_id,
            reason=decision.reason,
            audit_event_id=audit.event_id,
        )
