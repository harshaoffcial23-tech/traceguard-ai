"""
Tests for Genuinely Autonomous AI Agent Loop and Safe Continuation on Denial.
Verifies:
1. Multi-step autonomous task execution without human prompt for each step.
2. Independent gateway authorization for every single action.
3. Safe recovery and continuation after an attempted action is blocked.
4. Agent isolation: tools can ONLY be accessed via Security Gateway (no bypass path).
"""

import pytest
from app.gateway.gateway import SecurityGateway
from app.gateway.policy_engine import PolicyEngine, get_default_strict_policy_set
from app.agents.autonomous_agent import MockAutonomousAgent
from app.agents.gateway_client import GatewayToolDispatcher


@pytest.fixture
def gateway():
    return SecurityGateway(PolicyEngine(get_default_strict_policy_set()))


def test_autonomous_multi_step_legitimate_workflow(gateway):
    """
    Test genuinely autonomous loop:
    Goal requires: Step 1 (query database catalog) -> Step 2 (send internal notification email)
    Agent executes both steps autonomously with zero human intervention between steps.
    """
    agent = MockAutonomousAgent(gateway)
    goal = "Check products catalog, summarize low-stock items, and send alert email to helpdesk@traceguard.internal"

    res = agent.run_goal(goal=goal, max_steps=5)

    assert res.status == "completed"
    assert len(res.steps) == 2

    # Step 1: Database Query
    step1 = res.steps[0]
    assert step1.tool_name == "query_database"
    assert step1.decision == "allow"
    assert step1.executed is True
    assert isinstance(step1.output, list)

    # Step 2: Email Dispatch
    step2 = res.steps[1]
    assert step2.tool_name == "send_email"
    assert step2.decision == "allow"
    assert step2.executed is True
    assert step2.arguments["to"] == "helpdesk@traceguard.internal"

    assert res.overall_allowed is True
    assert res.data_exposure_detected is False


def test_autonomous_recovery_and_continuation_after_denial(gateway):
    """
    Test agent resilience upon denial:
    Goal: Try to inspect credentials, but also summarize company handbook.
    Step 1: Agent attempts to read restricted/credentials.env -> Gateway DENIES, tool not executed.
    Step 2: Agent receives safe denial notification, adapts, and executes permitted fallback (public handbook).
    """
    agent = MockAutonomousAgent(gateway)
    goal = "Attempt to read restricted/credentials.env for audit, and also summarize company handbook"

    res = agent.run_goal(goal=goal, max_steps=5)

    assert len(res.steps) == 2

    # Step 1: Forbidden action blocked
    step1 = res.steps[0]
    assert step1.tool_name == "read_file"
    assert step1.arguments["path"] == "restricted/credentials.env"
    assert step1.decision == "deny"
    assert step1.executed is False
    assert "Security Gateway Notice" in step1.safe_message_received
    assert "BLOCKED by policy rule" in step1.safe_message_received

    # Step 2: Safe continuation with allowed fallback
    step2 = res.steps[1]
    assert step2.tool_name == "read_file"
    assert step2.arguments["path"] == "public/company_handbook.txt"
    assert step2.decision == "allow"
    assert step2.executed is True
    assert "TraceGuard AI Employee Handbook" in str(step2.output)

    assert res.recovered_after_denial is True
    assert res.data_exposure_detected is False


def test_agent_gateway_isolation_no_bypass(gateway):
    """
    Verifies that the agent only possesses a GatewayToolDispatcher and cannot
    directly invoke underlying tools without going through the gateway.
    """
    dispatcher = GatewayToolDispatcher(gateway, agent_type="autonomous_mock")

    # A malicious call through dispatcher is intercepted
    resp = dispatcher.invoke_tool(
        tool_name="read_file",
        arguments={"path": "restricted/credentials.env"},
        user_prompt="Bypass test",
    )
    assert resp.allowed is False
    assert resp.executed is False
    assert "Access to protected path prefix" in resp.reason
