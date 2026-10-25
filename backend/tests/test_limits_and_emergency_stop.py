"""
Tests for Enforceable Limits, Circuit Breakers, and Emergency Stop Controls.
Verifies:
1. Working emergency stop / pause kill-switch.
2. Enforceable limit on action counts per session.
3. Enforceable circuit breaker on repeated consecutive denials.
4. Agent identity authorization.
"""

import pytest
from app.gateway.gateway import SecurityGateway
from app.gateway.policy_engine import PolicyEngine, get_default_strict_policy_set
from app.models.schemas import DecisionOutcome, ToolInvocationRequest


@pytest.fixture
def gateway():
    return SecurityGateway(
        policy_engine=PolicyEngine(get_default_strict_policy_set()),
        max_actions_per_session=4,
        max_consecutive_denials=3,
        max_session_duration_seconds=5.0,
    )


def test_emergency_stop_halts_all_actions(gateway):
    """Verifies that activating emergency stop pauses all further protected actions."""
    assert gateway.is_emergency_stopped() is False

    # 1. Normal allowed call
    req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "public/company_handbook.txt"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is True
    assert res.executed is True

    # 2. Engage Emergency Stop
    gateway.set_emergency_stop(True)
    assert gateway.is_emergency_stopped() is True

    # 3. Attempt same previously allowed call -> Must be immediately denied and NOT executed
    decision_stopped, res_stopped, audit_stopped = gateway.invoke(req)
    assert decision_stopped.allowed is False
    assert decision_stopped.decision == DecisionOutcome.DENY
    assert decision_stopped.rule_id == "EMERGENCY_STOP_TRIGGERED"
    assert "Emergency stop engaged" in decision_stopped.reason
    assert res_stopped.executed is False

    # 4. Deactivate Emergency Stop
    gateway.set_emergency_stop(False)
    decision_restored, res_restored, _ = gateway.invoke(req)
    assert decision_restored.allowed is True
    assert res_restored.executed is True


def test_action_count_limit_enforced(gateway):
    """Verifies that exceeding the maximum action count halts the session."""
    session_id = "test_action_limit_session"

    req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "public/company_handbook.txt"},
        agent_type="mock",
        session_id=session_id,
    )

    # Max actions is set to 4 in fixture
    for i in range(4):
        decision, res, _ = gateway.invoke(req)
        assert decision.allowed is True
        assert res.executed is True

    # 5th action must be blocked by action count limit
    decision_5, res_5, _ = gateway.invoke(req)
    assert decision_5.allowed is False
    assert decision_5.rule_id == "ACTION_LIMIT_EXCEEDED"
    assert res_5.executed is False
    assert "Maximum action count" in decision_5.reason


def test_consecutive_denials_circuit_breaker(gateway):
    """
    Verifies that repeated denials trip the circuit breaker and halt the session
    to prevent brute-force adversarial jailbreak attempts.
    """
    session_id = "test_circuit_breaker_session"

    malicious_req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "restricted/credentials.env"},
        agent_type="mock",
        session_id=session_id,
    )

    # Consecutive denial limit is 3 in fixture
    # Denials 1, 2, 3: denied by policy rule
    for i in range(3):
        decision, res, _ = gateway.invoke(malicious_req)
        assert decision.allowed is False
        assert res.executed is False

    # Call 4: Circuit breaker must trip and halt the session!
    decision_4, res_4, _ = gateway.invoke(malicious_req)
    assert decision_4.allowed is False
    assert decision_4.rule_id == "CIRCUIT_BREAKER_TRIPPED"
    assert "Circuit breaker tripped" in decision_4.reason
    assert res_4.executed is False

    # Even a legitimate call in this session should now be blocked because session is halted
    legit_req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "public/company_handbook.txt"},
        agent_type="mock",
        session_id=session_id,
    )
    decision_legit, res_legit, _ = gateway.invoke(legit_req)
    assert decision_legit.allowed is False
    assert decision_legit.rule_id == "SESSION_TERMINATED"
    assert res_legit.executed is False


def test_unregistered_agent_identity_rejected(gateway):
    """Verifies that requests from unregistered agent identities are denied."""
    spoofed_req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "public/company_handbook.txt"},
        agent_type="unauthorized_external_bot",
    )
    decision, res, _ = gateway.invoke(spoofed_req)
    assert decision.allowed is False
    assert decision.rule_id == "AGENT_IDENTITY_INVALID"
    assert res.executed is False
