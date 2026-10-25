"""
Comprehensive security and functional tests for TraceGuard AI user authentication,
password hashing, session tokens, and route protection.
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.gateway.auth import hash_password, verify_password, hash_token, generate_session_token
from app.gateway.rate_limiter import rate_limiter
from app.db.storage import Storage

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_limiter():
    rate_limiter.reset()
    yield
    rate_limiter.reset()


def test_password_hashing_and_verification():
    """Verify password hashing produces distinct salts and constant-time verification works."""
    raw_pass = "ComplexSecOpsP@ssw0rd!"
    hash1, salt1 = hash_password(raw_pass)
    hash2, salt2 = hash_password(raw_pass)

    # Cryptographically random salts must ensure unique hashes for same password
    assert salt1 != salt2
    assert hash1 != hash2
    assert len(salt1) == 32  # 16 bytes hex

    # Verification checks
    assert verify_password(raw_pass, hash1, salt1) is True
    assert verify_password(raw_pass, hash2, salt2) is True
    assert verify_password("WrongPassword!", hash1, salt1) is False
    assert verify_password("", hash1, salt1) is False


def test_session_token_generation_and_hashing():
    """Verify session tokens are high-entropy and only hashes are stored."""
    token, t_hash = generate_session_token()
    assert len(token) >= 32
    assert t_hash == hash_token(token)
    assert t_hash != token


def test_user_registration_and_validation():
    """Test user registration constraints: valid, short password, duplicate email."""
    # Register valid user
    email = f"analyst_{uuid.uuid4().hex[:8]}@traceguard.internal"
    res = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": "ValidStrongPassword123!",
            "full_name": "Security Analyst",
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert "access_token" in data
    assert data["user"]["email"] == email
    assert data["user"]["role"] == "operator"
    assert "traceguard_session" in res.cookies

    # Test short password rejection
    res_short = client.post(
        "/api/auth/register",
        json={
            "email": f"short_{uuid.uuid4().hex[:8]}@traceguard.internal",
            "password": "short",
            "full_name": "Short Password User",
        },
    )
    assert res_short.status_code == 400
    assert "at least 8 characters" in res_short.json()["detail"]

    # Test duplicate email rejection
    res_dup = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": "AnotherPassword123!",
            "full_name": "Duplicate User",
        },
    )
    assert res_dup.status_code == 400
    assert "already exists" in res_dup.json()["detail"]


def test_user_login_and_invalid_credentials():
    """Test login with correct and incorrect credentials."""
    email = f"dev_{uuid.uuid4().hex[:8]}@traceguard.internal"
    password = "SuperSecretDevPassword123!"

    # Register user first
    reg = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Lead Developer",
        },
    )
    assert reg.status_code == 201

    # Login with wrong password
    bad_login = client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword123!"},
    )
    assert bad_login.status_code == 401
    assert "Invalid email or password" in bad_login.json()["detail"]

    # Login with nonexistent email
    no_user = client.post(
        "/api/auth/login",
        json={"email": f"nonexistent_{uuid.uuid4().hex[:8]}@traceguard.internal", "password": password},
    )
    assert no_user.status_code == 401

    # Login with valid credentials
    good_login = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert good_login.status_code == 200
    token_data = good_login.json()
    assert "access_token" in token_data
    assert token_data["user"]["email"] == email
    assert token_data["user"]["role"] == "operator"


def test_auth_me_profile_and_logout_revocation():
    """Test /api/auth/me retrieval and logout revocation."""
    email = f"admin_{uuid.uuid4().hex[:8]}@traceguard.internal"
    password = "AdminSuperPass123!"
    reg = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Admin Tester",
        },
    )
    assert reg.status_code == 201
    token = reg.json()["access_token"]

    # Access /api/auth/me with Bearer token
    me_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email

    # Access /api/auth/me with cookie
    client.cookies.set("traceguard_session", token)
    me_cookie_resp = client.get("/api/auth/me")
    assert me_cookie_resp.status_code == 200
    assert me_cookie_resp.json()["email"] == email

    # Logout
    logout_resp = client.post("/api/auth/logout")
    assert logout_resp.status_code == 200

    # Ensure revoked token can no longer access /api/auth/me
    unauth_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert unauth_resp.status_code == 401


def test_operational_routes_protected_against_unauthenticated_callers():
    """Ensure operational endpoints naturally reject unauthenticated requests with 401."""
    # 1. Policies endpoint
    r_policies = client.get("/api/policies")
    assert r_policies.status_code == 401

    # 2. Runs endpoint
    r_runs = client.get("/api/runs")
    assert r_runs.status_code == 401

    # 3. Emergency stop
    r_stop = client.get("/api/gateway/emergency-stop")
    assert r_stop.status_code == 401

    # 4. Audit events
    r_audit = client.get("/api/audit")
    assert r_audit.status_code == 401

    # 5. Playground execution
    r_play = client.post(
        "/api/playground/execute",
        json={"prompt": "list database tables", "agent_type": "mock"},
    )
    assert r_play.status_code == 401

    # 6. Autonomous run
    r_auto = client.post(
        "/api/agent/autonomous-run",
        json={"goal": "Exfiltrate database", "max_steps": 2},
    )
    assert r_auto.status_code == 401


def test_public_endpoints_accessible_without_auth():
    """Ensure public endpoints remain unauthenticated."""
    # /api/health
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "online"

    # /api/suites
    r_suites = client.get("/api/suites")
    assert r_suites.status_code == 200

    # /api/findings
    r_findings = client.get("/api/findings")
    assert r_findings.status_code == 200


def test_authenticated_caller_can_access_operational_routes():
    """Ensure that an authenticated user can operate the gateway endpoints."""
    # Register and get token
    email = f"active_op_{uuid.uuid4().hex[:8]}@traceguard.internal"
    reg = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": "OperatorSafePass123!",
            "full_name": "Active Operator",
        },
    )
    token = reg.json()["access_token"]
    auth_headers = {
        "Authorization": f"Bearer {token}",
    }

    # Policies read
    r_policies = client.get("/api/policies", headers=auth_headers)
    assert r_policies.status_code == 200
    assert len(r_policies.json()) >= 2

    # Emergency stop status read
    r_stop = client.get("/api/gateway/emergency-stop", headers=auth_headers)
    assert r_stop.status_code == 200

    # Audit log read
    r_audit = client.get("/api/audit", headers=auth_headers)
    assert r_audit.status_code == 200
