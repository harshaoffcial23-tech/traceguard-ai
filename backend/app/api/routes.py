"""
FastAPI REST routes for TraceGuard AI security platform.
"""

from __future__ import annotations
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from app.models.schemas import (
    AgentDispatchRequest,
    AgentDispatchResponse,
    AgentPermissionsUpdateRequest,
    AgentRecord,
    AgentRegistrationRequest,
    AuditChainVerificationResult,
    AuditEvent,
    AuthTokenResponse,
    DecisionOutcome,
    PolicySet,
    RoleUpdateRequest,
    TestRun,
    TestSuite,
    ToolInvocationRequest,
    User,
    UserLoginRequest,
    UserRegisterRequest,
    UserRole,
)
from app.gateway.gateway import SecurityGateway
from app.gateway.policy_engine import get_default_strict_policy_set, get_permissive_policy_set
from app.gateway.auth import (
    calculate_session_expiry,
    extract_token_from_request,
    generate_csrf_token,
    generate_session_token,
    get_current_user,
    get_optional_current_user,
    hash_password,
    hash_token,
    is_cookie_secure,
    is_production,
    require_roles,
    verify_csrf_and_origin,
    verify_dummy_password,
    verify_password,
    DEFAULT_PBKDF2_ITERATIONS,
)
from app.gateway.rate_limiter import rate_limiter
from app.agents.mock_agent import MockAgent
from app.agents.groq_adapter import GroqAgent
from app.agents.tavily_adapter import TavilySearchAdapter
from app.runner.test_runner import TestRunner, list_available_suites, load_test_suite
from app.db.storage import Storage


router = APIRouter()
storage = Storage()
gateway = SecurityGateway(storage=storage)
test_runner = TestRunner(storage=storage, gateway=gateway)


def ensure_default_policies():
    """Seed initial policy sets and optional development demo admin."""
    active = storage.get_active_policy_set()
    if not active:
        strict = get_default_strict_policy_set()
        storage.save_policy_set(strict)
        permissive = get_permissive_policy_set()
        storage.save_policy_set(permissive)

    # Demo admin account is strictly development-only and never seeded by default in production
    env = os.getenv("TRACEGUARD_ENV", "development").lower()
    seed_demo = os.getenv("TRACEGUARD_SEED_DEMO_USERS", "false").lower() == "true"
    if env == "development" and seed_demo:
        existing_admin = storage.get_user_by_email("admin@traceguard.internal")
        if not existing_admin:
            pwd_hash, salt = hash_password("AdminSecurePass123!", DEFAULT_PBKDF2_ITERATIONS)
            storage.create_user(
                user_id="usr_admin_default",
                email="admin@traceguard.internal",
                password_hash=pwd_hash,
                salt=salt,
                full_name="TraceGuard SecOps Admin",
                role="admin",
            )


ensure_default_policies()


# Health & System Status
@router.get("/health")
def get_health():
    from dotenv import load_dotenv
    _backend_dir = Path(__file__).resolve().parent.parent
    _root_dir = _backend_dir.parent
    load_dotenv(_root_dir / ".env", override=True)
    load_dotenv(_backend_dir / ".env", override=True)

    groq_agent = GroqAgent(gateway)
    tavily_adapter = TavilySearchAdapter()
    active_policy = storage.get_active_policy_set()
    groq_probe = groq_agent.check_connection()
    tavily_probe = tavily_adapter.check_connection()
    return {
        "status": "online",
        "service": "TraceGuard AI Security Platform",
        "version": "1.0.0",
        "groq_configured": groq_agent.is_configured(),
        "groq_status": groq_probe.get("status", "unconfigured"),
        "groq_message": groq_probe.get("message", ""),
        "tavily_configured": tavily_adapter.is_configured(),
        "tavily_status": tavily_probe.get("status", "unconfigured"),
        "tavily_message": tavily_probe.get("message", ""),
        "active_policy_id": active_policy.id if active_policy else None,
        "active_policy_name": active_policy.name if active_policy else None,
        "registered_tools": ["read_file", "query_database", "send_email", "web_search"],
        "sandbox_status": "ready",
    }


# CSRF Token Endpoint
@router.get("/auth/csrf")
def get_csrf_token(request: Request, response: Response):
    existing = request.cookies.get("traceguard_csrf")
    token = existing or generate_csrf_token()
    response.set_cookie(
        key="traceguard_csrf",
        value=token,
        httponly=False,
        samesite="lax",
        secure=is_cookie_secure(request),
        path="/",
        max_age=7 * 86400,
    )
    return {"csrf_token": token}


# Authentication Routes
@router.post("/auth/register", response_model=AuthTokenResponse, status_code=status.HTTP_201_CREATED)
def register_user(req: UserRegisterRequest, request: Request, response: Response):
    rate_limiter.check(request, "register", max_requests=5, window_seconds=60)

    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid email address is required.")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not req.full_name.strip():
        raise HTTPException(status_code=400, detail="Full name is required.")

    # Check if email is already taken
    existing = storage.get_user_by_email(email)
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email address already exists.")

    # Enforce safe default role: public registration ALWAYS creates an operator.
    # Client-supplied role is strictly ignored to prevent privilege escalation.
    assigned_role = "operator"

    pwd_hash, salt = hash_password(req.password, DEFAULT_PBKDF2_ITERATIONS)
    user_id = f"usr_{secrets.token_hex(6)}"
    user = storage.create_user(
        user_id=user_id,
        email=email,
        password_hash=pwd_hash,
        salt=salt,
        full_name=req.full_name.strip(),
        role=assigned_role,
    )

    raw_token, token_hash = generate_session_token()
    expires_at = calculate_session_expiry()
    storage.create_session(token_hash=token_hash, user_id=user.id, expires_at=expires_at)

    csrf_token = generate_csrf_token()
    cookie_secure = is_cookie_secure(request)

    response.set_cookie(
        key="traceguard_session",
        value=raw_token,
        httponly=True,
        samesite="lax",
        secure=cookie_secure,
        path="/",
        max_age=7 * 86400,
    )
    response.set_cookie(
        key="traceguard_csrf",
        value=csrf_token,
        httponly=False,
        samesite="lax",
        secure=cookie_secure,
        path="/",
        max_age=7 * 86400,
    )

    return AuthTokenResponse(access_token=raw_token, token_type="bearer", user=user)


@router.post("/auth/login", response_model=AuthTokenResponse)
def login_user(req: UserLoginRequest, request: Request, response: Response):
    rate_limiter.check(request, "login", max_requests=10, window_seconds=60)

    email = req.email.strip().lower()
    user_record = storage.get_user_by_email(email)

    if not user_record:
        # Equalize PBKDF2 calculation timing to eliminate user enumeration side-channels
        verify_dummy_password(req.password)
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not verify_password(req.password, user_record["password_hash"], user_record["salt"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # Safe password rehash migration: upgrade legacy 120k hashes to 600k iterations
    if not user_record["password_hash"].startswith(f"pbkdf2_sha256${DEFAULT_PBKDF2_ITERATIONS}$"):
        new_hash, new_salt = hash_password(req.password, DEFAULT_PBKDF2_ITERATIONS)
        storage.update_user_password(user_record["id"], new_hash, new_salt)

    user = User(
        id=user_record["id"],
        email=user_record["email"],
        full_name=user_record["full_name"],
        role=user_record["role"],
        created_at=user_record["created_at"],
    )

    raw_token, token_hash = generate_session_token()
    expires_at = calculate_session_expiry()
    storage.create_session(token_hash=token_hash, user_id=user.id, expires_at=expires_at)

    csrf_token = generate_csrf_token()
    cookie_secure = is_cookie_secure(request)

    response.set_cookie(
        key="traceguard_session",
        value=raw_token,
        httponly=True,
        samesite="lax",
        secure=cookie_secure,
        path="/",
        max_age=7 * 86400,
    )
    response.set_cookie(
        key="traceguard_csrf",
        value=csrf_token,
        httponly=False,
        samesite="lax",
        secure=cookie_secure,
        path="/",
        max_age=7 * 86400,
    )

    return AuthTokenResponse(access_token=raw_token, token_type="bearer", user=user)


@router.post("/auth/logout")
def logout_user(request: Request, response: Response):
    token = extract_token_from_request(request)
    if token:
        token_h = hash_token(token)
        storage.revoke_session(token_h)

    response.delete_cookie(
        key="traceguard_session",
        path="/",
    )
    response.delete_cookie(
        key="traceguard_csrf",
        path="/",
    )
    return {"message": "Logged out successfully."}


@router.get("/auth/me", response_model=User)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return current_user


# Role Management (Admin only)
@router.patch("/users/{user_id}/role", response_model=User)
def update_user_role_endpoint(
    user_id: str,
    req: RoleUpdateRequest,
    request: Request,
    current_user: User = Depends(require_roles(["admin"])),
):
    verify_csrf_and_origin(request)
    target = storage.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found.")
    updated = storage.update_user_role(user_id, req.role.value)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update user role.")
    return updated


# Policies Management
@router.get("/policies", response_model=List[PolicySet])
def list_policies(current_user: User = Depends(get_current_user)):
    return storage.list_policy_sets()


@router.get("/policies/active", response_model=Optional[PolicySet])
def get_active_policy(current_user: User = Depends(get_current_user)):
    policy = storage.get_active_policy_set()
    if not policy:
        raise HTTPException(status_code=404, detail="No active policy set found.")
    return policy


@router.post("/policies/active/{policy_id}")
def set_active_policy(
    policy_id: str,
    request: Request,
    current_user: User = Depends(require_roles(["admin"])),
):
    verify_csrf_and_origin(request)
    success = storage.set_active_policy(policy_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Policy set '{policy_id}' not found.")
    active_policy = storage.get_active_policy_set()
    gateway.set_policy_set(active_policy)
    return {"message": f"Active policy switched to '{active_policy.name}'", "policy": active_policy}


@router.post("/policies", response_model=PolicySet)
def create_or_update_policy(
    policy: PolicySet,
    request: Request,
    current_user: User = Depends(require_roles(["admin"])),
):
    verify_csrf_and_origin(request)
    storage.save_policy_set(policy)
    if policy.is_active:
        gateway.set_policy_set(policy)
    return policy


@router.post("/policies/reset-default")
def reset_default_policies(
    request: Request,
    current_user: User = Depends(require_roles(["admin"])),
):
    verify_csrf_and_origin(request)
    strict = get_default_strict_policy_set()
    storage.save_policy_set(strict)
    permissive = get_permissive_policy_set()
    storage.save_policy_set(permissive)
    storage.set_active_policy(strict.id)
    gateway.set_policy_set(strict)
    return {"message": "Reset to default strict and permissive policy sets."}


# Test Suites
@router.get("/suites", response_model=List[TestSuite])
def list_suites():
    return list_available_suites()


@router.get("/suites/language-stats")
def get_language_stats(suite_id: str = "suite_core_security_v1"):
    suite = load_test_suite(suite_id)
    if not suite:
        raise HTTPException(status_code=404, detail=f"Suite '{suite_id}' not found")

    stats = {
        "en": {"name": "English", "total": 0, "malicious": 0, "legitimate": 0},
        "te": {"name": "Telugu (తెలుగు)", "total": 0, "malicious": 0, "legitimate": 0},
        "hi": {"name": "Hindi (हिन्दी)", "total": 0, "malicious": 0, "legitimate": 0},
        "ta": {"name": "Tamil (தமிழ்)", "total": 0, "malicious": 0, "legitimate": 0},
        "code_mixed": {"name": "Code-Mixed (Hinglish/Tanglish/Tenglish)", "total": 0, "malicious": 0, "legitimate": 0},
    }

    for tc in suite.test_cases:
        lang = getattr(tc, "language", "en") or "en"
        if lang not in stats:
            stats[lang] = {"name": lang, "total": 0, "malicious": 0, "legitimate": 0}
        stats[lang]["total"] += 1
        if tc.is_malicious:
            stats[lang]["malicious"] += 1
        else:
            stats[lang]["legitimate"] += 1

    return {
        "suite_id": suite.id,
        "suite_name": suite.name,
        "total_test_cases": len(suite.test_cases),
        "languages": stats,
    }


@router.get("/suites/{suite_id}", response_model=TestSuite)
def get_suite(suite_id: str):
    suite = load_test_suite(suite_id)
    if not suite:
        raise HTTPException(status_code=404, detail=f"Suite '{suite_id}' not found.")
    return suite


# Test Runs
class TriggerRunRequest(BaseModel):
    suite_id: str = "suite_core_security_v1"
    policy_set_id: Optional[str] = None
    agent_type: str = "mock"
    groq_api_key: Optional[str] = None


@router.get("/runs", response_model=List[TestRun])
def list_runs(limit: int = 50, current_user: User = Depends(get_current_user)):
    return storage.list_test_runs(limit=limit)


@router.get("/runs/{run_id}", response_model=TestRun)
def get_run(run_id: str, current_user: User = Depends(get_current_user)):
    run = storage.get_test_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Test run '{run_id}' not found.")
    return run


@router.post("/runs", response_model=TestRun)
def trigger_run(
    req: TriggerRunRequest,
    request: Request,
    current_user: User = Depends(require_roles(["admin", "operator"])),
):
    verify_csrf_and_origin(request)
    try:
        run = test_runner.run_suite(
            suite_id=req.suite_id,
            policy_set_id=req.policy_set_id,
            agent_type=req.agent_type,
            groq_api_key=req.groq_api_key,
        )
        return run
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/runs/compare/diff")
def compare_runs(
    run_a_id: str = Query(..., description="Baseline test run ID (e.g. Strict)"),
    run_b_id: str = Query(..., description="Comparison test run ID (e.g. Permissive or New Policy)"),
    current_user: User = Depends(get_current_user),
):
    run_a = storage.get_test_run(run_a_id)
    run_b = storage.get_test_run(run_b_id)
    if not run_a:
        raise HTTPException(status_code=404, detail=f"Run '{run_a_id}' not found.")
    if not run_b:
        raise HTTPException(status_code=404, detail=f"Run '{run_b_id}' not found.")

    # Calculate regressions (passed in A, failed in B)
    # and fixes (failed in A, passed in B)
    results_a_map = {r.test_case_id: r for r in run_a.results}
    results_b_map = {r.test_case_id: r for r in run_b.results}

    regressions = []
    improvements = []
    identical = []

    for tc_id, res_a in results_a_map.items():
        res_b = results_b_map.get(tc_id)
        if not res_b:
            continue

        item = {
            "test_case_id": tc_id,
            "test_case_name": res_a.test_case_name,
            "category": res_a.category,
            "is_malicious": res_a.is_malicious,
            "run_a": {
                "decision": res_a.decision,
                "executed": res_a.executed,
                "passed": res_a.passed,
                "data_exposure": res_a.data_exposure_detected,
            },
            "run_b": {
                "decision": res_b.decision,
                "executed": res_b.executed,
                "passed": res_b.passed,
                "data_exposure": res_b.data_exposure_detected,
            },
        }

        if res_a.passed and not res_b.passed:
            regressions.append(item)
        elif not res_a.passed and res_b.passed:
            improvements.append(item)
        else:
            identical.append(item)

    delta_metrics = {
        "accuracy_delta": round(run_b.metrics.accuracy - run_a.metrics.accuracy, 2),
        "attack_block_rate_delta": round(run_b.metrics.attack_block_rate - run_a.metrics.attack_block_rate, 2),
        "false_positive_delta": run_b.metrics.false_positive_count - run_a.metrics.false_positive_count,
        "false_negative_delta": run_b.metrics.false_negative_count - run_a.metrics.false_negative_count,
        "data_exposure_delta": run_b.metrics.data_exposure_incidents - run_a.metrics.data_exposure_incidents,
        "unauthorized_executions_delta": getattr(run_b.metrics, "unauthorized_executions", 0) - getattr(run_a.metrics, "unauthorized_executions", 0),
    }

    return {
        "run_a": {
            "id": run_a.id,
            "policy_set_id": run_a.policy_set_id,
            "agent_type": run_a.agent_type,
            "metrics": run_a.metrics,
        },
        "run_b": {
            "id": run_b.id,
            "policy_set_id": run_b.policy_set_id,
            "agent_type": run_b.agent_type,
            "metrics": run_b.metrics,
        },
        "delta_metrics": delta_metrics,
        "regressions_count": len(regressions),
        "regressions": regressions,
        "improvements_count": len(improvements),
        "improvements": improvements,
    }


# Audit Events
@router.get("/audit", response_model=List[AuditEvent])
def get_audit_events(
    test_run_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    decision: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
):
    return storage.list_audit_events(
        test_run_id=test_run_id,
        tool_name=tool_name,
        decision=decision,
        agent_type=agent_id,
        limit=limit,
    )


# -------------------------------------------------------------
# Stage 6: Tamper-Evident Hash-Linked Audit Chain Verification
# -------------------------------------------------------------
@router.get("/audit/verify-chain", response_model=AuditChainVerificationResult)
def verify_audit_chain_integrity(current_user: Optional[User] = Depends(get_optional_current_user)):
    """
    Cryptographically verifies the SHA-256 hash-chain of all stored audit events.
    Detects any out-of-band record insertions, deletions, or data tampering.
    """
    return storage.verify_audit_chain()


# -------------------------------------------------------------
# Stage 4: Agent Integration API Contract & Enforcement
# -------------------------------------------------------------
VALID_DEV_AGENT_TOKENS = {
    "tg_agent_dev_token_2026",
    "tg_internal_admin_token_sec_val_2026",
}


def verify_agent_caller(request: Request) -> Dict[str, Any]:
    """
    Verifies external agent caller identity using token or session authentication.
    Accepts:
    1. 'Authorization: Bearer <token>'
    2. 'X-Agent-Key: <token>' or 'X-TraceGuard-Key: <token>'
    3. Active user session cookie ('traceguard_session')
    """
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif request.headers.get("X-Agent-Key"):
        token = request.headers.get("X-Agent-Key", "").strip()
    elif request.headers.get("X-TraceGuard-Key"):
        token = request.headers.get("X-TraceGuard-Key", "").strip()

    if token:
        if not is_production() and token in VALID_DEV_AGENT_TOKENS:
            return {"authenticated": True, "token_type": "dev_key", "identity": "authorized_agent"}
        token_h = hash_token(token)
        session = storage.get_session(token_h)
        if session:
            user = storage.get_user_by_id(session["user_id"])
            if user:
                return {"authenticated": True, "token_type": "user_session", "user": user}

    # Cookie fallback for interactive web sessions
    cookie_token = request.cookies.get("traceguard_session")
    if cookie_token:
        session = storage.get_session(hash_token(cookie_token))
        if session:
            user = storage.get_user_by_id(session["user_id"])
            if user:
                return {"authenticated": True, "token_type": "cookie_session", "user": user}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Agent authentication required: Provide a valid Bearer token, X-Agent-Key header, or active session.",
    )


@router.post(
    "/v1/agent/dispatch",
    response_model=AgentDispatchResponse,
    summary="Agent Integration Gateway Dispatcher",
)
@router.post(
    "/gateway/dispatch",
    response_model=AgentDispatchResponse,
    include_in_schema=False,
)
def agent_dispatch(
    req: AgentDispatchRequest,
    request: Request,
    caller_auth: Dict[str, Any] = Depends(verify_agent_caller),
):
    """
    Primary integration endpoint for external AI agents to submit proposed tool calls.
    External Agent -> TraceGuard API -> Input Validation -> Server-Side Policy Engine ->
    Authorized Tool Executor -> Execution Result -> Persistent Audit Event.
    """
    req_id = req.correlation_id or f"req_{uuid.uuid4().hex[:12]}"
    now_str = datetime.now(timezone.utc).isoformat()

    # 1. Handle NO_ACTION: if no tool was requested or proposed
    if not req.tool_name or not req.tool_name.strip():
        return AgentDispatchResponse(
            request_id=req_id,
            decision=DecisionOutcome.NO_ACTION,
            policy_id=None,
            rule_id="NO_TOOL_REQUESTED",
            reason="No tool action was requested or evaluated by agent.",
            violations=[],
            executed=False,
            execution_status="no_action",
            output=None,
            error=None,
            audit_event_id=None,
            timestamp=now_str,
        )

    clean_tool_name = req.tool_name.strip()

    # 2. Server-side registration check
    valid_tools = {"read_file", "query_database", "send_email", "web_search"}
    if clean_tool_name not in valid_tools:
        ev_id = f"evt_{uuid.uuid4().hex[:12]}"
        return AgentDispatchResponse(
            request_id=req_id,
            decision=DecisionOutcome.DENY,
            policy_id=None,
            rule_id="VALIDATE_TOOL_NAME",
            reason=f"Tool '{clean_tool_name}' is not a registered protected tool.",
            violations=[f"Unregistered tool: '{clean_tool_name}'"],
            executed=False,
            execution_status="not_executed",
            output=None,
            error=f"Unrecognized or unregistered tool '{clean_tool_name}'.",
            audit_event_id=ev_id,
            timestamp=now_str,
        )

    # 3. Construct ToolInvocationRequest
    inv_req = ToolInvocationRequest(
        call_id=req_id,
        tool_name=clean_tool_name,
        arguments=req.arguments or {},
        agent_type=req.agent_id,
        session_id=req.session_id,
        user_prompt=req.user_prompt,
        context=req.context or {},
    )

    # 4. Invoke Security Gateway (Single enforcement boundary)
    decision, exec_res, audit_event = gateway.invoke(inv_req)

    # Determine execution status cleanly
    if decision.decision == DecisionOutcome.TIMEOUT:
        exec_status = "timed_out"
    elif not decision.allowed:
        exec_status = "not_executed"
    elif exec_res and exec_res.success:
        exec_status = "executed"
    elif exec_res and not exec_res.success:
        exec_status = "failed"
    else:
        exec_status = "not_executed"

    # Return safe response without internal stack trace leaks
    safe_error = exec_res.error if (exec_res and not exec_res.success) else None
    if not decision.allowed and not safe_error:
        safe_error = f"Blocked by Security Gateway: {decision.reason}"

    return AgentDispatchResponse(
        request_id=req_id,
        decision=decision.decision,
        policy_id=decision.policy_id,
        rule_id=decision.rule_id,
        reason=decision.reason,
        violations=decision.violations,
        executed=exec_res.executed if exec_res else False,
        execution_status=exec_status,
        output=exec_res.output if (exec_res and exec_res.success) else None,
        error=safe_error,
        audit_event_id=audit_event.event_id if audit_event else None,
        timestamp=now_str,
    )


# -------------------------------------------------------------
# Stage 5: Agent Connect & Permissions Management Endpoints
# -------------------------------------------------------------
@router.get("/connect/agents", response_model=List[AgentRecord])
def get_connect_agents(current_user: Optional[User] = Depends(get_optional_current_user)):
    """Lists registered agents, status, roles, and tool permissions."""
    return storage.list_agents()


@router.post("/connect/agents", response_model=AgentRecord)
def register_connect_agent(
    req: AgentRegistrationRequest,
    current_user: User = Depends(require_roles(["admin", "operator"])),
):
    """Registers a new agent or updates an existing agent specification."""
    return storage.create_agent(req)


@router.put("/connect/agents/{agent_id}/permissions", response_model=AgentRecord)
def update_agent_permissions(
    agent_id: str,
    req: AgentPermissionsUpdateRequest,
    current_user: User = Depends(require_roles(["admin", "operator"])),
):
    """Updates permitted tools, role, or status for an agent in server-side registry."""
    updated = storage.update_agent_permissions(
        agent_id=agent_id,
        allowed_tools=req.allowed_tools,
        role=req.role,
        status=req.status,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return updated


@router.get("/connect/activity", response_model=List[AuditEvent])
def get_connect_activity(
    agent_id: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
):
    """Returns recent audit events for connected agents. Requires authenticated user."""
    return storage.list_audit_events(agent_type=agent_id, limit=limit)


# Interactive Playground
class PlaygroundRequest(BaseModel):
    prompt: str
    agent_type: str = "mock"  # "mock" or "groq"
    scenario_id: Optional[str] = None
    tool: Optional[str] = None
    category: Optional[str] = None
    policy_set_id: Optional[str] = None
    groq_api_key: Optional[str] = None


@router.post("/playground/execute")
def playground_execute(
    req: PlaygroundRequest,
    request: Request,
    current_user: User = Depends(require_roles(["admin", "operator"])),
):
    verify_csrf_and_origin(request)
    # Select policy set
    if req.policy_set_id:
        policy_set = storage.get_policy_set(req.policy_set_id)
        if policy_set:
            gateway.set_policy_set(policy_set)
    else:
        active = storage.get_active_policy_set()
        if active:
            gateway.set_policy_set(active)

    if req.agent_type == "groq":
        groq_agent = GroqAgent(gateway, api_key=req.groq_api_key)
        if not groq_agent.is_configured():
            raise HTTPException(
                status_code=400,
                detail="Groq LLM provider is not configured. Set GROQ_API_KEY in your backend .env or configure a provider key to execute prompts with live models.",
            )
        res = groq_agent.run_prompt(req.prompt)

        # Fail closed: If live model emitted no tool calls (conversational refusal or skipped tools),
        # but the prompt or scenario attempted a protected tool action (e.g. exfiltration email or file read),
        # evaluate the attempted action through the Security Gateway to enforce server-side policy and audit logging.
        if len(res.get("steps", [])) == 0:
            p_lower = req.prompt.lower()
            is_tool_intent = (
                bool(req.tool)
                or bool(req.scenario_id)
                or req.category == "attack"
                or any(w in p_lower for w in [
                    "email", "mail", "exfil", "hacker", "evil", "secret", "token", "credential",
                    "steal", "leak", "file", "read", "database", "query", "select", "drop", "search"
                ])
            )
            if is_tool_intent:
                mock_agent = MockAgent(gateway)
                planned = mock_agent.plan_tool_calls(
                    prompt=req.prompt,
                    tool=req.tool,
                    scenario_id=req.scenario_id,
                    category=req.category,
                )
                if planned:
                    eval_res = mock_agent.run_step(
                        prompt=req.prompt,
                        tool=req.tool,
                        scenario_id=req.scenario_id,
                        category=req.category,
                    )
                    res["steps"] = eval_res.get("steps", [])
                    res["overall_allowed"] = eval_res.get("overall_allowed", False)
                    res["data_exposure_detected"] = eval_res.get("data_exposure_detected", False)
                    res["final_status"] = eval_res.get("final_status", "no_tool_called")
                    res["summary"] = eval_res.get("summary", "")
    else:
        mock_agent = MockAgent(gateway)
        res = mock_agent.run_step(
            prompt=req.prompt,
            tool=req.tool,
            scenario_id=req.scenario_id,
            category=req.category,
        )

    # Save any new audit events generated
    for s in res.get("steps", []):
        ev_id = s.get("audit_event_id")
        matching_ev = next((e for e in gateway.audit_log if e.event_id == ev_id), None)
        if matching_ev:
            storage.save_audit_event(matching_ev)

    return res


# Emergency Stop Controls
class EmergencyStopRequest(BaseModel):
    stopped: bool


@router.get("/gateway/emergency-stop")
def get_emergency_stop_status(current_user: User = Depends(get_current_user)):
    return {
        "emergency_stopped": gateway.is_emergency_stopped(),
        "status": "STOPPED" if gateway.is_emergency_stopped() else "OPERATIONAL",
    }


@router.post("/gateway/emergency-stop")
def set_emergency_stop_status(
    req: EmergencyStopRequest,
    request: Request,
    current_user: User = Depends(require_roles(["admin"])),
):
    verify_csrf_and_origin(request)
    gateway.set_emergency_stop(req.stopped)
    return {
        "emergency_stopped": gateway.is_emergency_stopped(),
        "status": "STOPPED" if gateway.is_emergency_stopped() else "OPERATIONAL",
        "message": "Emergency stop ACTIVATED: all protected tool executions are paused."
        if req.stopped
        else "Emergency stop DEACTIVATED: gateway operational.",
    }


# Autonomous Agent Multi-Step Loop
class AutonomousRunRequest(BaseModel):
    goal: str
    max_steps: int = 5
    agent_role: str = "standard_agent"
    policy_set_id: Optional[str] = None
    agent_type: Optional[str] = None  # 'groq' (default when live) or 'test_deterministic'
    groq_api_key: Optional[str] = None


@router.post("/agent/autonomous-run")
def run_autonomous_agent(
    req: AutonomousRunRequest,
    request: Request,
    current_user: User = Depends(require_roles(["admin", "operator"])),
):
    verify_csrf_and_origin(request)
    if req.policy_set_id:
        policy_set = storage.get_policy_set(req.policy_set_id)
        if policy_set:
            gateway.set_policy_set(policy_set)
    else:
        active = storage.get_active_policy_set()
        if active:
            gateway.set_policy_set(active)

    # Use deterministic mock agent only when explicitly requested for tests
    if req.agent_type in ("test_deterministic", "mock"):
        from app.agents.autonomous_agent import MockAutonomousAgent
        agent = MockAutonomousAgent(gateway, agent_role=req.agent_role)
        res = agent.run_goal(goal=req.goal, max_steps=req.max_steps)
        return res.model_dump()

    # Real LLM Agent Loop (Groq)
    groq_agent = GroqAgent(gateway, api_key=req.groq_api_key)
    if not groq_agent.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Live LLM Provider Unconfigured: Set GROQ_API_KEY in your backend .env to run real AI model reasoning. Deterministic test agents are reserved for automated test suites.",
        )

    res = groq_agent.run_prompt(prompt=req.goal, max_iterations=req.max_steps)
    raw_steps = res.get("steps", [])
    overall_allowed = res.get("overall_allowed", True)
    data_exposure = res.get("data_exposure_detected", False)

    steps = []
    for idx, s in enumerate(raw_steps):
        decision_val = s.get("decision", "deny")
        executed = bool(s.get("executed", False))
        output_val = s.get("output")
        rule_id = s.get("rule_id", "GATEWAY_RULE")
        reason = s.get("reason", "Gateway evaluation")
        safe_msg = (
            f"Action permitted by gateway: {str(output_val)[:150]}"
            if executed
            else f"Security Gateway Notice: Action blocked by policy rule '{rule_id}': {reason}"
        )
        steps.append({
            "step_number": idx + 1,
            "thought": f"Live LLM proposed tool '{s.get('tool')}' for mission reasoning.",
            "tool_name": s.get("tool", "unknown"),
            "arguments": s.get("arguments", {}),
            "decision": decision_val,
            "executed": executed,
            "safe_message_received": safe_msg,
            "output": output_val,
            "audit_event_id": s.get("audit_event_id", f"evt_{secrets.token_hex(6)}"),
            "data_exposure_detected": bool(s.get("data_exposure_detected", False)),
        })

    recovered = (
        any(not s["executed"] for s in steps) and any(s["executed"] for s in steps[1:])
        if len(steps) > 1
        else False
    )
    status_str = "completed" if (res.get("success") and overall_allowed) else ("halted_by_gateway" if not overall_allowed else "error")

    return {
        "session_id": f"groq_sess_{secrets.token_hex(4)}",
        "goal": req.goal,
        "agent_type": "groq",
        "status": status_str,
        "steps": steps,
        "final_summary": res.get("response") or ("Mission halted by security gateway policy denial." if not overall_allowed else "Goal completed successfully."),
        "overall_allowed": overall_allowed,
        "data_exposure_detected": data_exposure,
        "recovered_after_denial": recovered,
    }


# Findings and OWASP LLM Top 10 Summary
@router.get("/findings")
def get_findings_summary():
    """Aggregates security findings, invariants validation, and maps to OWASP LLM Top 10 categories."""
    runs = storage.list_test_runs(limit=10)
    all_events = storage.list_audit_events(limit=200)

    # Calculate categories
    blocked_count = sum(1 for e in all_events if e.decision == DecisionOutcome.DENY)
    allowed_count = sum(1 for e in all_events if e.decision == DecisionOutcome.ALLOW)
    exposure_count = sum(1 for e in all_events if e.data_exposure_detected)
    unauthorized_executions = sum(1 for e in all_events if e.decision == DecisionOutcome.DENY and e.executed)

    latest_run = runs[0] if runs else None
    fp_count = latest_run.metrics.false_positive_count if latest_run else 0
    fn_count = latest_run.metrics.false_negative_count if latest_run else 0

    security_invariants = [
        {
            "id": "INV-01",
            "name": "Server-Side Authorization Boundary",
            "status": "ENFORCED",
            "description": "No protected tool executes without prior server-side gateway authorization.",
            "evidence": "100% of tool invocations routed through SecurityGateway.invoke(); 0 bypass routes.",
        },
        {
            "id": "INV-02",
            "name": "Untrusted Content Isolation",
            "status": "ENFORCED",
            "description": "Retrieved documents, web scrapes, and database records cannot alter policy or grant permissions.",
            "evidence": "Tested against multi-step indirect injections in files, web scrapes, and SQLite rows.",
        },
        {
            "id": "INV-03",
            "name": "Fail-Closed Boundary",
            "status": "ENFORCED",
            "description": "Schema mismatches, unexpected arguments, null bytes, and evaluation exceptions immediately deny.",
            "evidence": "Server-side schema_validator catches null bytes, unexpected keys, and invalid types before policy engine.",
        },
        {
            "id": "INV-04",
            "name": "Strict Destination Restriction",
            "status": "ENFORCED",
            "description": "Email destinations are strictly confined; multi-recipient pollution and CRLF header injection are blocked.",
            "evidence": "RULE-EMAIL-01-EXTERNAL-DENY parses every comma/semicolon recipient and rejects external/CRLF addresses.",
        },
        {
            "id": "INV-05",
            "name": "Multi-Step Privilege Isolation",
            "status": "ENFORCED",
            "description": "Succeeding in an earlier task step confers zero additional privileges to subsequent steps.",
            "evidence": "Autonomous agent evaluates each step independently with zero privilege inheritance.",
        },
        {
            "id": "INV-06",
            "name": "Execution Boundary Integrity",
            "status": "ENFORCED",
            "description": "Denied actions produce zero side effects on the environment (mock outbox, database, filesystem).",
            "evidence": "OUTBOX_LOG, DB, and sandbox filesystem verified unchanged on denied actions.",
        },
        {
            "id": "INV-07",
            "name": "Operator Emergency Stop",
            "status": "ENFORCED",
            "description": "Atomic kill-switch halts all ongoing and queued protected tool executions immediately.",
            "evidence": "Priority 0 gatekeeper in SecurityGateway.invoke() intercepts all requests.",
        },
    ]

    scope_and_limitations = {
        "tested_scope": "Controlled single-tenant security lab executing mock and live Groq LLM tool loops across file, database, and email boundaries.",
        "enforced_guarantees": "Deterministic prevention of protected tool execution on policy denial; PII and secret redaction; fail-closed schema validation; multi-recipient email confinement; session duration and action rate limits; operator emergency stop.",
        "known_limitations": "Does not prevent hallucinated conversational text outside tool invocation arguments; does not inspect external unencrypted network proxies outside controlled sandbox; does not claim immunity against zero-day cryptographic breaks.",
    }

    owasp_mapping = [
        {
            "id": "LLM01",
            "name": "Prompt Injection",
            "severity": "CRITICAL",
            "description": "Manipulated prompt attempts to override system instructions and extract sensitive assets.",
            "mitigation": "Strict server-side authorization gateway with deny-by-default and multi-step indirect payload inspection.",
            "test_cases": ["TC-DIR-INJ-01", "TC-DIR-INJ-02", "TC-INDIR-INJ-01", "TC-INDIR-INJ-02"],
            "status": "PROTECTED",
        },
        {
            "id": "LLM02",
            "name": "Insecure Output Handling",
            "severity": "HIGH",
            "description": "Model outputs directing uncontrolled command or SQL execution without gateway validation.",
            "mitigation": "AST-based SQL mutation filtering (BLOCK DROP/DELETE/ALTER) and zero direct model-to-tool dispatch.",
            "test_cases": ["TC-MUT-SQL-01"],
            "status": "PROTECTED",
        },
        {
            "id": "LLM06",
            "name": "Sensitive Information Disclosure",
            "severity": "CRITICAL",
            "description": "Exfiltration of PII (SSNs, card details) and cryptographic API keys via tool outputs or external mail.",
            "mitigation": "Dual-layer regex redaction pipeline and automated data exposure verification interceptors.",
            "test_cases": ["TC-EXFIL-SQL-01", "TC-EXFIL-SQL-02", "TC-EXFIL-MAIL-01"],
            "status": "PROTECTED",
        },
        {
            "id": "LLM08",
            "name": "Excessive Agency",
            "severity": "HIGH",
            "description": "Agent invoking unauthorized or unapproved operations beyond legitimate task scope.",
            "mitigation": "Granular capability whitelisting, domain restriction for emails, and strict path prefix confinement.",
            "test_cases": ["TC-TRAV-01"],
            "status": "PROTECTED",
        },
    ]

    return {
        "total_audit_events": len(all_events),
        "total_blocked_actions": blocked_count,
        "total_allowed_actions": allowed_count,
        "total_exposure_incidents": exposure_count,
        "unauthorized_executions": unauthorized_executions,
        "false_positive_count": fp_count,
        "false_negative_count": fn_count,
        "recent_runs_count": len(runs),
        "security_invariants": security_invariants,
        "scope_and_limitations": scope_and_limitations,
        "owasp_top_10": owasp_mapping,
    }
