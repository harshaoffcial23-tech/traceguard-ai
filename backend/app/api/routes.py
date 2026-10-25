"""
FastAPI REST routes for TraceGuard AI security platform.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.models.schemas import AuditEvent, DecisionOutcome, PolicySet, TestRun, TestSuite, ToolInvocationRequest
from app.gateway.gateway import SecurityGateway
from app.gateway.policy_engine import get_default_strict_policy_set, get_permissive_policy_set
from app.agents.mock_agent import MockAgent
from app.agents.groq_adapter import GroqAgent
from app.agents.tavily_adapter import TavilySearchAdapter
from app.runner.test_runner import TestRunner, list_available_suites, load_test_suite
from app.db.storage import Storage


router = APIRouter()
storage = Storage()
gateway = SecurityGateway()
test_runner = TestRunner(storage=storage, gateway=gateway)


def ensure_default_policies():
    """Seed initial policy sets if database is empty."""
    active = storage.get_active_policy_set()
    if not active:
        strict = get_default_strict_policy_set()
        storage.save_policy_set(strict)
        permissive = get_permissive_policy_set()
        storage.save_policy_set(permissive)


ensure_default_policies()


# Health & System Status
@router.get("/health")
def get_health():
    groq_agent = GroqAgent(gateway)
    tavily_adapter = TavilySearchAdapter()
    active_policy = storage.get_active_policy_set()
    return {
        "status": "online",
        "service": "TraceGuard AI Security Platform",
        "version": "1.0.0",
        "groq_configured": groq_agent.is_configured(),
        "tavily_configured": tavily_adapter.is_configured(),
        "active_policy_id": active_policy.id if active_policy else None,
        "active_policy_name": active_policy.name if active_policy else None,
        "registered_tools": ["read_file", "query_database", "send_email"],
        "sandbox_status": "ready",
    }


# Policies Management
@router.get("/policies", response_model=List[PolicySet])
def list_policies():
    return storage.list_policy_sets()


@router.get("/policies/active", response_model=Optional[PolicySet])
def get_active_policy():
    policy = storage.get_active_policy_set()
    if not policy:
        raise HTTPException(status_code=404, detail="No active policy set found.")
    return policy


@router.post("/policies/active/{policy_id}")
def set_active_policy(policy_id: str):
    success = storage.set_active_policy(policy_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Policy set '{policy_id}' not found.")
    active_policy = storage.get_active_policy_set()
    gateway.set_policy_set(active_policy)
    return {"message": f"Active policy switched to '{active_policy.name}'", "policy": active_policy}


@router.post("/policies", response_model=PolicySet)
def create_or_update_policy(policy: PolicySet):
    storage.save_policy_set(policy)
    if policy.is_active:
        gateway.set_policy_set(policy)
    return policy


@router.post("/policies/reset-default")
def reset_default_policies():
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
def list_runs(limit: int = 50):
    return storage.list_test_runs(limit=limit)


@router.get("/runs/{run_id}", response_model=TestRun)
def get_run(run_id: str):
    run = storage.get_test_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Test run '{run_id}' not found.")
    return run


@router.post("/runs", response_model=TestRun)
def trigger_run(req: TriggerRunRequest):
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
    limit: int = 100,
):
    return storage.list_audit_events(
        test_run_id=test_run_id, tool_name=tool_name, decision=decision, limit=limit
    )


# Interactive Playground
class PlaygroundRequest(BaseModel):
    prompt: str
    agent_type: str = "mock"  # "mock" or "groq"
    policy_set_id: Optional[str] = None
    groq_api_key: Optional[str] = None


@router.post("/playground/execute")
def playground_execute(req: PlaygroundRequest):
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
        res = groq_agent.run_prompt(req.prompt)
    else:
        mock_agent = MockAgent(gateway)
        res = mock_agent.run_step(req.prompt)

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
def get_emergency_stop_status():
    return {
        "emergency_stopped": gateway.is_emergency_stopped(),
        "status": "STOPPED" if gateway.is_emergency_stopped() else "OPERATIONAL",
    }


@router.post("/gateway/emergency-stop")
def set_emergency_stop_status(req: EmergencyStopRequest):
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
    policy_set_id: Optional[str] = None


@router.post("/agent/autonomous-run")
def run_autonomous_agent(req: AutonomousRunRequest):
    if req.policy_set_id:
        policy_set = storage.get_policy_set(req.policy_set_id)
        if policy_set:
            gateway.set_policy_set(policy_set)
    else:
        active = storage.get_active_policy_set()
        if active:
            gateway.set_policy_set(active)

    from app.agents.autonomous_agent import MockAutonomousAgent
    agent = MockAutonomousAgent(gateway)
    res = agent.run_goal(goal=req.goal, max_steps=req.max_steps)

    # Persist all audit events generated by the autonomous loop
    for step in res.steps:
        matching_ev = next((e for e in gateway.audit_log if e.event_id == step.audit_event_id), None)
        if matching_ev:
            storage.save_audit_event(matching_ev)

    return res.model_dump()


# Findings and OWASP LLM Top 10 Summary
@router.get("/findings")
def get_findings_summary():
    """Aggregates security findings and maps to OWASP LLM Top 10 categories."""
    runs = storage.list_test_runs(limit=10)
    all_events = storage.list_audit_events(limit=200)

    # Calculate categories
    blocked_count = sum(1 for e in all_events if e.decision == DecisionOutcome.DENY)
    allowed_count = sum(1 for e in all_events if e.decision == DecisionOutcome.ALLOW)
    exposure_count = sum(1 for e in all_events if e.data_exposure_detected)

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
        "recent_runs_count": len(runs),
        "owasp_top_10": owasp_mapping,
    }
