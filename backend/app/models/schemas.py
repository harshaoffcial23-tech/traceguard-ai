"""
Pydantic schemas for TraceGuard AI security gateway, tools, policies, audit events, and test runners.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class AgentType(str, Enum):
    MOCK = "mock"
    GROQ = "groq"
    HYBRID = "hybrid"


class ToolCall(BaseModel):
    call_id: Optional[str] = None
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolInvocationRequest(BaseModel):
    call_id: Optional[str] = None
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    agent_type: str = "mock"
    session_id: Optional[str] = None
    user_prompt: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class GatewayDecision(BaseModel):
    allowed: bool
    decision: DecisionOutcome
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    rule_id: Optional[str] = None
    reason: str
    violations: List[str] = Field(default_factory=list)
    matched_rules: List[str] = Field(default_factory=list)


class ToolExecutionResult(BaseModel):
    executed: bool
    success: bool
    output: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DataExposureInspection(BaseModel):
    exposure_detected: bool
    exposed_categories: List[str] = Field(default_factory=list)
    details: List[str] = Field(default_factory=list)
    redacted_preview: Optional[str] = None


class AuditEvent(BaseModel):
    event_id: str
    timestamp: str
    test_run_id: Optional[str] = None
    test_case_id: Optional[str] = None
    agent_type: str
    tool_name: str
    raw_arguments_hash: str
    redacted_arguments: Dict[str, Any] = Field(default_factory=dict)
    decision: DecisionOutcome
    policy_id: Optional[str] = None
    rule_id: Optional[str] = None
    reason: str
    violations: List[str] = Field(default_factory=list)
    attempted: bool = True
    executed: bool = False
    data_exposure_detected: bool = False
    exposure_details: List[str] = Field(default_factory=list)
    execution_output_redacted: Optional[Any] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    priority: int = 100
    tool: str  # e.g., "read_file", "query_database", "send_email", or "*"
    action: DecisionOutcome  # "allow" or "deny"
    condition_type: str  # e.g., "path_prefix_allow", "path_pattern_deny", "sql_table_whitelist", "email_domain_whitelist", etc.
    parameters: Dict[str, Any] = Field(default_factory=dict)


class PolicySet(BaseModel):
    id: str
    name: str
    description: str
    is_active: bool = True
    default_action: DecisionOutcome = DecisionOutcome.DENY
    rules: List[PolicyRule] = Field(default_factory=list)


# Test Runner Schemas
class TestCase(BaseModel):
    id: str
    suite_id: str
    name: str
    description: str
    category: str  # "direct_injection", "indirect_injection", "data_exfiltration", "privilege_escalation", "legitimate"
    is_malicious: bool
    user_prompt: str
    expected_tool: Optional[str] = None
    expected_decision: DecisionOutcome
    expected_execution: bool
    target_resource: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TestSuite(BaseModel):
    id: str
    name: str
    description: str
    version: str = "1.0.0"
    test_cases: List[TestCase] = Field(default_factory=list)


class TestCaseResult(BaseModel):
    test_case_id: str
    test_case_name: str
    category: str
    is_malicious: bool
    prompt: str
    tool_attempted: Optional[str] = None
    decision: DecisionOutcome
    executed: bool
    data_exposure_detected: bool
    passed: bool
    failure_reason: Optional[str] = None
    audit_event_id: Optional[str] = None
    duration_ms: float = 0.0


class TestRunMetrics(BaseModel):
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    accuracy: float = 0.0
    attack_block_rate: float = 0.0  # Percentage of malicious attacks denied
    legitimate_allow_rate: float = 0.0  # Percentage of legitimate requests allowed
    false_positive_count: int = 0  # Legitimate requests wrongly blocked
    false_negative_count: int = 0  # Malicious attacks wrongly allowed
    data_exposure_incidents: int = 0  # Cases where protected data leaked


class TestRun(BaseModel):
    id: str
    suite_id: str
    suite_name: str
    policy_set_id: str
    agent_type: str
    status: str  # "completed", "running", "failed"
    started_at: str
    completed_at: Optional[str] = None
    metrics: TestRunMetrics = Field(default_factory=TestRunMetrics)
    results: List[TestCaseResult] = Field(default_factory=list)
