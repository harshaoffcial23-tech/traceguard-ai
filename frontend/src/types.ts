export type DecisionOutcome = 'allow' | 'deny' | 'escalate';

export interface SystemHealth {
  status: string;
  service: string;
  version: string;
  groq_configured: boolean;
  groq_status?: string;
  groq_message?: string;
  tavily_configured: boolean;
  tavily_status?: string;
  tavily_message?: string;
  active_policy_id: string | null;
  active_policy_name: string | null;
  registered_tools: string[];
  sandbox_status: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  tool: string;
  action: DecisionOutcome;
  condition_type: string;
  parameters: Record<string, any>;
}

export interface PolicySet {
  id: string;
  name: string;
  description: string;
  is_active: boolean;
  default_action: DecisionOutcome;
  rules: PolicyRule[];
}

export interface TestCase {
  id: string;
  suite_id: string;
  name: string;
  description: string;
  category: string;
  is_malicious: boolean;
  user_prompt: string;
  expected_tool?: string;
  expected_decision: DecisionOutcome;
  expected_execution: boolean;
  target_resource?: string;
  metadata?: Record<string, any>;
}

export interface TestSuite {
  id: string;
  name: string;
  description: string;
  version: string;
  test_cases: TestCase[];
}

export interface TestCaseResult {
  test_case_id: string;
  test_case_name: string;
  category: string;
  is_malicious: boolean;
  prompt: string;
  tool_attempted?: string;
  decision: DecisionOutcome;
  executed: boolean;
  data_exposure_detected: boolean;
  passed: boolean;
  failure_reason?: string;
  audit_event_id?: string;
  duration_ms: number;
}

export interface TestRunMetrics {
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  accuracy: number;
  malicious_total?: number;
  legitimate_total?: number;
  attack_block_rate: number;
  legitimate_allow_rate: number;
  unauthorized_executions?: number;
  unauthorized_execution_rate?: number;
  false_positive_count: number;
  false_positive_rate?: number;
  false_negative_count: number;
  false_negative_rate?: number;
  data_exposure_incidents: number;
  verified_exposure_rate?: number;
}

export interface TestRun {
  id: string;
  suite_id: string;
  suite_name: string;
  policy_set_id: string;
  agent_type: string;
  status: string;
  started_at: string;
  completed_at?: string;
  metrics: TestRunMetrics;
  results: TestCaseResult[];
}

export interface AuditEvent {
  event_id: string;
  timestamp: string;
  test_run_id?: string;
  test_case_id?: string;
  agent_type: string;
  tool_name: string;
  raw_arguments_hash: string;
  redacted_arguments: Record<string, any>;
  decision: DecisionOutcome;
  policy_id?: string;
  rule_id?: string;
  reason: string;
  violations: string[];
  attempted: boolean;
  executed: boolean;
  data_exposure_detected: boolean;
  exposure_details: string[];
  execution_output_redacted?: any;
  context: Record<string, any>;
}

export interface OwaspItem {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  mitigation: string;
  test_cases: string[];
  status: string;
}

export interface SecurityInvariant {
  id: string;
  name: string;
  status: 'ENFORCED' | 'PARTIAL' | 'UNSUPPORTED';
  description: string;
  evidence: string;
}

export interface ScopeAndLimitations {
  tested_scope: string;
  enforced_guarantees: string;
  known_limitations: string;
}

export interface FindingsSummary {
  total_audit_events: number;
  total_blocked_actions: number;
  total_allowed_actions: number;
  total_exposure_incidents: number;
  unauthorized_executions?: number;
  false_positive_count?: number;
  false_negative_count?: number;
  recent_runs_count: number;
  security_invariants?: SecurityInvariant[];
  scope_and_limitations?: ScopeAndLimitations;
  owasp_top_10: OwaspItem[];
}

export interface RegressionComparison {
  run_a: {
    id: string;
    policy_set_id: string;
    agent_type: string;
    metrics: TestRunMetrics;
  };
  run_b: {
    id: string;
    policy_set_id: string;
    agent_type: string;
    metrics: TestRunMetrics;
  };
  delta_metrics: {
    accuracy_delta: number;
    attack_block_rate_delta: number;
    false_positive_delta: number;
    false_negative_delta: number;
    data_exposure_delta: number;
  };
  regressions_count: number;
  regressions: any[];
  improvements_count: number;
  improvements: any[];
}

export interface AutonomousStep {
  step_number: number;
  thought: string;
  tool_name: string;
  arguments: Record<string, any>;
  decision: string;
  executed: boolean;
  safe_message_received: string;
  output?: any;
  audit_event_id: string;
  data_exposure_detected: boolean;
}

export interface AutonomousRunResult {
  session_id: string;
  goal: string;
  agent_type: string;
  status: string;
  steps: AutonomousStep[];
  final_summary: string;
  overall_allowed: boolean;
  data_exposure_detected: boolean;
  recovered_after_denial: boolean;
}

export interface EmergencyStopStatus {
  emergency_stopped: boolean;
  status: 'STOPPED' | 'OPERATIONAL';
  message?: string;
}

export interface LanguageStatItem {
  name: string;
  total: number;
  malicious: number;
  legitimate: number;
}

export interface LanguageStatsResponse {
  suite_id: string;
  suite_name: string;
  total_test_cases: number;
  languages: Record<string, LanguageStatItem>;
}

export type UserRole = 'admin' | 'operator' | 'developer';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  created_at: string;
}

export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials {
  email: string;
  password: string;
  full_name: string;
  role?: UserRole;
}
