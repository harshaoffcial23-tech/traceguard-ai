import {
  AuditEvent,
  FindingsSummary,
  PolicySet,
  RegressionComparison,
  SystemHealth,
  TestRun,
  TestSuite,
} from '../types';

const API_BASE = '/api';

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Failed to fetch health: ${res.statusText}`);
  return res.json();
}

export async function fetchPolicies(): Promise<PolicySet[]> {
  const res = await fetch(`${API_BASE}/policies`);
  if (!res.ok) throw new Error(`Failed to fetch policies: ${res.statusText}`);
  return res.json();
}

export async function setActivePolicy(policyId: string): Promise<{ message: string; policy: PolicySet }> {
  const res = await fetch(`${API_BASE}/policies/active/${policyId}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to activate policy: ${res.statusText}`);
  return res.json();
}

export async function resetDefaultPolicies(): Promise<{ message: string }> {
  const res = await fetch(`${API_BASE}/policies/reset-default`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to reset policies: ${res.statusText}`);
  return res.json();
}

export async function savePolicy(policy: PolicySet): Promise<PolicySet> {
  const res = await fetch(`${API_BASE}/policies`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy),
  });
  if (!res.ok) throw new Error(`Failed to save policy: ${res.statusText}`);
  return res.json();
}

export async function fetchSuites(): Promise<TestSuite[]> {
  const res = await fetch(`${API_BASE}/suites`);
  if (!res.ok) throw new Error(`Failed to fetch test suites: ${res.statusText}`);
  return res.json();
}

export async function fetchRuns(): Promise<TestRun[]> {
  const res = await fetch(`${API_BASE}/runs`);
  if (!res.ok) throw new Error(`Failed to fetch test runs: ${res.statusText}`);
  return res.json();
}

export async function fetchRun(runId: string): Promise<TestRun> {
  const res = await fetch(`${API_BASE}/runs/${runId}`);
  if (!res.ok) throw new Error(`Failed to fetch run details: ${res.statusText}`);
  return res.json();
}

export async function triggerRun(params: {
  suite_id: string;
  policy_set_id?: string;
  agent_type: string;
  groq_api_key?: string;
}): Promise<TestRun> {
  const res = await fetch(`${API_BASE}/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to trigger run');
  }
  return res.json();
}

export async function compareRuns(runAId: string, runBId: string): Promise<RegressionComparison> {
  const res = await fetch(`${API_BASE}/runs/compare/diff?run_a_id=${runAId}&run_b_id=${runBId}`);
  if (!res.ok) throw new Error(`Failed to compare runs: ${res.statusText}`);
  return res.json();
}

export async function fetchAuditEvents(filters?: {
  test_run_id?: string;
  tool_name?: string;
  decision?: string;
  limit?: number;
}): Promise<AuditEvent[]> {
  const params = new URLSearchParams();
  if (filters?.test_run_id) params.set('test_run_id', filters.test_run_id);
  if (filters?.tool_name) params.set('tool_name', filters.tool_name);
  if (filters?.decision) params.set('decision', filters.decision);
  if (filters?.limit) params.set('limit', String(filters.limit));

  const res = await fetch(`${API_BASE}/audit?${params.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch audit events: ${res.statusText}`);
  return res.json();
}

export async function executePlayground(params: {
  prompt: string;
  agent_type: string;
  policy_set_id?: string;
  groq_api_key?: string;
}): Promise<any> {
  const res = await fetch(`${API_BASE}/playground/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Playground execution failed');
  }
  return res.json();
}

export async function fetchFindings(): Promise<FindingsSummary> {
  const res = await fetch(`${API_BASE}/findings`);
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
  return res.json();
}
