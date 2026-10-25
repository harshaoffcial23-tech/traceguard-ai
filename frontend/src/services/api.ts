import {
  AuditEvent,
  AuthTokenResponse,
  FindingsSummary,
  LoginCredentials,
  PolicySet,
  RegisterCredentials,
  RegressionComparison,
  SystemHealth,
  TestRun,
  TestSuite,
  User,
} from '../types';

const API_BASE = '/api';

export function getCsrfTokenFromCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(/(?:^|;\s*)traceguard_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function authFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers || {});
  const method = (init.method || 'GET').toUpperCase();

  // Attach CSRF protection token for state-modifying requests
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    let csrfToken = getCsrfTokenFromCookie();
    if (!csrfToken) {
      try {
        const csrfRes = await fetch(`${API_BASE}/auth/csrf`, { credentials: 'include' });
        if (csrfRes.ok) {
          const data = await csrfRes.json();
          csrfToken = data.csrf_token;
        }
      } catch {
        // Fall back to cookie
      }
    }
    if (csrfToken && !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', csrfToken);
    }
  }

  return fetch(input, {
    ...init,
    headers,
    credentials: 'include', // Primary secure HttpOnly session cookie
  });
}

// Authentication
export async function register(credentials: RegisterCredentials): Promise<AuthTokenResponse> {
  const res = await authFetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Registration failed');
  }
  return res.json();
}

export async function login(credentials: LoginCredentials): Promise<AuthTokenResponse> {
  const res = await authFetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Login failed');
  }
  return res.json();
}

export async function logout(): Promise<{ message: string }> {
  try {
    const res = await authFetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`Logout failed: ${res.statusText}`);
    return res.json();
  } catch {
    return { message: 'Logged out' };
  }
}

export async function fetchCurrentUser(): Promise<User | null> {
  try {
    const res = await authFetch(`${API_BASE}/auth/me`);
    if (!res.ok) {
      return null;
    }
    return res.json();
  } catch {
    return null;
  }
}

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await authFetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Failed to fetch health: ${res.statusText}`);
  return res.json();
}

export async function fetchPolicies(): Promise<PolicySet[]> {
  const res = await authFetch(`${API_BASE}/policies`);
  if (!res.ok) throw new Error(`Failed to fetch policies: ${res.statusText}`);
  return res.json();
}

export async function setActivePolicy(policyId: string): Promise<{ message: string; policy: PolicySet }> {
  const res = await authFetch(`${API_BASE}/policies/active/${policyId}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to activate policy: ${res.statusText}`);
  return res.json();
}

export async function resetDefaultPolicies(): Promise<{ message: string }> {
  const res = await authFetch(`${API_BASE}/policies/reset-default`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to reset policies: ${res.statusText}`);
  return res.json();
}

export async function savePolicy(policy: PolicySet): Promise<PolicySet> {
  const res = await authFetch(`${API_BASE}/policies`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy),
  });
  if (!res.ok) throw new Error(`Failed to save policy: ${res.statusText}`);
  return res.json();
}

export async function fetchSuites(): Promise<TestSuite[]> {
  const res = await authFetch(`${API_BASE}/suites`);
  if (!res.ok) throw new Error(`Failed to fetch test suites: ${res.statusText}`);
  return res.json();
}

export async function fetchRuns(): Promise<TestRun[]> {
  const res = await authFetch(`${API_BASE}/runs`);
  if (!res.ok) throw new Error(`Failed to fetch test runs: ${res.statusText}`);
  return res.json();
}

export async function fetchRun(runId: string): Promise<TestRun> {
  const res = await authFetch(`${API_BASE}/runs/${runId}`);
  if (!res.ok) throw new Error(`Failed to fetch run details: ${res.statusText}`);
  return res.json();
}

export async function triggerRun(params: {
  suite_id: string;
  policy_set_id?: string;
  agent_type: string;
  groq_api_key?: string;
}): Promise<TestRun> {
  const res = await authFetch(`${API_BASE}/runs`, {
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
  const res = await authFetch(`${API_BASE}/runs/compare/diff?run_a_id=${runAId}&run_b_id=${runBId}`);
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

  const res = await authFetch(`${API_BASE}/audit?${params.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch audit events: ${res.statusText}`);
  return res.json();
}

export async function executePlayground(params: {
  prompt: string;
  agent_type: string;
  scenario_id?: string;
  tool?: string;
  category?: string;
  policy_set_id?: string;
  groq_api_key?: string;
}): Promise<any> {
  const res = await authFetch(`${API_BASE}/playground/execute`, {
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
  const res = await authFetch(`${API_BASE}/findings`);
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
  return res.json();
}

export async function fetchLanguageStats(suiteId: string = 'suite_core_security_v1'): Promise<any> {
  const res = await authFetch(`${API_BASE}/suites/language-stats?suite_id=${suiteId}`);
  if (!res.ok) throw new Error(`Failed to fetch language stats: ${res.statusText}`);
  return res.json();
}

export async function fetchEmergencyStop(): Promise<{ emergency_stopped: boolean; status: string }> {
  const res = await authFetch(`${API_BASE}/gateway/emergency-stop`);
  if (!res.ok) throw new Error(`Failed to fetch emergency stop status: ${res.statusText}`);
  return res.json();
}

export async function setEmergencyStop(stopped: boolean): Promise<{ emergency_stopped: boolean; status: string; message: string }> {
  const res = await authFetch(`${API_BASE}/gateway/emergency-stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ stopped }),
  });
  if (!res.ok) throw new Error(`Failed to update emergency stop: ${res.statusText}`);
  return res.json();
}

export async function runAutonomousAgent(params: {
  goal: string;
  max_steps?: number;
  policy_set_id?: string;
}): Promise<any> {
  const res = await authFetch(`${API_BASE}/agent/autonomous-run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Autonomous agent run failed');
  }
  return res.json();
}
