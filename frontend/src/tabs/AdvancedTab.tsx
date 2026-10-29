import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  GitCompare,
  AlertTriangle,
  Layers,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertOctagon,
  ShieldAlert,
  ShieldCheck,
  Power,
  ChevronDown,
  ChevronRight,
  Database,
  Mail,
  FileCode,
} from 'lucide-react';
import {
  TestSuite,
  PolicySet,
  TestRun,
  RegressionComparison,
  FindingsSummary,
  LanguageStatsResponse,
} from '../types';
import {
  fetchSuites,
  fetchPolicies,
  fetchRuns,
  triggerRun,
  compareRuns,
  fetchFindings,
  fetchLanguageStats,
  fetchEmergencyStop,
  setEmergencyStop,
  setActivePolicy,
  resetDefaultPolicies,
} from '../services/api';

interface AdvancedTabProps {
  initialSubTab?: 'benchmark' | 'regression' | 'owasp' | 'policies';
  onNavigateTab: (tab: string) => void;
}

export const AdvancedTab: React.FC<AdvancedTabProps> = ({ initialSubTab = 'benchmark', onNavigateTab }) => {
  const [subTab, setSubTab] = useState<'benchmark' | 'regression' | 'owasp' | 'policies'>(initialSubTab);

  // Data states
  const [suites, setSuites] = useState<TestSuite[]>([]);
  const [policies, setPolicies] = useState<PolicySet[]>([]);
  const [runs, setRuns] = useState<TestRun[]>([]);
  const [findings, setFindings] = useState<FindingsSummary | null>(null);
  const [langStats, setLangStats] = useState<LanguageStatsResponse | null>(null);
  const [emergencyStopped, setEmergencyStopped] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // Benchmark Run State
  const [isRunningBenchmark, setIsRunningBenchmark] = useState<boolean>(false);
  const [selectedPolicyForRun, setSelectedPolicyForRun] = useState<string>('policy_strict_enterprise_v1');
  const [lastBenchmarkRun, setLastBenchmarkRun] = useState<TestRun | null>(null);

  // Regression Diff State
  const [runAId, setRunAId] = useState<string>('');
  const [runBId, setRunBId] = useState<string>('');
  const [diffResult, setDiffResult] = useState<RegressionComparison | null>(null);
  const [isComparing, setIsComparing] = useState<boolean>(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [s, p, r, f, l, es] = await Promise.all([
        fetchSuites().catch(() => []),
        fetchPolicies().catch(() => []),
        fetchRuns().catch(() => []),
        fetchFindings().catch(() => null),
        fetchLanguageStats().catch(() => null),
        fetchEmergencyStop().catch(() => ({ emergency_stopped: false, status: 'OPERATIONAL' })),
      ]);
      setSuites(s);
      setPolicies(p);
      setRuns(r);
      setFindings(f);
      setLangStats(l);
      setEmergencyStopped(es.emergency_stopped);

      if (r.length >= 2) {
        setRunAId(r[0].id);
        setRunBId(r[1].id);
      } else if (r.length === 1) {
        setRunAId(r[0].id);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // 1. Run Benchmark Handler
  const handleExecuteBenchmark = async () => {
    setIsRunningBenchmark(true);
    setStatusMsg(null);
    try {
      const newRun = await triggerRun({
        suite_id: 'suite_core_security_v1',
        policy_set_id: selectedPolicyForRun,
        agent_type: 'mock',
      });
      setLastBenchmarkRun(newRun);
      setRuns((prev) => [newRun, ...prev.filter((r) => r.id !== newRun.id)]);
      setStatusMsg(`Benchmark run ${newRun.id} completed successfully.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err.message || 'Benchmark run failed'}`);
    } finally {
      setIsRunningBenchmark(false);
    }
  };

  // 2. Run Compare Handler
  const handleCompare = async () => {
    if (!runAId || !runBId) return;
    setIsComparing(true);
    try {
      const comp = await compareRuns(runAId, runBId);
      setDiffResult(comp);
    } catch (err: any) {
      setStatusMsg(`Comparison error: ${err.message}`);
    } finally {
      setIsComparing(false);
    }
  };

  // 3. Emergency Stop Toggle
  const handleToggleEmergencyStop = async () => {
    try {
      const targetState = !emergencyStopped;
      const res = await setEmergencyStop(targetState);
      setEmergencyStopped(res.emergency_stopped);
      setStatusMsg(res.message);
    } catch (err: any) {
      setStatusMsg(`Failed to toggle kill switch: ${err.message}`);
    }
  };

  // 4. Policy Switcher
  const handleSwitchPolicy = async (polId: string) => {
    try {
      const res = await setActivePolicy(polId);
      setPolicies((prev) =>
        prev.map((p) => ({ ...p, is_active: p.id === polId }))
      );
      setStatusMsg(res.message);
    } catch (err: any) {
      setStatusMsg(`Failed to activate policy: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto py-2">
      {/* Header */}
      <div className="glass-panel rounded-2xl p-6 border border-white/10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-[#8E969E] mb-2">
          <Layers className="w-3.5 h-3.5 text-purple-400" />
          <span>Security Suites & Policy Engine</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold text-white tracking-tight">
          Adversarial Benchmarks & Invariant Policies
        </h1>
        <p className="text-xs sm:text-sm text-[#8E969E] mt-1">
          Deep-dive benchmark runner, multi-lingual test evaluation, policy regression diffing, and emergency circuit breakers.
        </p>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 p-1.5 rounded-full liquid-pill">
        <button
          type="button"
          onClick={() => setSubTab('benchmark')}
          className={`px-4 py-1.5 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
            subTab === 'benchmark'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white'
          }`}
        >
          <FileCheck2 className="w-3.5 h-3.5" />
          <span>Benchmark Suites</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('regression')}
          className={`px-4 py-1.5 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
            subTab === 'regression'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white'
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>Policy Regression Diff</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('owasp')}
          className={`px-4 py-1.5 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
            subTab === 'owasp'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Security Invariants</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('policies')}
          className={`px-4 py-1.5 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
            subTab === 'policies'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Policies & Circuit Breaker</span>
        </button>
      </div>

      {statusMsg && (
        <div className="p-3.5 rounded-xl bg-white/[0.04] border border-white/10 text-xs font-mono text-white">
          {statusMsg}
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* 1. BENCHMARK SUITES VIEW */}
      {/* ------------------------------------------------------------- */}
      {subTab === 'benchmark' && (
        <div className="space-y-6">
          <div className="glass-panel rounded-2xl border border-white/10 p-6 space-y-5">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-semibold text-white">
                  Core Security Suite (suite_core_security_v1)
                </h2>
                <p className="text-xs text-[#8E969E] mt-0.5">
                  31 real benchmark cases evaluated across 5 languages.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <select
                  value={selectedPolicyForRun}
                  onChange={(e) => setSelectedPolicyForRun(e.target.value)}
                  className="bg-black/80 border border-white/15 text-xs rounded-xl px-3 py-2 text-white font-mono cursor-pointer"
                >
                  {policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>

                <button
                  type="button"
                  onClick={handleExecuteBenchmark}
                  disabled={isRunningBenchmark}
                  className="glass-button-primary px-5 py-2 rounded-full text-xs font-semibold text-white transition flex items-center gap-2 disabled:opacity-50 cursor-pointer shadow-md"
                >
                  <Play className="w-3.5 h-3.5 fill-current text-[#C7F36B]" />
                  <span>{isRunningBenchmark ? 'Running Suite...' : 'Run Benchmark'}</span>
                </button>
              </div>
            </div>

            {/* Language Breakdown Table */}
            {langStats && (
              <div className="pt-2">
                <div className="text-xs font-medium text-[#929CA3] mb-2">
                  Multilingual Benchmark Composition:
                </div>
                <div className="border border-[#242C31] rounded overflow-hidden">
                  <table className="w-full text-xs font-mono text-left">
                    <thead className="bg-[#111417] text-[#929CA3] border-b border-[#242C31]">
                      <tr>
                        <th className="p-2.5">Language</th>
                        <th className="p-2.5">Total Cases</th>
                        <th className="p-2.5 text-[#EF4444]">Malicious Attacks</th>
                        <th className="p-2.5 text-[#C7F36B]">Legitimate Requests</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#242C31]">
                      {Object.entries(langStats.languages).map(([k, st]) => (
                        <tr key={k} className="hover:bg-[#1C2226]/40">
                          <td className="p-2.5 font-medium text-[#E8ECEF]">{st.name}</td>
                          <td className="p-2.5 text-[#E8ECEF]">{st.total}</td>
                          <td className="p-2.5 text-[#EF4444]">{st.malicious}</td>
                          <td className="p-2.5 text-[#C7F36B]">{st.legitimate}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Results of Latest Execution */}
            {lastBenchmarkRun && (
              <div className="pt-3 border-t border-[#242C31] space-y-3">
                <div className="text-xs font-medium text-[#929CA3]">
                  Latest Benchmark Results (Run ID: {lastBenchmarkRun.id}):
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">Accuracy</div>
                    <div className="text-lg font-mono font-semibold text-[#E8ECEF]">
                      {lastBenchmarkRun.metrics.accuracy}%
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">Attack Block Rate</div>
                    <div className="text-lg font-mono font-semibold text-[#C7F36B]">
                      {lastBenchmarkRun.metrics.attack_block_rate}%
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">Legitimate Allow Rate</div>
                    <div className="text-lg font-mono font-semibold text-[#C7F36B]">
                      {lastBenchmarkRun.metrics.legitimate_allow_rate}%
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">Data Exposure Leaks</div>
                    <div className="text-lg font-mono font-semibold text-[#E8ECEF]">
                      {lastBenchmarkRun.metrics.data_exposure_incidents}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* 2. POLICY REGRESSION DIFF VIEW */}
      {/* ------------------------------------------------------------- */}
      {subTab === 'regression' && (
        <div className="space-y-6">
          <div className="border border-[#242C31] bg-[#15191C] rounded-lg p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-[#E8ECEF]">
                Policy Regression Comparison
              </h2>
              <p className="text-xs text-[#929CA3] mt-0.5">
                Compare test run results under Strict Zero-Trust vs Permissive policies to identify regressions.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-3">
              <div className="w-full sm:w-1/2 space-y-1">
                <label className="text-[11px] text-[#929CA3] font-mono">Run A (e.g. Strict Baseline):</label>
                <select
                  value={runAId}
                  onChange={(e) => setRunAId(e.target.value)}
                  className="w-full bg-[#0B0D0F] border border-[#242C31] text-xs rounded p-2 text-[#E8ECEF] font-mono"
                >
                  <option value="">Select Baseline Run...</option>
                  {runs.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.id} ({r.policy_set_id}) - Block Rate: {r.metrics.attack_block_rate}%
                    </option>
                  ))}
                </select>
              </div>

              <div className="w-full sm:w-1/2 space-y-1">
                <label className="text-[11px] text-[#929CA3] font-mono">Run B (e.g. Permissive / Modified):</label>
                <select
                  value={runBId}
                  onChange={(e) => setRunBId(e.target.value)}
                  className="w-full bg-[#0B0D0F] border border-[#242C31] text-xs rounded p-2 text-[#E8ECEF] font-mono"
                >
                  <option value="">Select Comparison Run...</option>
                  {runs.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.id} ({r.policy_set_id}) - Block Rate: {r.metrics.attack_block_rate}%
                    </option>
                  ))}
                </select>
              </div>

              <button
                type="button"
                onClick={handleCompare}
                disabled={isComparing || !runAId || !runBId}
                className="mt-5 px-4 py-2 rounded bg-[#C7F36B] hover:bg-[#B8E85C] text-[#0B0D0F] font-semibold text-xs transition disabled:opacity-50 shrink-0"
              >
                {isComparing ? 'Comparing...' : 'Compare Runs'}
              </button>
            </div>

            {/* Diff Results */}
            {diffResult && (
              <div className="pt-4 border-t border-[#242C31] space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">Regressions Count</div>
                    <div className="text-lg font-mono font-semibold text-[#EF4444]">
                      {diffResult.regressions_count}
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">Attack Block Delta</div>
                    <div className="text-lg font-mono font-semibold text-[#E8ECEF]">
                      {diffResult.delta_metrics.attack_block_rate_delta}%
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">False Negatives Delta</div>
                    <div className="text-lg font-mono font-semibold text-[#EF4444]">
                      +{diffResult.delta_metrics.false_negative_delta}
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#0B0D0F] border border-[#242C31]">
                    <div className="text-[11px] text-[#929CA3]">Data Exposure Delta</div>
                    <div className="text-lg font-mono font-semibold text-[#EF4444]">
                      +{diffResult.delta_metrics.data_exposure_delta}
                    </div>
                  </div>
                </div>

                {/* Specific Regressions List */}
                {diffResult.regressions.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-medium text-[#EF4444]">
                      Identified Vulnerability Regressions ({diffResult.regressions.length} attacks allowed in Run B):
                    </div>
                    <div className="border border-[#242C31] rounded divide-y divide-[#242C31] max-h-60 overflow-y-auto">
                      {diffResult.regressions.map((rg: any, i: number) => (
                        <div key={i} className="p-2.5 text-xs font-mono flex items-center justify-between gap-3 bg-[#111417]">
                          <div>
                            <span className="text-[#E8ECEF] font-semibold">{rg.test_case_name}</span>
                            <span className="text-[#5E6971] text-[11px] ml-2">({rg.category})</span>
                          </div>
                          <div className="text-[11px] text-[#EF4444]">
                            Run A: Blocked → Run B: Allowed
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* 3. SECURITY INVARIANTS & THREAT ASSESSMENT */}
      {/* ------------------------------------------------------------- */}
      {subTab === 'owasp' && (
        <div className="space-y-6">
          {/* Prominent Scope & Limitations Banner */}
          <div className="border border-[#242C31] bg-[#15191C] rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#242C31] pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-[#C7F36B]" />
                <h2 className="text-sm font-semibold text-[#E8ECEF]">
                  Gateway Security Posture & Verified Invariants
                </h2>
              </div>
              <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-[#C7F36B]/15 text-[#C7F36B] border border-[#C7F36B]/30 font-bold">
                FAIL-CLOSED ZERO-TRUST GATEWAY
              </span>
            </div>

            {/* Scope and Disclaimer */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded bg-[#111417] border border-[#242C31] space-y-1">
                <span className="text-[10px] font-mono uppercase text-[#C7F36B] font-semibold block">
                  Tested Scope
                </span>
                <p className="text-[#929CA3] leading-relaxed">
                  {findings?.scope_and_limitations?.tested_scope ||
                    'Controlled single-tenant security lab executing mock and live Groq LLM tool loops across file, database, and email boundaries.'}
                </p>
              </div>

              <div className="p-3 rounded bg-[#111417] border border-[#242C31] space-y-1">
                <span className="text-[10px] font-mono uppercase text-[#38BDF8] font-semibold block">
                  Enforced Policy Protections
                </span>
                <p className="text-[#929CA3] leading-relaxed">
                  {findings?.scope_and_limitations?.enforced_guarantees ||
                    'Deterministic prevention of protected tool execution on denial; PII and secret redaction; fail-closed schema validation; multi-recipient email confinement; operator emergency stop.'}
                </p>
              </div>

              <div className="p-3 rounded bg-[#111417] border border-[#242C31] space-y-1">
                <span className="text-[10px] font-mono uppercase text-[#F59E0B] font-semibold block">
                  Tested Scope Limitations
                </span>
                <p className="text-[#929CA3] leading-relaxed">
                  {findings?.scope_and_limitations?.known_limitations ||
                    'Does not prevent conversational text hallucination outside tool execution; does not inspect external unencrypted proxies; does not claim immunity against zero-day cryptographic breaks.'}
                </p>
              </div>
            </div>

            {/* Key Telemetry Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
              <div className="p-3 rounded bg-[#111417] border border-[#242C31] text-center">
                <span className="text-[10px] font-mono uppercase text-[#5E6971] block">
                  Attacks Intercepted
                </span>
                <span className="text-lg font-bold font-mono text-[#C7F36B]">
                  {findings?.total_blocked_actions ?? 0}
                </span>
              </div>

              <div className="p-3 rounded bg-[#111417] border border-[#242C31] text-center">
                <span className="text-[10px] font-mono uppercase text-[#5E6971] block">
                  Unauthorized Executions
                </span>
                <span className="text-lg font-bold font-mono text-[#C7F36B]">
                  {findings?.unauthorized_executions ?? 0}
                </span>
              </div>

              <div className="p-3 rounded bg-[#111417] border border-[#242C31] text-center">
                <span className="text-[10px] font-mono uppercase text-[#5E6971] block">
                  Verified Data Exposures
                </span>
                <span className="text-lg font-bold font-mono text-[#C7F36B]">
                  {findings?.total_exposure_incidents ?? 0}
                </span>
              </div>

              <div className="p-3 rounded bg-[#111417] border border-[#242C31] text-center">
                <span className="text-[10px] font-mono uppercase text-[#5E6971] block">
                  False Positives
                </span>
                <span className="text-lg font-bold font-mono text-[#E8ECEF]">
                  {findings?.false_positive_count ?? 0}
                </span>
              </div>

              <div className="p-3 rounded bg-[#111417] border border-[#242C31] text-center">
                <span className="text-[10px] font-mono uppercase text-[#5E6971] block">
                  False Negatives
                </span>
                <span className="text-lg font-bold font-mono text-[#E8ECEF]">
                  {findings?.false_negative_count ?? 0}
                </span>
              </div>
            </div>
          </div>

          {/* 7 Core Security Invariants */}
          <div className="border border-[#242C31] bg-[#15191C] rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#242C31] pb-3">
              <h3 className="text-sm font-semibold text-[#E8ECEF]">
                Verified Security Invariants (Automated Gatekeeper Rules)
              </h3>
              <span className="text-xs font-mono text-[#5E6971]">
                7 of 7 Automated Rules Active
              </span>
            </div>

            <div className="space-y-3">
              {(findings?.security_invariants || []).map((inv) => (
                <div
                  key={inv.id}
                  className="p-3.5 rounded-lg bg-[#111417] border border-[#242C31] flex flex-col sm:flex-row sm:items-start justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-[#C7F36B]">
                        {inv.id}
                      </span>
                      <span className="text-xs font-semibold text-[#E8ECEF]">
                        {inv.name}
                      </span>
                    </div>
                    <p className="text-xs text-[#929CA3]">{inv.description}</p>
                    <div className="text-[11px] font-mono text-[#5E6971] pt-1">
                      <span className="text-[#929CA3]">Evidence:</span> {inv.evidence}
                    </div>
                  </div>

                  <span className="text-[10px] font-mono px-2.5 py-0.5 rounded bg-[#C7F36B]/10 text-[#C7F36B] border border-[#C7F36B]/25 shrink-0 self-start">
                    {inv.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* OWASP LLM Top 10 Threat Matrix */}
          <div className="border border-[#242C31] bg-[#15191C] rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-[#E8ECEF]">
              OWASP Top 10 for Large Language Models Threat Coverage
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {findings?.owasp_top_10.map((item) => (
                <div
                  key={item.id}
                  className="p-4 rounded-lg bg-[#111417] border border-[#242C31] space-y-2.5 flex flex-col justify-between"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-[#1C2226] text-[#C7F36B] border border-[#242C31]">
                          {item.id}
                        </span>
                        <span className="text-xs font-semibold text-[#E8ECEF]">
                          {item.name}
                        </span>
                      </div>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${
                          item.severity === 'CRITICAL'
                            ? 'bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/30'
                            : 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/30'
                        }`}
                      >
                        {item.severity}
                      </span>
                    </div>

                    <p className="text-xs text-[#929CA3]">{item.description}</p>

                    <div className="pt-1 text-xs font-mono text-[#5E6971]">
                      <span className="text-[#929CA3]">Enforcement:</span> {item.mitigation}
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-[#242C31] text-[11px] font-mono">
                    <span className="text-[#5E6971]">
                      Tests: <code className="text-[#E8ECEF]">{item.test_cases.join(', ')}</code>
                    </span>
                    <span className="text-[#C7F36B] font-semibold">{item.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* 4. POLICIES & KILL-SWITCH CONTROLS */}
      {/* ------------------------------------------------------------- */}
      {subTab === 'policies' && (
        <div className="space-y-6">
          {/* Emergency Stop Card */}
          <div className="border border-[#242C31] bg-[#15191C] rounded-lg p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Power className="w-4 h-4 text-[#EF4444]" />
                <h3 className="text-sm font-semibold text-[#E8ECEF]">
                  Gateway Emergency Kill-Switch
                </h3>
              </div>
              <p className="text-xs text-[#929CA3] mt-1 max-w-lg">
                Instantly halts all protected tool executions across all sessions and agent threads. Evaluated prior to policy evaluation.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <span
                className={`text-xs font-mono font-bold px-2.5 py-1 rounded ${
                  emergencyStopped
                    ? 'bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/40'
                    : 'bg-[#C7F36B]/15 text-[#C7F36B] border border-[#C7F36B]/30'
                }`}
              >
                {emergencyStopped ? 'HALTED / STOPPED' : 'GATEWAY OPERATIONAL'}
              </span>

              <button
                type="button"
                onClick={handleToggleEmergencyStop}
                className={`px-4 py-1.5 rounded text-xs font-semibold font-mono transition ${
                  emergencyStopped
                    ? 'bg-[#C7F36B] text-[#0B0D0F] hover:bg-[#B8E85C]'
                    : 'bg-[#EF4444] text-white hover:bg-[#DC2626]'
                }`}
              >
                {emergencyStopped ? 'Resume Operations' : 'Emergency Stop'}
              </button>
            </div>
          </div>

          {/* Policy Sets List */}
          <div className="border border-[#242C31] bg-[#15191C] rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-[#E8ECEF]">Registered Security Policy Sets</h3>
            <div className="space-y-3">
              {policies.map((pol) => (
                <div
                  key={pol.id}
                  className={`p-4 rounded-lg border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                    pol.is_active
                      ? 'bg-[#1C2226] border-[#C7F36B]'
                      : 'bg-[#111417] border-[#242C31]'
                  }`}
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-xs text-[#E8ECEF]">{pol.name}</span>
                      {pol.is_active && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#C7F36B]/10 text-[#C7F36B] border border-[#C7F36B]/25">
                          ACTIVE
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-[#929CA3] mt-1">{pol.description}</p>
                    <div className="text-[11px] font-mono text-[#5E6971] mt-1">
                      {pol.rules.length} configured rules · Default Action: {pol.default_action.toUpperCase()}
                    </div>
                  </div>

                  {!pol.is_active && (
                    <button
                      type="button"
                      onClick={() => handleSwitchPolicy(pol.id)}
                      className="px-3 py-1 rounded bg-[#1C2226] hover:bg-[#242C31] border border-[#242C31] text-xs font-mono text-[#E8ECEF] transition shrink-0"
                    >
                      Set Active
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
