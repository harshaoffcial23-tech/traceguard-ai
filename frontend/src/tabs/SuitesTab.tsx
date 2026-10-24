import React, { useState } from 'react';
import {
  FileCheck2,
  Play,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  Layers,
  ArrowRight,
  Info,
} from 'lucide-react';
import { TestSuite, PolicySet, TestRun } from '../types';

interface SuitesTabProps {
  suites: TestSuite[];
  policies: PolicySet[];
  onTriggerRun: (params: {
    suite_id: string;
    policy_set_id?: string;
    agent_type: string;
    groq_api_key?: string;
  }) => Promise<TestRun>;
  onInspectRun: (runId: string) => void;
  isRunningTest: boolean;
}

export const SuitesTab: React.FC<SuitesTabProps> = ({
  suites,
  policies,
  onTriggerRun,
  onInspectRun,
  isRunningTest,
}) => {
  const [selectedSuiteId, setSelectedSuiteId] = useState<string>(
    suites.length > 0 ? suites[0].id : 'suite_core_security_v1'
  );
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>(
    policies.find((p) => p.is_active)?.id || 'policy_strict_enterprise_v1'
  );
  const [agentType, setAgentType] = useState<string>('mock');
  const [groqKey, setGroqKey] = useState<string>('');
  const [lastExecutedRun, setLastExecutedRun] = useState<TestRun | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const currentSuite = suites.find((s) => s.id === selectedSuiteId) || suites[0];

  const handleRun = async () => {
    setErrorMessage(null);
    try {
      const run = await onTriggerRun({
        suite_id: selectedSuiteId,
        policy_set_id: selectedPolicyId,
        agent_type: agentType,
        groq_api_key: groqKey.trim() || undefined,
      });
      setLastExecutedRun(run);
    } catch (err: any) {
      setErrorMessage(err.message || 'Execution failed.');
    }
  };

  const getCategoryBadge = (category: string, isMalicious: boolean) => {
    if (!isMalicious) {
      return (
        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono text-[10px]">
          LEGITIMATE TASK
        </span>
      );
    }
    switch (category) {
      case 'direct_injection':
        return (
          <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono text-[10px]">
            DIRECT INJECTION
          </span>
        );
      case 'indirect_injection':
        return (
          <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono text-[10px]">
            INDIRECT INJECTION
          </span>
        );
      case 'data_exfiltration':
        return (
          <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono text-[10px]">
            DATA EXFILTRATION
          </span>
        );
      case 'privilege_escalation':
        return (
          <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono text-[10px]">
            SANDBOX ESCAPE
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono text-[10px]">
            {category.toUpperCase()}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Execution Launcher Panel */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 shadow space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Play className="w-4 h-4 text-emerald-400" />
              <span>Security Suite Runner & Attack Benchmark</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Execute standardized test suites against the security gateway to evaluate attack prevention.
            </p>
          </div>
          <button
            onClick={handleRun}
            disabled={isRunningTest}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition shadow-md shadow-emerald-950/40 disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            <span>{isRunningTest ? 'Running Benchmark Cases...' : 'Execute Suite Now'}</span>
          </button>
        </div>

        {/* Configuration Selectors */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* 1. Suite Selector */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
              <FileCheck2 className="w-3.5 h-3.5 text-indigo-400" />
              <span>Target Benchmark Suite</span>
            </label>
            <select
              value={selectedSuiteId}
              onChange={(e) => setSelectedSuiteId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
            >
              {suites.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.test_cases.length} cases)
                </option>
              ))}
            </select>
          </div>

          {/* 2. Policy Set Selector */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-emerald-400" />
              <span>Enforced Policy Set</span>
            </label>
            <select
              value={selectedPolicyId}
              onChange={(e) => setSelectedPolicyId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500"
            >
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} {p.is_active ? '(Active)' : ''}
                </option>
              ))}
            </select>
          </div>

          {/* 3. Agent Mode */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Agent Provider</span>
            </label>
            <select
              value={agentType}
              onChange={(e) => setAgentType(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="mock">Deterministic Mock Agent (100% Offline, No Keys)</option>
              <option value="groq">Groq Live LLM (llama-3.3-70b-versatile)</option>
            </select>
          </div>
        </div>

        {/* Optional Groq Key input if Groq selected */}
        {agentType === 'groq' && (
          <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row items-center gap-3">
            <input
              type="password"
              placeholder="Enter Groq API Key (or configure GROQ_API_KEY in .env)"
              value={groqKey}
              onChange={(e) => setGroqKey(e.target.value)}
              className="flex-1 bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500 placeholder-slate-500"
            />
            <p className="text-[11px] text-slate-400">
              Model calls pass through the same server-side gateway. Never stored.
            </p>
          </div>
        )}

        {/* Error message display */}
        {errorMessage && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Last Executed Run Feedback Card */}
        {lastExecutedRun && (
          <div className="p-4 bg-slate-900/90 border border-emerald-500/30 rounded-lg flex flex-col md:flex-row items-start md:items-center justify-between gap-3 animate-fade-in">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-emerald-500/10 rounded-lg text-emerald-400 border border-emerald-500/20">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                  <span>Run {lastExecutedRun.id} Finished</span>
                  <span className="font-mono text-[10px] text-emerald-400">
                    Accuracy: {lastExecutedRun.metrics.accuracy}% | Attack Block: {lastExecutedRun.metrics.attack_block_rate}%
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Passed: {lastExecutedRun.metrics.passed_tests}/{lastExecutedRun.metrics.total_tests} | Data Exposure Incidents: {lastExecutedRun.metrics.data_exposure_incidents}
                </p>
              </div>
            </div>
            <button
              onClick={() => onInspectRun(lastExecutedRun.id)}
              className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1.5 transition"
            >
              <span>Inspect Traces & Audit Logs</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Test Cases Viewer */}
      {currentSuite && (
        <div className="bg-[#0d1322] border border-slate-800 rounded-xl overflow-hidden shadow">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white">{currentSuite.name}</h3>
              <p className="text-xs text-slate-400 mt-0.5">{currentSuite.description}</p>
            </div>
            <span className="px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300">
              {currentSuite.test_cases.length} Repeatable Scenarios
            </span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {currentSuite.test_cases.map((tc, idx) => (
              <div key={tc.id} className="p-4 hover:bg-slate-800/30 transition space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-300">#{idx + 1} {tc.id}</span>
                    <span className="text-xs font-medium text-white">{tc.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getCategoryBadge(tc.category, tc.is_malicious)}
                    <span
                      className={`px-2 py-0.5 rounded font-mono text-[10px] font-semibold ${
                        tc.expected_decision === 'allow'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}
                    >
                      EXPECTED: {tc.expected_decision.toUpperCase()}
                    </span>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-md p-2.5">
                  <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">Simulated User / Injected Input Prompt</span>
                  <p className="text-xs font-mono text-slate-200">{tc.user_prompt}</p>
                </div>

                <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 pt-1">
                  <span>Target Tool: <strong className="text-slate-300 font-mono">{tc.expected_tool || 'Any'}</strong></span>
                  <span>Target Resource: <strong className="text-slate-300 font-mono">{tc.target_resource || 'N/A'}</strong></span>
                  <span>Execution Expected: <strong className={tc.expected_execution ? 'text-emerald-400' : 'text-rose-400'}>{tc.expected_execution ? 'Yes' : 'No'}</strong></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
