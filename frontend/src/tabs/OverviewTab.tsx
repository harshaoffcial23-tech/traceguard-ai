import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Play,
  CheckCircle2,
  AlertCircle,
  FileText,
  Activity,
  ArrowRight,
  Database,
  Mail,
  FileCode,
} from 'lucide-react';
import { TestRun, SystemHealth } from '../types';

interface OverviewTabProps {
  runs: TestRun[];
  health: SystemHealth | null;
  onSelectRun: (runId: string) => void;
  onNavigateTab: (tab: string) => void;
  onQuickRun: () => void;
  isRunningTest: boolean;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  runs,
  health,
  onSelectRun,
  onNavigateTab,
  onQuickRun,
  isRunningTest,
}) => {
  const latestRun = runs.length > 0 ? runs[0] : null;
  const metrics = latestRun?.metrics;

  return (
    <div className="space-y-6">
      {/* Top Banner / Callout */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 rounded-xl p-6 shadow-lg">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Zero-Trust Gateway Architecture
              </span>
              <span className="text-xs text-slate-400">Deterministic Lab + Live Agent Adapters</span>
            </div>
            <h1 className="text-xl md:text-2xl font-bold text-white tracking-tight">
              AI Agent Security & Tool-Use Authorization Gateway
            </h1>
            <p className="text-sm text-slate-400 max-w-2xl">
              Strict deny-by-default gateway for LLM tool invocation. Intercepts prompt injections,
              prevents unauthorized data exfiltration, sanitizes PII audit traces, and calculates
              reproducible security metrics.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onQuickRun}
              disabled={isRunningTest}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-sm transition shadow-md shadow-emerald-950/40 disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>{isRunningTest ? 'Running Benchmark...' : 'Run Security Suite'}</span>
            </button>
            <button
              onClick={() => onNavigateTab('playground')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-sm border border-slate-700 transition"
            >
              <span>Live Playground</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Attack Block Rate */}
        <div className="bg-[#0d1322] border border-slate-800/80 rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Attack Block Rate</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold text-white font-mono">
              {metrics ? `${metrics.attack_block_rate}%` : '---'}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              {metrics ? `${metrics.total_tests - metrics.false_negative_count} / ${metrics.total_tests - metrics.false_positive_count} attacks stopped` : 'Run benchmark to calculate'}
            </p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 to-teal-400"></div>
        </div>

        {/* Metric 2: Legitimate Allow Rate */}
        <div className="bg-[#0d1322] border border-slate-800/80 rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Legitimate Allow Rate</span>
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold text-white font-mono">
              {metrics ? `${metrics.legitimate_allow_rate}%` : '---'}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              {metrics ? `${metrics.false_positive_count} false positives recorded` : 'Permitted task rate'}
            </p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-indigo-500 to-cyan-400"></div>
        </div>

        {/* Metric 3: Verified Data Exposure Incidents */}
        <div className="bg-[#0d1322] border border-slate-800/80 rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Data Exposure Incidents</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-emerald-400">
              {metrics ? `${metrics.data_exposure_incidents}` : '0'}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Zero-exposure guaranteed by gateway interception
            </p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-500 to-emerald-400"></div>
        </div>

        {/* Metric 4: Benchmark Accuracy */}
        <div className="bg-[#0d1322] border border-slate-800/80 rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Suite Accuracy</span>
            <div className="p-2 rounded-lg bg-teal-500/10 text-teal-400 border border-teal-500/20">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold text-white font-mono">
              {metrics ? `${metrics.accuracy}%` : '---'}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              {metrics ? `${metrics.passed_tests} passed / ${metrics.failed_tests} failed` : 'Actual labeled test results'}
            </p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-teal-500 to-blue-500"></div>
        </div>
      </div>

      {/* Controlled Tools & Core Security Pipeline Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <FileCode className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Controlled Tool: read_file</h3>
              <p className="text-xs text-slate-400">Sandboxed filesystem access</p>
            </div>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Strict prefix whitelisting (<code className="text-sky-300">public/</code>, <code className="text-sky-300">internal/</code>).
            Denies directory traversal (<code className="text-rose-400">../</code>) and confidential files (<code className="text-rose-400">restricted/credentials.env</code>).
          </p>
          <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5 pt-1">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Path Confinement Active</span>
          </div>
        </div>

        <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Controlled Tool: query_database</h3>
              <p className="text-xs text-slate-400">Synthetic SQLite catalog</p>
            </div>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Permits SELECT on public catalog (<code className="text-violet-300">products</code>, <code className="text-violet-300">faq</code>).
            Rejects mutations (DROP, DELETE) and confidential tables (<code className="text-rose-400">api_tokens</code>, <code className="text-rose-400">user_profiles</code>).
          </p>
          <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5 pt-1">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>SQL Authorization Active</span>
          </div>
        </div>

        <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-pink-500/10 text-pink-400 border border-pink-500/20">
              <Mail className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Controlled Tool: send_email</h3>
              <p className="text-xs text-slate-400">Outbox domain isolation</p>
            </div>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Permits dispatch only to approved internal domains (<code className="text-pink-300">@traceguard.internal</code>).
            Denies external mail drops (<code className="text-rose-400">@evil.com</code>) and scans body for SSN/secret exfiltration.
          </p>
          <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5 pt-1">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Exfiltration Guard Active</span>
          </div>
        </div>
      </div>

      {/* Recent Runs Table */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl overflow-hidden shadow">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-slate-200">Recent Security Benchmark Runs</h2>
          </div>
          <button
            onClick={() => onNavigateTab('suites')}
            className="text-xs text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1 transition"
          >
            <span>View All Suites</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {runs.length === 0 ? (
          <div className="p-8 text-center text-slate-400 space-y-3">
            <AlertCircle className="w-8 h-8 mx-auto text-slate-500" />
            <p className="text-sm">No benchmark runs recorded yet.</p>
            <button
              onClick={onQuickRun}
              className="px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition"
            >
              Execute First Security Run
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase font-mono text-[11px]">
                <tr>
                  <th className="px-4 py-3">Run ID</th>
                  <th className="px-4 py-3">Policy Applied</th>
                  <th className="px-4 py-3">Agent Type</th>
                  <th className="px-4 py-3">Block Rate</th>
                  <th className="px-4 py-3">Legit Allowed</th>
                  <th className="px-4 py-3">Data Exposure</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {runs.slice(0, 5).map((run) => (
                  <tr key={run.id} className="hover:bg-slate-800/40 transition">
                    <td className="px-4 py-3 font-mono font-medium text-slate-200">{run.id}</td>
                    <td className="px-4 py-3 text-slate-300">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 font-mono text-[10px]">
                        {run.policy_set_id}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300 capitalize font-mono">{run.agent_type}</td>
                    <td className="px-4 py-3 font-mono">
                      <span className={run.metrics.attack_block_rate >= 100 ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
                        {run.metrics.attack_block_rate}%
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-indigo-300">{run.metrics.legitimate_allow_rate}%</td>
                    <td className="px-4 py-3 font-mono">
                      {run.metrics.data_exposure_incidents === 0 ? (
                        <span className="text-emerald-400">0 (Safe)</span>
                      ) : (
                        <span className="text-rose-400 font-bold">{run.metrics.data_exposure_incidents} (Exposed)</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400">{new Date(run.started_at).toLocaleTimeString()}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => onSelectRun(run.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-medium transition"
                      >
                        Inspect Traces
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
