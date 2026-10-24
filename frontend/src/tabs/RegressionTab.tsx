import React, { useState } from 'react';
import {
  GitCompare,
  ArrowRight,
  TrendingDown,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  ShieldCheck,
  Layers,
} from 'lucide-react';
import { TestRun, RegressionComparison } from '../types';
import { compareRuns } from '../services/api';

interface RegressionTabProps {
  runs: TestRun[];
}

export const RegressionTab: React.FC<RegressionTabProps> = ({ runs }) => {
  const [runAId, setRunAId] = useState<string>(runs[0]?.id || '');
  const [runBId, setRunBId] = useState<string>(runs[1]?.id || runs[0]?.id || '');
  const [comparison, setComparison] = useState<RegressionComparison | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleCompare = async () => {
    if (!runAId || !runBId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await compareRuns(runAId, runBId);
      setComparison(data);
    } catch (err: any) {
      setError(err.message || 'Comparison failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Run Selectors */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 shadow space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <GitCompare className="w-4 h-4 text-emerald-400" />
              <span>Policy Regression Comparison Engine</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Compare benchmark outcomes side-by-side across policy revisions (e.g. Strict Zero-Trust vs Permissive).
            </p>
          </div>
          <button
            onClick={handleCompare}
            disabled={loading || runs.length < 2}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition shadow-md shadow-emerald-950/40 disabled:opacity-50"
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>{loading ? 'Analyzing Delta...' : 'Compare Test Runs'}</span>
          </button>
        </div>

        {/* Selection Columns */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Baseline Run A (e.g., Hardened Policy)</label>
            <select
              value={runAId}
              onChange={(e) => setRunAId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} ({r.policy_set_id} | Block Rate: {r.metrics.attack_block_rate}%)
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Comparison Run B (e.g., Relaxed / New Policy)</label>
            <select
              value={runBId}
              onChange={(e) => setRunBId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} ({r.policy_set_id} | Block Rate: {r.metrics.attack_block_rate}%)
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Comparison Delta Results */}
      {comparison && (
        <div className="space-y-6 animate-fade-in">
          {/* Delta Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-4">
              <span className="text-[10px] uppercase font-mono text-slate-400">Accuracy Delta</span>
              <div className="text-xl font-bold font-mono mt-1 flex items-center gap-1.5">
                <span className={comparison.delta_metrics.accuracy_delta >= 0 ? 'text-emerald-400' : 'text-rose-400'}>
                  {comparison.delta_metrics.accuracy_delta > 0 ? `+${comparison.delta_metrics.accuracy_delta}%` : `${comparison.delta_metrics.accuracy_delta}%`}
                </span>
                {comparison.delta_metrics.accuracy_delta >= 0 ? (
                  <TrendingUp className="w-4 h-4 text-emerald-400" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-rose-400" />
                )}
              </div>
              <p className="text-[11px] text-slate-500 mt-1">Run A: {comparison.run_a.metrics.accuracy}% → Run B: {comparison.run_b.metrics.accuracy}%</p>
            </div>

            <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-4">
              <span className="text-[10px] uppercase font-mono text-slate-400">Attack Block Rate Delta</span>
              <div className="text-xl font-bold font-mono mt-1 flex items-center gap-1.5">
                <span className={comparison.delta_metrics.attack_block_rate_delta >= 0 ? 'text-emerald-400' : 'text-rose-400'}>
                  {comparison.delta_metrics.attack_block_rate_delta > 0 ? `+${comparison.delta_metrics.attack_block_rate_delta}%` : `${comparison.delta_metrics.attack_block_rate_delta}%`}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-1">Run A: {comparison.run_a.metrics.attack_block_rate}% → Run B: {comparison.run_b.metrics.attack_block_rate}%</p>
            </div>

            <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-4">
              <span className="text-[10px] uppercase font-mono text-slate-400">Data Exposure Incidents Delta</span>
              <div className="text-xl font-bold font-mono mt-1 flex items-center gap-1.5">
                <span className={comparison.delta_metrics.data_exposure_delta === 0 ? 'text-emerald-400' : 'text-rose-400'}>
                  {comparison.delta_metrics.data_exposure_delta > 0 ? `+${comparison.delta_metrics.data_exposure_delta} Leaks` : `${comparison.delta_metrics.data_exposure_delta} Leaks`}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-1">Run A: {comparison.run_a.metrics.data_exposure_incidents} → Run B: {comparison.run_b.metrics.data_exposure_incidents}</p>
            </div>

            <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-4">
              <span className="text-[10px] uppercase font-mono text-slate-400">Regressions Identified</span>
              <div className="text-xl font-bold font-mono mt-1 text-amber-400">
                {comparison.regressions_count} Regressions
              </div>
              <p className="text-[11px] text-slate-500 mt-1">Cases that passed in A but broke in B</p>
            </div>
          </div>

          {/* Regressions List */}
          {comparison.regressions.length > 0 && (
            <div className="bg-[#0d1322] border border-rose-500/30 rounded-xl overflow-hidden shadow">
              <div className="p-4 bg-rose-500/10 border-b border-rose-500/20 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <h3 className="text-sm font-semibold text-rose-300">
                    Security Regressions Detected ({comparison.regressions.length})
                  </h3>
                </div>
                <span className="text-xs font-mono text-rose-300">
                  Relaxing security policies allowed attacks to succeed
                </span>
              </div>

              <div className="divide-y divide-slate-800">
                {comparison.regressions.map((reg) => (
                  <div key={reg.test_case_id} className="p-4 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-200">{reg.test_case_id}</span>
                        <span className="text-xs font-semibold text-white">{reg.test_case_name}</span>
                        <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-slate-800 text-slate-300">
                          {reg.category}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1">
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-1">
                        <span className="text-[10px] font-mono text-slate-500 uppercase block">Baseline Run A</span>
                        <p className="text-emerald-400 font-semibold font-mono">
                          Decision: {reg.run_a.decision.toUpperCase()} | Executed: {reg.run_a.executed ? 'Yes' : 'No'} | Passed: Yes
                        </p>
                      </div>
                      <div className="bg-slate-900 border border-rose-500/30 rounded-lg p-3 space-y-1">
                        <span className="text-[10px] font-mono text-rose-400 uppercase block">Regressed Run B</span>
                        <p className="text-rose-400 font-semibold font-mono">
                          Decision: {reg.run_b.decision.toUpperCase()} | Executed: {reg.run_b.executed ? 'Yes (Vulnerable)' : 'No'} | Passed: No
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Improvements List */}
          {comparison.improvements.length > 0 && (
            <div className="bg-[#0d1322] border border-emerald-500/30 rounded-xl overflow-hidden shadow">
              <div className="p-4 bg-emerald-500/10 border-b border-emerald-500/20 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-emerald-300">
                    Security Improvements ({comparison.improvements.length})
                  </h3>
                </div>
              </div>
              <div className="divide-y divide-slate-800">
                {comparison.improvements.map((imp) => (
                  <div key={imp.test_case_id} className="p-4">
                    <span className="font-mono text-xs font-bold text-slate-200">{imp.test_case_id}</span> - {imp.test_case_name}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
