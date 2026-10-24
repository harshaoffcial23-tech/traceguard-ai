import React, { useState } from 'react';
import {
  Terminal,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Lock,
  ChevronDown,
  ChevronRight,
  Clock,
  Layers,
  Cpu,
  Eye,
  FileCode,
} from 'lucide-react';
import { TestRun, TestCaseResult } from '../types';

interface RunDetailsTabProps {
  runs: TestRun[];
  selectedRunId: string | null;
  onSelectRunId: (id: string) => void;
  onViewAuditEvent: (eventId: string) => void;
}

export const RunDetailsTab: React.FC<RunDetailsTabProps> = ({
  runs,
  selectedRunId,
  onSelectRunId,
  onViewAuditEvent,
}) => {
  const [filterMode, setFilterMode] = useState<'all' | 'failed' | 'malicious' | 'legitimate'>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const currentRun = runs.find((r) => r.id === selectedRunId) || (runs.length > 0 ? runs[0] : null);

  if (!currentRun) {
    return (
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-12 text-center text-slate-400 space-y-3">
        <Terminal className="w-10 h-10 mx-auto text-slate-600" />
        <h3 className="text-base font-semibold text-slate-300">No Test Run Selected</h3>
        <p className="text-xs text-slate-500 max-w-sm mx-auto">
          Execute a security benchmark suite or select a historical run to view detailed execution traces.
        </p>
      </div>
    );
  }

  const filteredResults = currentRun.results.filter((res) => {
    if (filterMode === 'failed') return !res.passed;
    if (filterMode === 'malicious') return res.is_malicious;
    if (filterMode === 'legitimate') return !res.is_malicious;
    return true;
  });

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="space-y-6">
      {/* Run Selector & Header Info */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 space-y-4 shadow">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                Run: {currentRun.id}
              </span>
              <span className="text-xs text-slate-400 flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" />
                {new Date(currentRun.started_at).toLocaleString()}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight">{currentRun.suite_name}</h2>
          </div>

          {/* Historical Runs Dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Select Run:</span>
            <select
              value={currentRun.id}
              onChange={(e) => onSelectRunId(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500"
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} ({r.policy_set_id} | {r.agent_type}) - {new Date(r.started_at).toLocaleTimeString()}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Badges / Metrics Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-3 pt-2 border-t border-slate-800/80">
          <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">Policy</span>
            <span className="text-xs font-mono font-bold text-slate-200 truncate block">
              {currentRun.policy_set_id}
            </span>
          </div>
          <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">Agent</span>
            <span className="text-xs font-mono font-bold text-cyan-300 capitalize block">
              {currentRun.agent_type}
            </span>
          </div>
          <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">Attack Block</span>
            <span className="text-xs font-mono font-bold text-emerald-400 block">
              {currentRun.metrics.attack_block_rate}%
            </span>
          </div>
          <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">Legit Allowed</span>
            <span className="text-xs font-mono font-bold text-indigo-400 block">
              {currentRun.metrics.legitimate_allow_rate}%
            </span>
          </div>
          <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">Data Leaks</span>
            <span className={`text-xs font-mono font-bold block ${currentRun.metrics.data_exposure_incidents === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
              {currentRun.metrics.data_exposure_incidents}
            </span>
          </div>
          <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">Accuracy</span>
            <span className="text-xs font-mono font-bold text-white block">
              {currentRun.metrics.accuracy}%
            </span>
          </div>
        </div>
      </div>

      {/* Filter Tabs & Test Results List */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl overflow-hidden shadow">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                filterMode === 'all' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({currentRun.results.length})
            </button>
            <button
              onClick={() => setFilterMode('failed')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                filterMode === 'failed' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Failed ({currentRun.results.filter((r) => !r.passed).length})
            </button>
            <button
              onClick={() => setFilterMode('malicious')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                filterMode === 'malicious' ? 'bg-amber-500/20 text-amber-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Malicious ({currentRun.results.filter((r) => r.is_malicious).length})
            </button>
            <button
              onClick={() => setFilterMode('legitimate')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                filterMode === 'legitimate' ? 'bg-indigo-500/20 text-indigo-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Legitimate ({currentRun.results.filter((r) => !r.is_malicious).length})
            </button>
          </div>

          <span className="text-xs text-slate-400">
            Showing {filteredResults.length} test traces
          </span>
        </div>

        {/* Results Accordion */}
        <div className="divide-y divide-slate-800/80">
          {filteredResults.map((res) => {
            const isExpanded = expandedId === res.test_case_id;
            return (
              <div key={res.test_case_id} className="transition hover:bg-slate-800/20">
                {/* Row Header */}
                <div
                  onClick={() => toggleExpand(res.test_case_id)}
                  className="p-4 cursor-pointer flex flex-wrap items-center justify-between gap-3 select-none"
                >
                  <div className="flex items-center gap-3">
                    {res.passed ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-300">{res.test_case_id}</span>
                        <span className="text-xs font-semibold text-white">{res.test_case_name}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">{res.prompt}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2 py-0.5 rounded font-mono text-[10px] uppercase ${
                        res.decision === 'allow'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}
                    >
                      GATEWAY: {res.decision}
                    </span>
                    <span className="text-xs font-mono text-slate-400">{res.duration_ms}ms</span>
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Trace Details */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-1 space-y-3 bg-slate-900/60 border-t border-slate-800/60">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      {/* Left: Input & Attempt */}
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
                        <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold block">
                          Attempted Invocation
                        </span>
                        <div className="space-y-1">
                          <p className="text-slate-300 font-mono">
                            Tool: <strong className="text-indigo-400">{res.tool_attempted || 'None'}</strong>
                          </p>
                          <p className="text-slate-400 text-[11px]">Prompt: {res.prompt}</p>
                          <p className="text-slate-400 text-[11px]">
                            Type: {res.is_malicious ? <strong className="text-rose-400">Malicious Adversarial Attack</strong> : <strong className="text-emerald-400">Legitimate Permitted Request</strong>}
                          </p>
                        </div>
                      </div>

                      {/* Right: Gateway Outcome */}
                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
                        <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold block">
                          Authorization Gateway Decision
                        </span>
                        <div className="space-y-1">
                          <p className="text-slate-300">
                            Decision: <strong className={res.decision === 'allow' ? 'text-emerald-400' : 'text-rose-400'}>{res.decision.toUpperCase()}</strong>
                          </p>
                          <p className="text-slate-300">
                            Tool Executed: <strong className={res.executed ? 'text-emerald-400' : 'text-slate-400'}>{res.executed ? 'Yes (Authorized)' : 'No (Blocked Before Execution)'}</strong>
                          </p>
                          <p className="text-slate-300">
                            Verified Data Exposure: <strong className={res.data_exposure_detected ? 'text-rose-400' : 'text-emerald-400'}>{res.data_exposure_detected ? 'Yes (LEAK DETECTED)' : 'No (Zero Exposure)'}</strong>
                          </p>
                          {res.failure_reason && (
                            <p className="text-rose-400 text-[11px]">Reason: {res.failure_reason}</p>
                          )}
                        </div>
                      </div>
                    </div>

                    {res.audit_event_id && (
                      <div className="flex items-center justify-between text-xs pt-1">
                        <span className="font-mono text-slate-400">Audit Event: {res.audit_event_id}</span>
                        <button
                          onClick={() => onViewAuditEvent(res.audit_event_id!)}
                          className="text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1 transition"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>View Full Sanitized Audit Record</span>
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
