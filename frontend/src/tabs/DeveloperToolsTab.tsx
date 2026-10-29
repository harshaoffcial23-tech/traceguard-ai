import React, { useState } from 'react';
import {
  Terminal,
  Play,
  Layers,
  Power,
  ShieldCheck,
  ShieldAlert,
  FileCode,
  RotateCcw,
  CheckCircle2,
  AlertOctagon,
  Lock,
  GitCompare,
  Sliders,
  Send,
} from 'lucide-react';
import { PolicySet, AuditChainVerificationResult, AgentDispatchResponse } from '../types';
import { PlaygroundTab } from './PlaygroundTab';
import { AdvancedTab } from './AdvancedTab';
import {
  verifyAuditChain,
  fetchEmergencyStop,
  setEmergencyStop,
  dispatchAgentTool,
} from '../services/api';

interface DeveloperToolsTabProps {
  policies: PolicySet[];
  initialSubTab?: 'playground' | 'benchmarks' | 'hash_chain' | 'kill_switch' | 'raw_dispatcher';
  onNavigateTab: (tab: string) => void;
  currentUser?: any;
}

export const DeveloperToolsTab: React.FC<DeveloperToolsTabProps> = ({
  policies,
  initialSubTab = 'playground',
  onNavigateTab,
  currentUser,
}) => {
  const [subTab, setSubTab] = useState<'playground' | 'benchmarks' | 'hash_chain' | 'kill_switch' | 'raw_dispatcher'>(
    initialSubTab
  );

  // Hash-Chain Verification State
  const [verifyingChain, setVerifyingChain] = useState<boolean>(false);
  const [chainResult, setChainResult] = useState<AuditChainVerificationResult | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);

  // Emergency Stop State
  const [emergencyStopped, setEmergencyStopped] = useState<boolean>(false);
  const [loadingKillSwitch, setLoadingKillSwitch] = useState<boolean>(false);
  const [killSwitchMsg, setKillSwitchMsg] = useState<string | null>(null);
  const [killSwitchError, setKillSwitchError] = useState<string | null>(null);

  // Raw JSON Dispatcher State
  const [rawAgentId, setRawAgentId] = useState<string>('standard_agent');
  const [rawToolName, setRawToolName] = useState<string>('read_file');
  const [rawArgsJson, setRawArgsJson] = useState<string>(
    JSON.stringify({ path: 'public/company_handbook.txt' }, null, 2)
  );
  const [rawAgentToken, setRawAgentToken] = useState<string>('tg_agent_dev_token_2026');
  const [rawDispatching, setRawDispatching] = useState<boolean>(false);
  const [rawResult, setRawResult] = useState<AgentDispatchResponse | null>(null);
  const [rawError, setRawError] = useState<string | null>(null);

  const handleVerifyLedger = async () => {
    setVerifyingChain(true);
    setChainError(null);
    setChainResult(null);
    try {
      const res = await verifyAuditChain();
      setChainResult(res);
    } catch (err: any) {
      setChainError(err.message || 'Failed to verify audit ledger.');
    } finally {
      setVerifyingChain(false);
    }
  };

  const handleToggleEmergencyStop = async () => {
    setLoadingKillSwitch(true);
    setKillSwitchMsg(null);
    setKillSwitchError(null);
    try {
      const nextState = !emergencyStopped;
      const res = await setEmergencyStop(nextState);
      setEmergencyStopped(res.emergency_stopped);
      setKillSwitchMsg(res.message || (nextState ? 'Kill-switch activated.' : 'Gateway resumed.'));
    } catch (err: any) {
      setKillSwitchError(err.message || 'Action failed: Admin privileges required.');
    } finally {
      setLoadingKillSwitch(false);
    }
  };

  const handleRawDispatch = async () => {
    setRawDispatching(true);
    setRawError(null);
    setRawResult(null);

    let parsedArgs: Record<string, any> = {};
    try {
      parsedArgs = JSON.parse(rawArgsJson);
    } catch (err: any) {
      setRawError('Malformed JSON arguments format. Please fix JSON syntax.');
      setRawDispatching(false);
      return;
    }

    try {
      const res = await dispatchAgentTool({
        agent_id: rawAgentId.trim(),
        tool_name: rawToolName.trim() || null,
        arguments: parsedArgs,
        correlation_id: `raw_dispatch_${Date.now()}`,
        agent_key: rawAgentToken.trim() || undefined,
      });
      setRawResult(res);
    } catch (err: any) {
      setRawError(err.message || 'Dispatch error');
    } finally {
      setRawDispatching(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto py-2">
      {/* Header Banner */}
      <div className="glass-panel rounded-2xl p-6 border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-purple-400 mb-2">
            <Terminal className="w-3.5 h-3.5" />
            <span>Developer & Security Operations</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold text-white tracking-tight">
            Developer Tools
          </h1>
          <p className="text-xs sm:text-sm text-[#8E969E] mt-1 max-w-2xl leading-relaxed">
            Advanced developer utilities: interactive penetration testing lab, automated benchmark suites, policy regression diffs, cryptographic hash-chain ledger verification, and operator emergency kill-switch.
          </p>
        </div>
      </div>

      {/* Sub-navigation pills */}
      <div className="flex flex-wrap items-center gap-2 border-b border-white/10 pb-3">
        <button
          type="button"
          onClick={() => setSubTab('playground')}
          className={`px-4 py-2 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-2 ${
            subTab === 'playground'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white bg-black/40'
          }`}
        >
          <Play className="w-3.5 h-3.5 text-[#C7F36B]" />
          <span>Security Testing Lab</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('benchmarks')}
          className={`px-4 py-2 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-2 ${
            subTab === 'benchmarks'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white bg-black/40'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-blue-400" />
          <span>Benchmarks & Policy Diff</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('hash_chain')}
          className={`px-4 py-2 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-2 ${
            subTab === 'hash_chain'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white bg-black/40'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>Audit Ledger Hash-Chain</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('kill_switch')}
          className={`px-4 py-2 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-2 ${
            subTab === 'kill_switch'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white bg-black/40'
          }`}
        >
          <Power className="w-3.5 h-3.5 text-red-400" />
          <span>Gateway Kill-Switch</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('raw_dispatcher')}
          className={`px-4 py-2 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-2 ${
            subTab === 'raw_dispatcher'
              ? 'bg-white/15 text-white border border-white/20 shadow-xs'
              : 'text-[#8E969E] hover:text-white bg-black/40'
          }`}
        >
          <Send className="w-3.5 h-3.5 text-purple-400" />
          <span>Raw JSON Dispatcher</span>
        </button>
      </div>

      {/* SUBTAB 1: Security Testing Lab */}
      {subTab === 'playground' && (
        <div className="space-y-4">
          <PlaygroundTab policies={policies} />
        </div>
      )}

      {/* SUBTAB 2: Benchmarks & Regression Diff */}
      {subTab === 'benchmarks' && (
        <div className="space-y-4">
          <AdvancedTab onNavigateTab={onNavigateTab} />
        </div>
      )}

      {/* SUBTAB 3: Cryptographic Audit Ledger Hash-Chain Verification */}
      {subTab === 'hash_chain' && (
        <div className="glass-panel rounded-2xl border border-white/10 p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">
                Cryptographic Audit Ledger Integrity Verification
              </h2>
              <p className="text-xs text-[#8E969E] mt-1 max-w-2xl leading-relaxed">
                TraceGuard AI cryptographically chains every audit event using SHA-256 hash digests. Each record incorporates the preceding record&apos;s hash digest. If any record is altered, deleted, or inserted out of band in the SQLite database, verification immediately fails and flags the exact record.
              </p>
            </div>

            <button
              type="button"
              onClick={handleVerifyLedger}
              disabled={verifyingChain}
              className="glass-button-primary px-5 py-2.5 rounded-full text-xs font-semibold text-white flex items-center gap-2 cursor-pointer disabled:opacity-50 shrink-0"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${verifyingChain ? 'animate-spin' : ''}`} />
              <span>{verifyingChain ? 'Verifying Hashes...' : 'Run Cryptographic Check'}</span>
            </button>
          </div>

          {chainError && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-300 flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />
              <span>{chainError}</span>
            </div>
          )}

          {chainResult && (
            <div className="p-5 rounded-xl bg-black border border-white/15 space-y-4 text-xs font-mono">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-[#8E969E]">Verification Status:</span>
                  <span
                    className={`px-3 py-1 rounded-full font-bold uppercase text-[11px] ${
                      chainResult.is_valid
                        ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        : 'bg-red-500/15 text-red-300 border border-red-500/30'
                    }`}
                  >
                    {chainResult.is_valid ? 'INTACT & VERIFIED' : 'TAMPER DETECTED'}
                  </span>
                </div>

                <div className="text-[11px] text-[#8E969E]">
                  Verified Records: <strong className="text-white">{chainResult.verified_events}</strong> of {chainResult.total_events}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-white/[0.03] border border-white/5 text-white/90">
                {chainResult.message}
              </div>

              {!chainResult.is_valid && chainResult.tampered_event_id && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/25 text-red-300">
                  Compromised Event ID: <code>{chainResult.tampered_event_id}</code> at index {chainResult.tampered_index}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 4: Gateway Emergency Kill-Switch */}
      {subTab === 'kill_switch' && (
        <div className="glass-panel rounded-2xl border border-white/10 p-6 space-y-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
              <Power className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Gateway Emergency Kill-Switch</h2>
              <p className="text-xs text-[#8E969E] mt-0.5">
                Atomic operational circuit-breaker. When activated, all protected tool execution requests are halted immediately by server-side policy.
              </p>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-black/60 border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs font-mono">
            <div>
              <span className="text-[#8E969E] block text-[11px]">Current Kill-Switch Status:</span>
              <span
                className={`text-base font-bold ${
                  emergencyStopped ? 'text-[#EF4444]' : 'text-[#C7F36B]'
                }`}
              >
                {emergencyStopped ? 'STOPPED (Tool Executions Blocked)' : 'OPERATIONAL (Normal Enforcement)'}
              </span>
            </div>

            <button
              type="button"
              onClick={handleToggleEmergencyStop}
              disabled={loadingKillSwitch}
              className={`px-5 py-2.5 rounded-full text-xs font-bold font-mono transition cursor-pointer disabled:opacity-50 ${
                emergencyStopped
                  ? 'bg-[#C7F36B] hover:bg-[#B8E85C] text-black shadow-lg'
                  : 'bg-red-500 hover:bg-red-600 text-white shadow-lg'
              }`}
            >
              {loadingKillSwitch
                ? 'Updating Circuit Breaker...'
                : emergencyStopped
                ? 'Resume Gateway Operations'
                : 'Activate Emergency Stop'}
            </button>
          </div>

          {killSwitchMsg && (
            <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-300">
              {killSwitchMsg}
            </div>
          )}

          {killSwitchError && (
            <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-300">
              {killSwitchError}
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 5: Raw JSON Dispatcher */}
      {subTab === 'raw_dispatcher' && (
        <div className="glass-panel rounded-2xl border border-white/10 p-6 space-y-5">
          <div>
            <h2 className="text-lg font-semibold text-white">Raw JSON Agent Tool Dispatcher</h2>
            <p className="text-xs text-[#8E969E] mt-0.5">
              Submit raw JSON payloads to <code>POST /api/v1/agent/dispatch</code> to test external agent integration contracts.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
            <div>
              <label className="text-[#8E969E] block mb-1">Agent ID:</label>
              <input
                type="text"
                value={rawAgentId}
                onChange={(e) => setRawAgentId(e.target.value)}
                className="w-full bg-black border border-white/15 focus:border-[#C7F36B] rounded-lg px-3 py-2 text-white"
              />
            </div>

            <div>
              <label className="text-[#8E969E] block mb-1">Tool Name:</label>
              <input
                type="text"
                value={rawToolName}
                onChange={(e) => setRawToolName(e.target.value)}
                className="w-full bg-black border border-white/15 focus:border-[#C7F36B] rounded-lg px-3 py-2 text-white"
              />
            </div>

            <div>
              <label className="text-[#8E969E] block mb-1">Agent Key (X-Agent-Key):</label>
              <input
                type="text"
                value={rawAgentToken}
                onChange={(e) => setRawAgentToken(e.target.value)}
                className="w-full bg-black border border-white/15 focus:border-[#C7F36B] rounded-lg px-3 py-2 text-white"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-mono text-[#8E969E] block mb-1">Tool Arguments (JSON):</label>
            <textarea
              rows={4}
              value={rawArgsJson}
              onChange={(e) => setRawArgsJson(e.target.value)}
              className="w-full bg-black border border-white/15 focus:border-[#C7F36B] rounded-xl p-3 text-xs font-mono text-white focus:outline-none"
            />
          </div>

          <button
            type="button"
            onClick={handleRawDispatch}
            disabled={rawDispatching}
            className="glass-button-primary px-5 py-2.5 rounded-full text-xs font-semibold text-white flex items-center gap-2 cursor-pointer disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            <span>{rawDispatching ? 'Dispatching...' : 'Dispatch Raw Request'}</span>
          </button>

          {rawError && (
            <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-300">
              {rawError}
            </div>
          )}

          {rawResult && (
            <div className="p-4 rounded-xl bg-black border border-white/15 space-y-2 text-xs font-mono">
              <div className="text-[#8E969E] text-[11px]">Dispatch Response:</div>
              <pre className="p-3 rounded-lg bg-white/[0.02] border border-white/5 text-emerald-300 overflow-x-auto max-h-60">
                {JSON.stringify(rawResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
