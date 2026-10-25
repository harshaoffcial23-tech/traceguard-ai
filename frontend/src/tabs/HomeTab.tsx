import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Play,
  Bot,
  Activity,
  Layers,
  FileCode,
  Database,
  Mail,
  AlertTriangle,
  Lock,
  Cpu,
  Zap,
  Globe,
  Sliders,
  CheckCircle2,
} from 'lucide-react';
import { SystemHealth, TestRun, AuditEvent } from '../types';
import { TiltCard } from '../components/TiltCard';

interface HomeTabProps {
  health: SystemHealth | null;
  runs: TestRun[];
  auditEvents: AuditEvent[];
  onNavigate: (tab: string) => void;
  onQuickRun: () => void;
  isRunningTest: boolean;
}

export const HomeTab: React.FC<HomeTabProps> = ({
  health,
  runs,
  auditEvents,
  onNavigate,
  onQuickRun,
  isRunningTest,
}) => {
  // Aggregate real metrics from actual backend audit events and test runs
  const totalEvents = auditEvents.length;
  const blockedCount = auditEvents.filter((e) => e.decision === 'deny').length;
  const allowedCount = auditEvents.filter((e) => e.decision === 'allow').length;
  const exposureCount = auditEvents.filter((e) => e.data_exposure_detected).length;

  const latestRun = runs.length > 0 ? runs[0] : null;
  const recentEvents = auditEvents.slice(0, 6);

  const getToolIcon = (tool: string) => {
    switch (tool) {
      case 'read_file':
        return <FileCode className="w-3.5 h-3.5 text-purple-400" />;
      case 'query_database':
        return <Database className="w-3.5 h-3.5 text-blue-400" />;
      case 'send_email':
        return <Mail className="w-3.5 h-3.5 text-pink-400" />;
      case 'tavily_search':
        return <Globe className="w-3.5 h-3.5 text-emerald-400" />;
      default:
        return <Lock className="w-3.5 h-3.5 text-[#8E969E]" />;
    }
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto py-2">
      {/* 1. Futuristic Hero Banner */}
      <div className="glass-panel rounded-2xl p-6 sm:p-8 relative overflow-hidden border border-white/10">
        <div className="relative z-10 max-w-3xl space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-[#8E969E]">
            <span className="w-2 h-2 rounded-full bg-[#C7F36B] animate-pulse"></span>
            <span>Gateway Runtime Status: Enforcing (Deny-by-Default)</span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
            TraceGuard Zero-Trust Gateway Console
          </h1>

          <p className="text-sm text-[#8E969E] leading-relaxed">
            Positioned out-of-band between autonomous AI agents and protected enterprise tools. Untrusted agent outputs and poisoned retrieved data are intercepted, parsed into AST invariants, and validated before any external action can execute.
          </p>
        </div>

        {/* Status Strip */}
        <div className="mt-6 pt-5 border-t border-white/10 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-6">
            <div className="flex items-center gap-2">
              <span className="text-[#8E969E]">Active Policy:</span>
              <span className="text-[#C7F36B] font-semibold">
                {health?.active_policy_name || 'Enterprise Strict Zero-Trust'}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[#8E969E]">Controlled Tools:</span>
              <span className="text-white">
                read_file, query_database, send_email, tavily_search
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[#8E969E]">Storage:</span>
              <span className="text-white">SQLite WAL (Concurrent)</span>
            </div>
          </div>

          <div className="text-[11px] text-[#535C64]">
            Synthetic Security Lab · Deterministic Verification
          </div>
        </div>
      </div>

      {/* 2. Four 3D Tilt Metrics Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div className="text-xs font-mono text-[#8E969E] mb-2">Actions Evaluated</div>
          <div className="text-3xl font-semibold font-mono text-white tracking-tight">{totalEvents}</div>
          <div className="text-[11px] text-[#535C64] mt-2 font-mono">Attempted tool invocations</div>
        </TiltCard>

        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div className="text-xs font-mono text-red-400 mb-2">Unauthorized Blocked</div>
          <div className="text-3xl font-semibold font-mono text-[#EF4444] tracking-tight">{blockedCount}</div>
          <div className="text-[11px] text-red-400/60 mt-2 font-mono">Neutralized before execution</div>
        </TiltCard>

        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div className="text-xs font-mono text-[#C7F36B] mb-2">Authorized Allowed</div>
          <div className="text-3xl font-semibold font-mono text-[#C7F36B] tracking-tight">{allowedCount}</div>
          <div className="text-[11px] text-[#C7F36B]/60 mt-2 font-mono">Passed security invariants</div>
        </TiltCard>

        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div className="text-xs font-mono text-purple-400 mb-2">Exposure Incidents</div>
          <div className={`text-3xl font-semibold font-mono tracking-tight ${exposureCount > 0 ? 'text-[#EF4444]' : 'text-white'}`}>
            {exposureCount}
          </div>
          <div className="text-[11px] text-[#535C64] mt-2 font-mono">
            {exposureCount === 0 ? 'Zero data leaks detected' : 'Flagged & masked'}
          </div>
        </TiltCard>
      </div>

      {/* 3. Three Primary Interactive Launchpads */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Launchpad 1: Security Playground */}
        <TiltCard className="glass-panel rounded-2xl p-6 border border-white/10 flex flex-col justify-between group">
          <div>
            <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-[#C7F36B] mb-4">
              <Play className="w-5 h-5 fill-current" />
            </div>
            <h3 className="text-lg font-semibold text-white group-hover:text-[#C7F36B] transition mb-1.5">
              Security Playground
            </h3>
            <p className="text-xs text-[#8E969E] leading-relaxed">
              Test custom model prompts with adversarial payloads. Watch the gateway validate tool arguments and block SQL injections, path escapes, and egress breaches.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('playground')}
            className="mt-5 pt-3 border-t border-white/10 flex items-center justify-between text-xs font-medium text-[#C7F36B] cursor-pointer"
          >
            <span>Open Playground</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </button>
        </TiltCard>

        {/* Launchpad 2: Autonomous Agent Demo */}
        <TiltCard className="glass-panel rounded-2xl p-6 border border-white/10 flex flex-col justify-between group">
          <div>
            <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-blue-400 mb-4">
              <Bot className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-white group-hover:text-blue-300 transition mb-1.5">
              Agent Loop Simulation
            </h3>
            <p className="text-xs text-[#8E969E] leading-relaxed">
              Run an autonomous multi-step reasoning loop. Observe the agent attempt an unsafe action, receive an out-of-band rejection, and gracefully continue execution.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('agent_demo')}
            className="mt-5 pt-3 border-t border-white/10 flex items-center justify-between text-xs font-medium text-blue-400 cursor-pointer"
          >
            <span>Run Agent Loop</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </button>
        </TiltCard>

        {/* Launchpad 3: Audit Activity & Telemetry */}
        <TiltCard className="glass-panel rounded-2xl p-6 border border-white/10 flex flex-col justify-between group">
          <div>
            <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-purple-400 mb-4">
              <Activity className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-white group-hover:text-purple-300 transition mb-1.5">
              Activity & Audit Stream
            </h3>
            <p className="text-xs text-[#8E969E] leading-relaxed">
              Explore cryptographically chained audit events. Inspect full payload hashes, sanitized inputs, evaluated rules, and execution timestamps.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('activity')}
            className="mt-5 pt-3 border-t border-white/10 flex items-center justify-between text-xs font-medium text-purple-400 cursor-pointer"
          >
            <span>Inspect Audit Log</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </button>
        </TiltCard>
      </div>

      {/* 4. Live Gateway Activity Feed */}
      <div className="glass-panel rounded-2xl border border-white/10 p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-base font-semibold text-white">Live Invariant Enforcement Stream</h3>
            <p className="text-xs text-[#8E969E] mt-0.5">Real-time tool invocation attempts evaluated by the security gateway.</p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('activity')}
            className="text-xs font-mono text-[#C7F36B] hover:underline flex items-center gap-1.5 cursor-pointer"
          >
            <span>Full Audit Log</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        {recentEvents.length === 0 ? (
          <div className="py-12 text-center text-xs text-[#8E969E] font-mono">
            No gateway events recorded yet. Run a test in the Playground or trigger a quick benchmark run.
          </div>
        ) : (
          <div className="divide-y divide-white/[0.06]">
            {recentEvents.map((ev) => {
              const isBlocked = ev.decision === 'deny';
              return (
                <div key={ev.event_id} className="py-3.5 flex items-center justify-between gap-4 text-xs">
                  <div className="flex items-center gap-3.5 min-w-0">
                    <div className="p-2 rounded-xl bg-white/[0.04] border border-white/10">
                      {getToolIcon(ev.tool_name)}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2.5">
                        <span className="font-mono font-semibold text-white">{ev.tool_name}</span>
                        <span className="text-[10px] text-[#535C64] font-mono">
                          {ev.timestamp.split('T')[1]?.slice(0, 8)}
                        </span>
                      </div>
                      <p className="text-xs text-[#8E969E] truncate max-w-xl mt-0.5 font-sans">
                        {ev.reason}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span
                      className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-semibold uppercase tracking-wider ${
                        isBlocked
                          ? 'bg-red-500/15 text-red-300 border border-red-500/30'
                          : 'bg-[#C7F36B]/15 text-[#C7F36B] border border-[#C7F36B]/30'
                      }`}
                    >
                      {isBlocked ? 'Blocked' : 'Allowed'}
                    </span>
                    <span className="text-[10px] font-mono text-[#535C64] hidden sm:inline">
                      {ev.executed ? 'Executed' : 'Pre-empted'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 5. Quick Benchmark Execution Callout */}
      <div className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <div className="text-white font-medium">Core Security Benchmark Suite (98 Invariant Tests)</div>
            <div className="text-[#8E969E] text-[11px]">
              Execute automated adversarial penetration scenarios and generate compliance scorecards.
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onQuickRun}
            disabled={isRunningTest}
            className="glass-button-primary px-4 py-2 rounded-full text-xs font-semibold text-white flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            {isRunningTest ? (
              <>
                <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                <span>Executing Suite...</span>
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5 text-[#C7F36B]" />
                <span>Run Quick Test</span>
              </>
            )}
          </button>
          <button
            type="button"
            onClick={() => onNavigate('advanced')}
            className="glass-button-secondary px-3.5 py-2 rounded-full text-xs font-medium text-[#8E969E] hover:text-white cursor-pointer"
          >
            Advanced Suites →
          </button>
        </div>
      </div>
    </div>
  );
};
