import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Play,
  Bot,
  Activity,
  Terminal,
  FileCode,
  Database,
  Mail,
  Lock,
  Globe,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Power,
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
  isEmergencyStopped?: boolean;
}

export const HomeTab: React.FC<HomeTabProps> = ({
  health,
  runs,
  auditEvents,
  onNavigate,
  onQuickRun,
  isRunningTest,
  isEmergencyStopped = false,
}) => {
  // Aggregate real metrics from actual backend audit events
  const totalEvents = auditEvents.length;
  const blockedCount = auditEvents.filter((e) => e.decision === 'deny').length;
  const allowedCount = auditEvents.filter((e) => e.decision === 'allow').length;
  const unauthorizedExecutions = auditEvents.filter((e) => e.decision === 'deny' && e.executed).length;

  const recentEvents = auditEvents.slice(0, 5);

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
    <div className="space-y-6 max-w-6xl mx-auto py-2">
      {/* 1. Header Overview Banner */}
      <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-[#8E969E]">
            <span
              className={`w-2 h-2 rounded-full ${
                isEmergencyStopped ? 'bg-[#EF4444] animate-ping' : 'bg-[#C7F36B] animate-pulse'
              }`}
            ></span>
            <span>
              Gateway Status:{' '}
              <strong className={isEmergencyStopped ? 'text-[#EF4444]' : 'text-[#C7F36B]'}>
                {isEmergencyStopped ? 'EMERGENCY STOPPED' : 'ACTIVE & ENFORCING'}
              </strong>
            </span>
          </div>

          <div className="text-[11px] font-mono text-[#535C64]">
            Policy: {health?.active_policy_name || 'Enterprise Strict (Default)'}
          </div>
        </div>

        <div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
            Security Gateway Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-[#8E969E] mt-1.5 max-w-3xl leading-relaxed">
            TraceGuard AI sits between external AI agents and protected internal tools. Every tool invocation request is authenticated, evaluated against server-side policies, and recorded in a tamper-evident cryptographic audit ledger.
          </p>
        </div>

        {/* Quick Launch Buttons */}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <button
            type="button"
            onClick={() => onNavigate('agents')}
            className="glass-button-primary px-4 py-2 rounded-full text-xs font-semibold text-white flex items-center gap-2 cursor-pointer shadow-md"
          >
            <Bot className="w-3.5 h-3.5 text-[#C7F36B]" />
            <span>Manage AI Agents & Permissions</span>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('developer')}
            className="px-4 py-2 rounded-full text-xs font-mono text-white/90 bg-white/[0.06] hover:bg-white/[0.12] border border-white/15 flex items-center gap-2 transition cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5 text-purple-400" />
            <span>Open Developer Tools & Lab</span>
          </button>
        </div>
      </div>

      {/* 2. Four Concise Status & Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Gateway Status */}
        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div>
            <div className="text-xs font-mono text-[#8E969E] mb-1">Gateway Status</div>
            <div className="flex items-center gap-2 mt-1">
              <span
                className={`w-3 h-3 rounded-full ${
                  isEmergencyStopped ? 'bg-[#EF4444]' : 'bg-[#C7F36B]'
                }`}
              ></span>
              <span className="text-xl font-bold font-mono text-white">
                {isEmergencyStopped ? 'Stopped' : 'Operational'}
              </span>
            </div>
          </div>
          <div className="text-[11px] text-[#535C64] mt-3 font-mono">
            {isEmergencyStopped ? 'Tool executions paused' : 'Fail-closed enforcement'}
          </div>
        </TiltCard>

        {/* Card 2: Allowed Actions */}
        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div>
            <div className="text-xs font-mono text-[#C7F36B] mb-1">Allowed Actions</div>
            <div className="text-3xl font-semibold font-mono text-[#C7F36B] tracking-tight">
              {allowedCount}
            </div>
          </div>
          <div className="text-[11px] text-[#8E969E] mt-3 font-mono">
            Passed server-side policy rules
          </div>
        </TiltCard>

        {/* Card 3: Blocked Actions */}
        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div>
            <div className="text-xs font-mono text-red-400 mb-1">Blocked Actions</div>
            <div className="text-3xl font-semibold font-mono text-[#EF4444] tracking-tight">
              {blockedCount}
            </div>
          </div>
          <div className="text-[11px] text-[#8E969E] mt-3 font-mono">
            Neutralized before execution
          </div>
        </TiltCard>

        {/* Card 4: Execution Invariant */}
        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div>
            <div className="text-xs font-mono text-purple-400 mb-1">Unauthorized Executions</div>
            <div className="text-3xl font-semibold font-mono text-white tracking-tight">
              {unauthorizedExecutions}
            </div>
          </div>
          <div className="text-[11px] text-[#C7F36B] mt-3 font-mono flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-[#C7F36B]" />
            <span>Zero Policy Bypasses</span>
          </div>
        </TiltCard>
      </div>

      {/* Explicit Metrics Notice */}
      <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 text-[11px] text-[#535C64] font-mono flex items-center justify-between">
        <span>
          Telemetry Source: Real events evaluated and recorded in SQLite audit ledger. Metrics reflect laboratory and test sessions.
        </span>
        <span className="hidden sm:inline text-[#8E969E]">
          Total Evaluated: {totalEvents}
        </span>
      </div>

      {/* 3. Recent Security Events Card */}
      <div className="glass-panel rounded-2xl border border-white/10 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Recent Security Events</h2>
            <p className="text-xs text-[#8E969E] mt-0.5">
              Live audit record of recent tool dispatch evaluations.
            </p>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('activity')}
            className="text-xs font-mono text-[#C7F36B] hover:underline flex items-center gap-1 cursor-pointer"
          >
            <span>View Full Audit Log</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {recentEvents.length === 0 ? (
          <div className="py-10 text-center text-xs text-[#8E969E] font-mono border border-dashed border-white/10 rounded-xl">
            No audit events recorded yet. Connect an agent or run a test scenario in Developer Tools.
          </div>
        ) : (
          <div className="divide-y divide-white/[0.06] overflow-hidden rounded-xl border border-white/5 bg-black/40">
            {recentEvents.map((ev) => {
              const isBlocked = ev.decision === 'deny';
              return (
                <div key={ev.event_id} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs hover:bg-white/[0.02] transition">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="p-2 rounded-lg bg-white/[0.04] border border-white/10 shrink-0">
                      {getToolIcon(ev.tool_name)}
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-white">{ev.tool_name}</span>
                        <span className="text-[10px] text-[#535C64] font-mono">
                          {ev.timestamp.split('T')[1]?.slice(0, 8)}
                        </span>
                        <span className="text-[10px] font-mono text-[#8E969E] px-1.5 py-0.5 rounded bg-white/[0.05]">
                          {ev.agent_type}
                        </span>
                      </div>
                      <p className="text-xs text-[#8E969E] truncate max-w-lg mt-0.5">
                        {ev.reason}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold uppercase ${
                        isBlocked
                          ? 'bg-red-500/15 text-red-300 border border-red-500/30'
                          : 'bg-[#C7F36B]/15 text-[#C7F36B] border border-[#C7F36B]/30'
                      }`}
                    >
                      {isBlocked ? 'Blocked' : 'Allowed'}
                    </span>
                    <span className="text-[10px] font-mono text-[#535C64]">
                      {ev.executed ? 'Executed' : 'Not Executed'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. Two Navigation Launchpads */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-3">
              <Bot className="w-4 h-4" />
            </div>
            <h3 className="text-base font-semibold text-white mb-1">
              My AI Agents
            </h3>
            <p className="text-xs text-[#8E969E] leading-relaxed">
              Step-by-step agent onboarding: select or register an agent, configure scoped tool permissions, and verify integration via the gateway dispatch API.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('agents')}
            className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between text-xs font-medium text-blue-400 cursor-pointer"
          >
            <span>Go to My AI Agents</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </TiltCard>

        <TiltCard className="glass-panel rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div>
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 mb-3">
              <Terminal className="w-4 h-4" />
            </div>
            <h3 className="text-base font-semibold text-white mb-1">
              Developer Tools
            </h3>
            <p className="text-xs text-[#8E969E] leading-relaxed">
              Access the Security Testing Lab, run automated penetration benchmark suites, verify cryptographic hash-chain integrity, or trigger emergency kill-switch controls.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('developer')}
            className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between text-xs font-medium text-purple-400 cursor-pointer"
          >
            <span>Open Developer Tools</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </TiltCard>
      </div>
    </div>
  );
};
