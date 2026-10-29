import React, { useState, useEffect } from 'react';
import {
  Activity,
  Search,
  Filter,
  CheckCircle2,
  AlertOctagon,
  ChevronDown,
  ChevronRight,
  RotateCcw,
  FileCode,
  Database,
  Mail,
  Lock,
  Globe,
  Sliders,
  Terminal,
  ShieldAlert,
  Clock,
  AlertTriangle,
} from 'lucide-react';
import { AuditEvent, User } from '../types';
import { fetchAuditEvents } from '../services/api';

interface ActivityTabProps {
  initialEventId?: string | null;
  currentUser?: User | null;
  onOpenAuth?: () => void;
}

export const ActivityTab: React.FC<ActivityTabProps> = ({
  initialEventId,
  currentUser,
  onOpenAuth,
}) => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isGuestMode, setIsGuestMode] = useState<boolean>(!currentUser);
  const [filterDecision, setFilterDecision] = useState<'all' | 'blocked' | 'allowed' | 'exposure'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string | null>(initialEventId || null);

  const loadEvents = async () => {
    setLoading(true);
    try {
      const data = await fetchAuditEvents({ limit: 100 });
      setEvents(data);
      setIsGuestMode(false);
    } catch (err: any) {
      if (err?.status === 401 || err?.message?.includes('401') || err?.message?.includes('Unauthorized')) {
        setIsGuestMode(true);
      }
      console.warn('Audit events fetch notice:', err?.message || err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setIsGuestMode(!currentUser);
    loadEvents();
  }, [currentUser]);

  useEffect(() => {
    if (initialEventId) {
      setExpandedId(initialEventId);
    }
  }, [initialEventId]);

  const filteredEvents = events.filter((ev) => {
    if (filterDecision === 'blocked' && ev.decision !== 'deny') return false;
    if (filterDecision === 'allowed' && ev.decision !== 'allow') return false;
    if (filterDecision === 'exposure' && !ev.data_exposure_detected) return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchId = ev.event_id.toLowerCase().includes(q);
      const matchTool = ev.tool_name.toLowerCase().includes(q);
      const matchReason = ev.reason.toLowerCase().includes(q);
      const matchRule = ev.rule_id ? ev.rule_id.toLowerCase().includes(q) : false;
      return matchId || matchTool || matchReason || matchRule;
    }
    return true;
  });

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

  const renderDecisionBadge = (ev: AuditEvent) => {
    const dec = (ev.decision || '').toLowerCase();
    if (dec === 'deny') {
      return (
        <span className="text-[10px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded-full bg-red-500/15 text-red-300 border border-red-500/30">
          Blocked / Denied
        </span>
      );
    }
    if (dec === 'allow') {
      return (
        <span className="text-[10px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded-full bg-[#C7F36B]/15 text-[#C7F36B] border border-[#C7F36B]/30">
          Allowed
        </span>
      );
    }
    if (dec === 'timeout') {
      return (
        <span className="text-[10px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
          Timed Out
        </span>
      );
    }
    if (dec === 'error') {
      return (
        <span className="text-[10px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded-full bg-rose-500/15 text-rose-300 border border-rose-500/30">
          Failed
        </span>
      );
    }
    if (dec === 'no_action') {
      return (
        <span className="text-[10px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded-full bg-zinc-500/15 text-zinc-300 border border-zinc-500/30">
          No Action
        </span>
      );
    }
    return (
      <span className="text-[10px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30">
        Requested
      </span>
    );
  };

  const renderExecutionBadge = (ev: AuditEvent) => {
    const dec = (ev.decision || '').toLowerCase();
    if (ev.executed) {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          Executed
        </span>
      );
    }
    if (dec === 'timeout') {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20">
          Timed Out
        </span>
      );
    }
    if (dec === 'error') {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20">
          Failed
        </span>
      );
    }
    return (
      <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-white/[0.04] text-[#8E969E] border border-white/10">
        Not Executed
      </span>
    );
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto py-2">
      {/* 1. Header & Controls */}
      <div className="glass-panel rounded-2xl p-6 border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-[#8E969E] mb-2">
            <Activity className="w-3.5 h-3.5 text-[#C7F36B]" />
            <span>Cryptographic Telemetry Ledger</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold text-white tracking-tight">
            Activity & Security Audit Log
          </h1>
          <p className="text-xs sm:text-sm text-[#8E969E] mt-1 max-w-3xl leading-relaxed">
            Tamper-evident record of all agent tool invocations, policy evaluations, and data exposure redacting. Each audit event is cryptographically linked to its predecessor via a SHA-256 hash digest (hash chain), ensuring that any database modification, deletion, or out-of-band insertion immediately breaks verification.
          </p>
        </div>

        <button
          type="button"
          onClick={loadEvents}
          className="glass-button-secondary px-4 py-2 rounded-full text-xs font-mono text-white/80 hover:text-white transition flex items-center gap-2 cursor-pointer self-start sm:self-auto shrink-0"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Refresh Feed</span>
        </button>
      </div>

      {/* Guest Mode Informational Banner */}
      {isGuestMode && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/25 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5 text-amber-200">
            <Lock className="w-4 h-4 shrink-0 text-amber-400" />
            <span>
              Viewing in guest exploration mode. Audit events are protected by operational RBAC. Please sign in as an Operator to inspect the live audit log.
            </span>
          </div>
          {onOpenAuth && (
            <button
              type="button"
              onClick={onOpenAuth}
              className="px-3.5 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/30 font-mono text-[11px] font-medium shrink-0 transition cursor-pointer"
            >
              Sign In as Operator &rarr;
            </button>
          )}
        </div>
      )}

      {/* 2. Filters & Search Bar */}
      <div className="glass-panel rounded-2xl border border-white/10 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          {/* Decision Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setFilterDecision('all')}
              className={`px-3.5 py-1.5 rounded-full text-xs font-mono transition cursor-pointer border ${
                filterDecision === 'all'
                  ? 'bg-white/15 text-white border-white/30 shadow-xs'
                  : 'bg-black/40 text-[#8E969E] hover:text-white border-white/5'
              }`}
            >
              All Actions ({events.length})
            </button>

            <button
              type="button"
              onClick={() => setFilterDecision('blocked')}
              className={`px-3.5 py-1.5 rounded-full text-xs font-mono transition cursor-pointer border ${
                filterDecision === 'blocked'
                  ? 'bg-red-500/20 text-red-300 border-red-500/40 shadow-xs'
                  : 'bg-black/40 text-[#8E969E] hover:text-white border-white/5'
              }`}
            >
              Blocked / Denied ({events.filter((e) => e.decision === 'deny').length})
            </button>

            <button
              type="button"
              onClick={() => setFilterDecision('allowed')}
              className={`px-3.5 py-1.5 rounded-full text-xs font-mono transition cursor-pointer border ${
                filterDecision === 'allowed'
                  ? 'bg-[#C7F36B]/20 text-[#C7F36B] border-[#C7F36B]/40 shadow-xs'
                  : 'bg-black/40 text-[#8E969E] hover:text-white border-white/5'
              }`}
            >
              Allowed ({events.filter((e) => e.decision === 'allow').length})
            </button>

            <button
              type="button"
              onClick={() => setFilterDecision('exposure')}
              className={`px-3.5 py-1.5 rounded-full text-xs font-mono transition cursor-pointer border ${
                filterDecision === 'exposure'
                  ? 'bg-red-500/20 text-red-300 border-red-500/40 shadow-xs'
                  : 'bg-black/40 text-[#8E969E] hover:text-white border-white/5'
              }`}
            >
              Exposure Flagged ({events.filter((e) => e.data_exposure_detected).length})
            </button>
          </div>

          {/* Search Input */}
          <div className="relative min-w-[240px]">
            <Search className="w-3.5 h-3.5 absolute left-3.5 top-3 text-[#535C64]" />
            <input
              type="text"
              placeholder="Filter by tool or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-black/80 border border-white/10 focus:border-[#C7F36B] rounded-xl pl-9 pr-3.5 py-2 text-xs text-white font-mono focus:outline-none transition"
            />
          </div>
        </div>
      </div>

      {/* 3. Event Timeline List */}
      <div className="glass-panel rounded-2xl border border-white/10 divide-y divide-white/[0.06] overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs text-[#8E969E] font-mono">
            Loading cryptographic audit telemetry...
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="p-12 text-center text-xs text-[#8E969E] font-mono">
            {isGuestMode
              ? 'No audit events visible in guest mode. Sign in with an Operator role to inspect all persistent audit records.'
              : 'No audit events match the selected criteria.'}
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isExpanded = expandedId === ev.event_id;

            return (
              <div key={ev.event_id} className="p-4 sm:p-5 transition hover:bg-white/[0.02]">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  {/* Left: Tool and Reason */}
                  <div className="flex items-start gap-3.5 min-w-0">
                    <div className="p-2 rounded-xl bg-white/[0.04] border border-white/10 mt-0.5 shrink-0">
                      {getToolIcon(ev.tool_name)}
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-mono text-xs font-semibold text-white">
                          {ev.tool_name}
                        </span>
                        <span className="text-[10px] font-mono text-[#535C64]">
                          {ev.timestamp.split('T')[1]?.slice(0, 8)}
                        </span>
                        <span className="text-[10px] font-mono text-[#535C64] hidden md:inline">
                          ({ev.event_id})
                        </span>
                      </div>

                      <p className="text-xs text-[#8E969E] mt-1 leading-relaxed font-sans">
                        {ev.reason}
                      </p>
                    </div>
                  </div>

                  {/* Right: Badges & Expand Trigger */}
                  <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto flex-wrap">
                    {renderDecisionBadge(ev)}
                    {renderExecutionBadge(ev)}

                    {ev.data_exposure_detected && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-red-500/15 text-red-300 border border-red-500/30">
                        Data Redacted
                      </span>
                    )}

                    <button
                      type="button"
                      onClick={() => setExpandedId(isExpanded ? null : ev.event_id)}
                      className="px-2.5 py-1 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-[11px] font-mono text-[#8E969E] hover:text-white flex items-center gap-1 transition cursor-pointer"
                    >
                      <span>{isExpanded ? 'Hide' : 'Details'}</span>
                      {isExpanded ? (
                        <ChevronDown className="w-3 h-3" />
                      ) : (
                        <ChevronRight className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Expandable Technical Details Drawer */}
                {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-white/10 space-y-3 text-xs font-mono">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-[#8E969E] text-[11px]">
                      <div className="bg-black/60 p-2.5 rounded-lg border border-white/5">
                        <span className="text-[#535C64] block text-[10px]">Rule ID:</span>
                        <span className="text-white">{ev.rule_id || 'DEFAULT_RULE'}</span>
                      </div>
                      <div className="bg-black/60 p-2.5 rounded-lg border border-white/5">
                        <span className="text-[#535C64] block text-[10px]">Policy ID:</span>
                        <span className="text-white">{ev.policy_id || 'N/A'}</span>
                      </div>
                      <div className="bg-black/60 p-2.5 rounded-lg border border-white/5">
                        <span className="text-[#535C64] block text-[10px]">SHA-256 Arg Hash:</span>
                        <span className="text-[#C7F36B] truncate block">{ev.raw_arguments_hash || 'N/A'}</span>
                      </div>
                    </div>

                    {/* Redacted arguments JSON */}
                    <div>
                      <div className="text-[11px] text-[#8E969E] mb-1">
                        Sanitized Arguments Evaluated by Gateway:
                      </div>
                      <pre className="p-3 rounded-xl bg-black border border-white/10 text-[11px] text-white/90 overflow-x-auto">
                        {JSON.stringify(ev.redacted_arguments, null, 2)}
                      </pre>
                    </div>

                    {/* Tool output if allowed */}
                    {ev.execution_output_redacted && (
                      <div>
                        <div className="text-[11px] text-[#8E969E] mb-1">Sanitized Execution Output:</div>
                        <pre className="p-3 rounded-xl bg-black border border-white/10 text-[11px] text-emerald-300 overflow-x-auto max-h-36">
                          {typeof ev.execution_output_redacted === 'object'
                            ? JSON.stringify(ev.execution_output_redacted, null, 2)
                            : String(ev.execution_output_redacted)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
