import React, { useState, useEffect } from 'react';
import {
  ScrollText,
  Search,
  Filter,
  ShieldCheck,
  ShieldAlert,
  Lock,
  ChevronDown,
  ChevronRight,
  Eye,
  Hash,
  Clock,
  RotateCcw,
} from 'lucide-react';
import { AuditEvent } from '../types';
import { fetchAuditEvents } from '../services/api';

interface AuditTabProps {
  initialEventId?: string | null;
}

export const AuditTab: React.FC<AuditTabProps> = ({ initialEventId }) => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedTool, setSelectedTool] = useState<string>('');
  const [selectedDecision, setSelectedDecision] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string | null>(initialEventId || null);

  const loadEvents = async () => {
    setLoading(true);
    try {
      const data = await fetchAuditEvents({
        tool_name: selectedTool || undefined,
        decision: selectedDecision || undefined,
        limit: 100,
      });
      setEvents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [selectedTool, selectedDecision]);

  useEffect(() => {
    if (initialEventId) {
      setExpandedId(initialEventId);
    }
  }, [initialEventId]);

  const filteredEvents = events.filter((ev) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      ev.event_id.toLowerCase().includes(q) ||
      ev.tool_name.toLowerCase().includes(q) ||
      ev.reason.toLowerCase().includes(q) ||
      (ev.rule_id && ev.rule_id.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Header & Filters */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 shadow space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <ScrollText className="w-4 h-4 text-emerald-400" />
              <span>Sanitized Security Audit Log & Timeline</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Immutable structured audit events. All PII and credentials automatically redacted.
            </p>
          </div>
          <button
            onClick={loadEvents}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh Events</span>
          </button>
        </div>

        {/* Filter Controls */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Search box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              placeholder="Search by Event ID, reason, or rule..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-2 focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* Tool filter */}
          <select
            value={selectedTool}
            onChange={(e) => setSelectedTool(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Tools (read_file, query_database, send_email)</option>
            <option value="read_file">read_file</option>
            <option value="query_database">query_database</option>
            <option value="send_email">send_email</option>
          </select>

          {/* Decision filter */}
          <select
            value={selectedDecision}
            onChange={(e) => setSelectedDecision(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Decisions (ALLOW & DENY)</option>
            <option value="allow">ALLOW Only</option>
            <option value="deny">DENY Only</option>
          </select>
        </div>
      </div>

      {/* Audit Events List */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl overflow-hidden shadow">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-semibold text-white">Audit Event Stream</span>
          <span className="text-xs font-mono text-slate-400">
            {filteredEvents.length} Recorded Security Actions
          </span>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center text-slate-400 text-xs">
            {loading ? 'Loading audit records...' : 'No audit records match the current filters.'}
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {filteredEvents.map((ev) => {
              const isExpanded = expandedId === ev.event_id;
              return (
                <div key={ev.event_id} className="transition hover:bg-slate-800/20">
                  {/* Event summary row */}
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : ev.event_id)}
                    className="p-4 cursor-pointer flex flex-wrap items-center justify-between gap-3 select-none"
                  >
                    <div className="flex items-center gap-3">
                      {ev.decision === 'allow' ? (
                        <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <ShieldCheck className="w-4 h-4" />
                        </div>
                      ) : (
                        <div className="p-1.5 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20">
                          <ShieldAlert className="w-4 h-4" />
                        </div>
                      )}
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-300">{ev.event_id}</span>
                          <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-slate-800 text-indigo-300 border border-slate-700">
                            {ev.tool_name}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase ${
                              ev.decision === 'allow'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                            }`}
                          >
                            {ev.decision}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 mt-1">{ev.reason}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-slate-400 flex items-center gap-1 font-mono text-[11px]">
                        <Clock className="w-3 h-3" />
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {/* Expanded Event Details */}
                  {isExpanded && (
                    <div className="px-5 pb-5 pt-1 space-y-3 bg-slate-900/60 border-t border-slate-800/60">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        {/* Redacted arguments */}
                        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold">
                              Redacted Arguments
                            </span>
                            <span className="text-[10px] font-mono text-emerald-400">PII MASKED</span>
                          </div>
                          <pre className="bg-slate-950 p-2.5 rounded border border-slate-800/80 font-mono text-[11px] text-slate-300 overflow-x-auto">
                            {JSON.stringify(ev.redacted_arguments, null, 2)}
                          </pre>
                        </div>

                        {/* Gateway Evaluation & Hashes */}
                        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
                          <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold block">
                            Cryptographic Traceability & Policy Info
                          </span>
                          <div className="space-y-1 font-mono text-[11px] text-slate-300">
                            <p className="flex items-center gap-1 text-slate-400 truncate">
                              <Hash className="w-3.5 h-3.5 shrink-0" />
                              <span>Raw Hash: <strong className="text-slate-200">{ev.raw_arguments_hash}</strong></span>
                            </p>
                            <p>Policy ID: <strong className="text-indigo-400">{ev.policy_id || 'N/A'}</strong></p>
                            <p>Rule ID: <strong className="text-slate-200">{ev.rule_id || 'N/A'}</strong></p>
                            <p>
                              Executed: <strong className={ev.executed ? 'text-emerald-400' : 'text-slate-400'}>{ev.executed ? 'Yes' : 'No'}</strong>
                            </p>
                            <p>
                              Data Exposure Detected: <strong className={ev.data_exposure_detected ? 'text-rose-400' : 'text-emerald-400'}>{ev.data_exposure_detected ? 'Yes (LEAK)' : 'No (Protected)'}</strong>
                            </p>
                            {ev.violations && ev.violations.length > 0 && (
                              <p className="text-rose-400">Violations: {ev.violations.join(', ')}</p>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Execution Output (if any) */}
                      {ev.execution_output_redacted && (
                        <div>
                          <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">
                            Execution Output (Redacted)
                          </span>
                          <pre className="bg-slate-950 p-2.5 rounded border border-slate-800/80 font-mono text-[11px] text-emerald-300 overflow-x-auto max-h-40">
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
            })}
          </div>
        )}
      </div>
    </div>
  );
};
