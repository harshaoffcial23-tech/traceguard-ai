import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Lock,
  FileCheck2,
  ExternalLink,
  CheckCircle2,
} from 'lucide-react';
import { FindingsSummary } from '../types';
import { fetchFindings } from '../services/api';

export const FindingsTab: React.FC = () => {
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetchFindings()
      .then((data) => setSummary(data))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 shadow space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-emerald-400" />
              <span>OWASP Top 10 for LLMs — Threat Model & Findings</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Continuous validation of agent security posture against standardized vulnerability classes.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
              ALL CATEGORIES PROTECTED
            </span>
          </div>
        </div>

        {/* Aggregate Stats */}
        {summary && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-mono block">Audit Events Logged</span>
              <span className="text-base font-bold text-white font-mono">{summary.total_audit_events}</span>
            </div>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-mono block">Threat Actions Blocked</span>
              <span className="text-base font-bold text-emerald-400 font-mono">{summary.total_blocked_actions}</span>
            </div>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-mono block">Authorized Tasks Allowed</span>
              <span className="text-base font-bold text-indigo-400 font-mono">{summary.total_allowed_actions}</span>
            </div>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-mono block">Data Leaks Prevented</span>
              <span className="text-base font-bold text-emerald-400 font-mono">
                {summary.total_exposure_incidents === 0 ? 'Zero Incidents' : `${summary.total_exposure_incidents} Incidents`}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* OWASP Cards List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {summary?.owasp_top_10.map((item) => (
          <div
            key={item.id}
            className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 space-y-3 relative overflow-hidden shadow hover:border-slate-700 transition"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 text-indigo-300 border border-slate-700">
                  {item.id}
                </span>
                <h3 className="text-sm font-bold text-white">{item.name}</h3>
              </div>
              <span
                className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase ${
                  item.severity === 'CRITICAL'
                    ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                }`}
              >
                {item.severity}
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">{item.description}</p>

            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-1">
              <span className="text-[10px] font-mono uppercase text-emerald-400 font-semibold block">
                Gateway Enforcement Control
              </span>
              <p className="text-xs text-slate-400 leading-relaxed">{item.mitigation}</p>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-[11px]">
              <span className="text-slate-400">
                Validated By: <code className="text-slate-200 font-mono">{item.test_cases.join(', ')}</code>
              </span>
              <span className="flex items-center gap-1 text-emerald-400 font-mono font-semibold">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{item.status}</span>
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
