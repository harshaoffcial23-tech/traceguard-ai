import React from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Layers,
  Terminal,
  FileCheck2,
  GitCompare,
  ScrollText,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { SystemHealth } from '../types';

interface NavbarProps {
  health: SystemHealth | null;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRefreshHealth: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  health,
  activeTab,
  setActiveTab,
  onRefreshHealth,
}) => {
  const tabs = [
    { id: 'overview', label: 'Overview', icon: Shield },
    { id: 'suites', label: 'Test Suites', icon: FileCheck2 },
    { id: 'run_details', label: 'Run Details', icon: Terminal },
    { id: 'playground', label: 'Live Playground', icon: Cpu },
    { id: 'policies', label: 'Policy Engine', icon: Layers },
    { id: 'audit', label: 'Audit Timeline', icon: ScrollText },
    { id: 'regression', label: 'Regression Diff', icon: GitCompare },
    { id: 'findings', label: 'OWASP Findings', icon: AlertTriangle },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0b101d]/90 backdrop-blur sticky top-0 z-50 px-6 py-3">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-indigo-500/20 to-emerald-500/20 border border-emerald-500/30 rounded-lg flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg text-slate-100 tracking-tight">TraceGuard AI</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                v1.0.0
              </span>
            </div>
            <p className="text-xs text-slate-400">Tool-Use Security Gateway & Attack Benchmark</p>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="flex items-center gap-3 text-xs">
          {health ? (
            <>
              {/* Backend status */}
              <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 px-2.5 py-1 rounded-md text-slate-300">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Gateway: <strong className="text-emerald-400">Online</strong></span>
              </div>

              {/* Active policy */}
              <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 px-2.5 py-1 rounded-md text-slate-300">
                <Shield className="w-3.5 h-3.5 text-indigo-400" />
                <span>Policy: <strong className="text-indigo-300">{health.active_policy_name || 'Strict Zero-Trust'}</strong></span>
              </div>

              {/* Groq Adapter status */}
              <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 px-2.5 py-1 rounded-md text-slate-300">
                <Cpu className="w-3.5 h-3.5 text-slate-400" />
                <span>Groq: {health.groq_configured ? (
                  <strong className="text-emerald-400">Ready</strong>
                ) : (
                  <strong className="text-amber-400" title="Offline mock mode active">Mock Lab</strong>
                )}</span>
              </div>
            </>
          ) : (
            <div className="flex items-center gap-1.5 bg-rose-500/10 border border-rose-500/30 px-2.5 py-1 rounded-md text-rose-400">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Connecting to Gateway...</span>
            </div>
          )}

          <button
            onClick={onRefreshHealth}
            title="Refresh System Status"
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded-md hover:border-slate-700 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Nav Tabs */}
      <div className="max-w-7xl mx-auto mt-3 flex items-center gap-1 overflow-x-auto pb-1 scrollbar-thin">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-all ${
                isActive
                  ? 'bg-slate-800 text-emerald-400 border border-slate-700 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
