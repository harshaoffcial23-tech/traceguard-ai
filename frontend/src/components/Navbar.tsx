import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Play,
  Bot,
  Activity,
  Layers,
  RotateCcw,
  Home,
  LogIn,
  LogOut,
  User as UserIcon,
  Shield,
  ArrowLeft,
} from 'lucide-react';
import { SystemHealth, User } from '../types';

interface NavbarProps {
  health: SystemHealth | null;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRefreshHealth: () => void;
  isEmergencyStopped?: boolean;
  currentUser: User | null;
  onOpenLogin: () => void;
  onOpenRegister: () => void;
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  health,
  activeTab,
  setActiveTab,
  onRefreshHealth,
  isEmergencyStopped = false,
  currentUser,
  onOpenLogin,
  onOpenRegister,
  onLogout,
}) => {
  const primaryTabs = [
    { id: 'home', label: 'Overview', icon: Home },
    { id: 'playground', label: 'Security Playground', icon: Play },
    { id: 'agent_demo', label: 'Agent Demo', icon: Bot },
    { id: 'activity', label: 'Activity & Audit', icon: Activity },
  ];

  return (
    <header className="sticky top-0 z-50 w-full backdrop-blur-xl bg-black/75 border-b border-white/[0.08] px-4 sm:px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Brand & Identity */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setActiveTab('landing')}
              title="Return to Public Landing Page"
              className="flex items-center gap-2.5 text-left group cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/40 rounded-lg p-1"
            >
              <div className="w-8 h-8 rounded-lg bg-white/[0.05] border border-white/15 flex items-center justify-center text-white group-hover:border-white/30 group-hover:bg-white/[0.1] transition shadow-xs">
                <Shield className="w-4 h-4 text-[#C7F36B]" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm text-white tracking-tight group-hover:text-white/90 transition">
                    TraceGuard AI
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/[0.05] text-[#8E969E] border border-white/10">
                    Console
                  </span>
                </div>
                <p className="text-[11px] text-[#8E969E] -mt-0.5">Zero-Trust Agent Gateway</p>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('landing')}
              className="hidden lg:flex items-center gap-1 text-[11px] font-mono text-[#8E969E] hover:text-white px-2 py-1 rounded bg-white/[0.03] border border-white/5 transition cursor-pointer"
              title="Back to Landing Page"
            >
              <ArrowLeft className="w-3 h-3" />
              <span>Landing</span>
            </button>
          </div>

          {/* Mobile Right Controls */}
          <div className="flex md:hidden items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                isEmergencyStopped ? 'bg-[#EF4444] animate-ping' : 'bg-[#C7F36B]'
              }`}
            ></span>
            {currentUser ? (
              <button
                type="button"
                onClick={onLogout}
                title="Log out"
                className="p-1.5 text-[#8E969E] hover:text-[#EF4444] rounded bg-white/[0.05] border border-white/10"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button
                type="button"
                onClick={onOpenLogin}
                className="px-3 py-1 text-xs font-semibold rounded-full bg-white text-black"
              >
                Log In
              </button>
            )}
          </div>
        </div>

        {/* 4 Primary Navigation Destinations + Advanced Pill */}
        <nav className="flex flex-wrap items-center gap-1.5 p-1 rounded-full liquid-pill" aria-label="Workspace Navigation">
          {primaryTabs.map((t) => {
            const Icon = t.icon;
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTab(t.id)}
                className={`px-3.5 py-1.5 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-white/15 text-white shadow-xs border border-white/20'
                    : 'text-[#8E969E] hover:text-white hover:bg-white/[0.05]'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-[#C7F36B]' : 'text-[#8E969E]'}`} />
                <span>{t.label}</span>
              </button>
            );
          })}

          {/* Advanced Section Tab */}
          <div className="h-4 w-[1px] bg-white/10 mx-1 hidden sm:block"></div>

          <button
            type="button"
            onClick={() => setActiveTab('advanced')}
            className={`px-3.5 py-1.5 rounded-full text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'advanced'
                ? 'bg-white/15 text-white shadow-xs border border-white/20'
                : 'text-[#8E969E] hover:text-white hover:bg-white/[0.05]'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-purple-400" />
            <span>Benchmarks</span>
          </button>
        </nav>

        {/* Right Status Indicator, User Profile & Auth Controls */}
        <div className="hidden md:flex items-center gap-3 text-xs">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.04] border border-white/10">
            <span
              className={`w-2 h-2 rounded-full ${
                isEmergencyStopped ? 'bg-[#EF4444] animate-ping' : 'bg-[#C7F36B]'
              }`}
            ></span>
            <span className="text-[11px] font-mono text-[#8E969E]">
              Gateway:{' '}
              <strong className={isEmergencyStopped ? 'text-[#EF4444]' : 'text-[#C7F36B]'}>
                {isEmergencyStopped ? 'STOPPED' : 'Active'}
              </strong>
            </span>
          </div>

          <button
            type="button"
            onClick={onRefreshHealth}
            title="Refresh System Health Status"
            className="p-2 text-[#8E969E] hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 rounded-full transition cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          {/* User Account Controls */}
          <div className="h-4 w-[1px] bg-white/10"></div>

          {currentUser ? (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.04] border border-white/10">
                <UserIcon className="w-3.5 h-3.5 text-[#C7F36B]" />
                <span className="text-white font-medium max-w-[120px] truncate">
                  {currentUser.full_name}
                </span>
                <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded-full bg-white/10 text-[#8E969E] border border-white/10">
                  {currentUser.role}
                </span>
              </div>
              <button
                type="button"
                onClick={onLogout}
                title="Log out of gateway"
                className="p-2 text-[#8E969E] hover:text-[#EF4444] bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 rounded-full transition cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onOpenLogin}
                className="glass-button-secondary px-3.5 py-1.5 rounded-full text-xs font-medium text-white/80 hover:text-white transition cursor-pointer"
              >
                Log In
              </button>
              <button
                type="button"
                onClick={onOpenRegister}
                className="glass-button-primary px-4 py-1.5 rounded-full text-xs font-semibold text-white transition shadow-xs cursor-pointer"
              >
                Sign Up
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
