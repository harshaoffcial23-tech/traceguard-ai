import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { LandingPage } from './components/LandingPage';
import { AuthModal } from './components/AuthModal';
import { HomeTab } from './tabs/HomeTab';
import { AgentDemoTab } from './tabs/AgentDemoTab';
import { ActivityTab } from './tabs/ActivityTab';
import { DeveloperToolsTab } from './tabs/DeveloperToolsTab';
import {
  fetchHealth,
  fetchPolicies,
  fetchRuns,
  fetchAuditEvents,
  triggerRun,
  fetchEmergencyStop,
  fetchCurrentUser,
  logout,
} from './services/api';
import { PolicySet, SystemHealth, TestRun, AuditEvent, User } from './types';
import { KeyRound, ShieldAlert } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<string>('landing');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('login');
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [policies, setPolicies] = useState<PolicySet[]>([]);
  const [runs, setRuns] = useState<TestRun[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [isEmergencyStopped, setIsEmergencyStopped] = useState<boolean>(false);
  const [isRunningTest, setIsRunningTest] = useState<boolean>(false);
  const [initialLoading, setInitialLoading] = useState<boolean>(true);

  const loadData = async () => {
    try {
      const [u, h, p, r, a, es] = await Promise.all([
        fetchCurrentUser().catch(() => null),
        fetchHealth().catch(() => null),
        fetchPolicies().catch(() => []),
        fetchRuns().catch(() => []),
        fetchAuditEvents({ limit: 100 }).catch(() => []),
        fetchEmergencyStop().catch(() => ({ emergency_stopped: false, status: 'OPERATIONAL' })),
      ]);
      setCurrentUser(u);
      setHealth(h);
      setPolicies(p);
      setRuns(r);
      setAuditEvents(a);
      setIsEmergencyStopped(es.emergency_stopped);
    } finally {
      setInitialLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleLogout = async () => {
    await logout();
    setCurrentUser(null);
    await loadData();
  };

  const handleAuthSuccess = async (user: User) => {
    setCurrentUser(user);
    await loadData();
  };

  const handleQuickRun = async () => {
    if (!currentUser) {
      setAuthModalMode('login');
      setIsAuthModalOpen(true);
      return;
    }

    setIsRunningTest(true);
    try {
      const activePolicy = policies.find((p) => p.is_active) || policies[0];
      const newRun = await triggerRun({
        suite_id: 'suite_core_security_v1',
        policy_set_id: activePolicy ? activePolicy.id : undefined,
        agent_type: 'mock',
      });
      setRuns((prev) => [newRun, ...prev.filter((r) => r.id !== newRun.id)]);
      // Refresh audit events after run
      const updatedEvents = await fetchAuditEvents({ limit: 100 }).catch(() => []);
      setAuditEvents(updatedEvents);
      setActiveTab('advanced');
    } catch (err: any) {
      console.error('Quick run failed:', err);
      if (err?.message?.includes('Authentication') || err?.message?.includes('401')) {
        setIsAuthModalOpen(true);
      }
    } finally {
      setIsRunningTest(false);
    }
  };

  if (activeTab === 'landing') {
    return (
      <div className="min-h-screen bg-[#000000] text-[#EDEDED] flex flex-col font-sans selection:bg-white/20 selection:text-white">
        <LandingPage
          onNavigate={setActiveTab}
          onOpenLogin={() => {
            setAuthModalMode('login');
            setIsAuthModalOpen(true);
          }}
          currentUser={currentUser}
        />
        <AuthModal
          isOpen={isAuthModalOpen}
          onClose={() => setIsAuthModalOpen(false)}
          onAuthSuccess={handleAuthSuccess}
          initialMode={authModalMode}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#000000] text-[#EDEDED] flex flex-col font-sans selection:bg-white/20 selection:text-white bg-grid-cyber">
      {/* 1. Simplified Navigation Bar with Auth State */}
      <Navbar
        health={health}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRefreshHealth={loadData}
        isEmergencyStopped={isEmergencyStopped}
        currentUser={currentUser}
        onOpenLogin={() => {
          setAuthModalMode('login');
          setIsAuthModalOpen(true);
        }}
        onOpenRegister={() => {
          setAuthModalMode('register');
          setIsAuthModalOpen(true);
        }}
        onLogout={handleLogout}
      />

      {/* Guest Explorer Notice Banner */}
      {!currentUser && !initialLoading && (
        <div className="bg-black/80 border-b border-white/[0.08] backdrop-blur-md px-4 py-2.5 text-xs">
          <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-[#8E969E]">
              <KeyRound className="w-3.5 h-3.5 text-[#C7F36B]" />
              <span>
                <strong className="text-white">Zero-Trust Gateway:</strong> Viewing in read-only audit mode. Sign in to execute live agent tools, edit security policies, or toggle emergency stop.
              </span>
            </div>
            <button
              type="button"
              onClick={() => {
                setAuthModalMode('login');
                setIsAuthModalOpen(true);
              }}
              className="text-[#C7F36B] hover:underline font-mono text-xs font-medium shrink-0 cursor-pointer"
            >
              Sign In / Register &rarr;
            </button>
          </div>
        </div>
      )}

      {/* 2. Main Workspace Container */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-6 sm:py-8">
        {initialLoading ? (
          <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-3 text-[#8E969E]">
            <div className="w-6 h-6 border-2 border-[#C7F36B] border-t-transparent rounded-full animate-spin"></div>
            <p className="text-xs font-mono">Initializing TraceGuard Security Gateway...</p>
          </div>
        ) : (
          <>
            {(activeTab === 'dashboard' || activeTab === 'home') && (
              <HomeTab
                health={health}
                runs={runs}
                auditEvents={auditEvents}
                onNavigate={setActiveTab}
                onQuickRun={handleQuickRun}
                isRunningTest={isRunningTest}
                isEmergencyStopped={isEmergencyStopped}
              />
            )}

            {(activeTab === 'agents' || activeTab === 'agent_demo') && <AgentDemoTab />}

            {activeTab === 'activity' && (
              <ActivityTab
                currentUser={currentUser}
                onOpenAuth={() => {
                  setAuthModalMode('login');
                  setIsAuthModalOpen(true);
                }}
              />
            )}

            {(activeTab === 'developer' || activeTab === 'playground' || activeTab === 'advanced') && (
              <DeveloperToolsTab
                policies={policies}
                initialSubTab={activeTab === 'playground' ? 'playground' : activeTab === 'advanced' ? 'benchmarks' : 'playground'}
                onNavigateTab={setActiveTab}
                currentUser={currentUser}
              />
            )}
          </>
        )}
      </main>

      {/* 3. Authentication Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onAuthSuccess={handleAuthSuccess}
        initialMode={authModalMode}
      />

      {/* 4. Streamlined Clean Footer */}
      <footer className="border-t border-white/[0.08] bg-black/80 backdrop-blur-md px-4 sm:px-6 py-4 text-xs text-[#535C64]">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-medium text-white">TraceGuard AI</span>
            <span>·</span>
            <span>Zero-Trust Security Gateway for Tool-Using AI Agents</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono text-[#535C64]">
            <span>FastAPI Backend</span>
            <span>React Frontend</span>
            <span>Synthetic Lab</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
