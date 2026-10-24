import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { OverviewTab } from './tabs/OverviewTab';
import { SuitesTab } from './tabs/SuitesTab';
import { RunDetailsTab } from './tabs/RunDetailsTab';
import { PlaygroundTab } from './tabs/PlaygroundTab';
import { PoliciesTab } from './tabs/PoliciesTab';
import { AuditTab } from './tabs/AuditTab';
import { RegressionTab } from './tabs/RegressionTab';
import { FindingsTab } from './tabs/FindingsTab';
import {
  fetchHealth,
  fetchPolicies,
  fetchRuns,
  fetchSuites,
  triggerRun,
} from './services/api';
import { PolicySet, SystemHealth, TestRun, TestSuite } from './types';

export function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [policies, setPolicies] = useState<PolicySet[]>([]);
  const [runs, setRuns] = useState<TestRun[]>([]);
  const [suites, setSuites] = useState<TestSuite[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedAuditEventId, setSelectedAuditEventId] = useState<string | null>(null);
  const [isRunningTest, setIsRunningTest] = useState<boolean>(false);
  const [initialLoading, setInitialLoading] = useState<boolean>(true);

  const loadData = async () => {
    try {
      const [h, p, r, s] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchPolicies().catch(() => []),
        fetchRuns().catch(() => []),
        fetchSuites().catch(() => []),
      ]);
      setHealth(h);
      setPolicies(p);
      setRuns(r);
      setSuites(s);
      if (r.length > 0 && !selectedRunId) {
        setSelectedRunId(r[0].id);
      }
    } finally {
      setInitialLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleQuickRun = async () => {
    setIsRunningTest(true);
    try {
      const activePolicy = policies.find((p) => p.is_active) || policies[0];
      const newRun = await triggerRun({
        suite_id: 'suite_core_security_v1',
        policy_set_id: activePolicy ? activePolicy.id : undefined,
        agent_type: 'mock',
      });
      setRuns((prev) => [newRun, ...prev.filter((r) => r.id !== newRun.id)]);
      setSelectedRunId(newRun.id);
      setActiveTab('run_details');
    } catch (err) {
      console.error('Quick run failed:', err);
    } finally {
      setIsRunningTest(false);
    }
  };

  const handleTriggerRun = async (params: {
    suite_id: string;
    policy_set_id?: string;
    agent_type: string;
    groq_api_key?: string;
  }): Promise<TestRun> => {
    setIsRunningTest(true);
    try {
      const newRun = await triggerRun(params);
      setRuns((prev) => [newRun, ...prev.filter((r) => r.id !== newRun.id)]);
      setSelectedRunId(newRun.id);
      return newRun;
    } finally {
      setIsRunningTest(false);
    }
  };

  const handleInspectRun = (runId: string) => {
    setSelectedRunId(runId);
    setActiveTab('run_details');
  };

  const handleViewAuditEvent = (eventId: string) => {
    setSelectedAuditEventId(eventId);
    setActiveTab('audit');
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-300">
      {/* Navigation */}
      <Navbar
        health={health}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRefreshHealth={loadData}
      />

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {initialLoading ? (
          <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3 text-slate-400">
            <div className="w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin"></div>
            <p className="text-xs font-mono">Initializing TraceGuard AI Security Engine...</p>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <OverviewTab
                runs={runs}
                health={health}
                onSelectRun={handleInspectRun}
                onNavigateTab={setActiveTab}
                onQuickRun={handleQuickRun}
                isRunningTest={isRunningTest}
              />
            )}

            {activeTab === 'suites' && (
              <SuitesTab
                suites={suites}
                policies={policies}
                onTriggerRun={handleTriggerRun}
                onInspectRun={handleInspectRun}
                isRunningTest={isRunningTest}
              />
            )}

            {activeTab === 'run_details' && (
              <RunDetailsTab
                runs={runs}
                selectedRunId={selectedRunId}
                onSelectRunId={setSelectedRunId}
                onViewAuditEvent={handleViewAuditEvent}
              />
            )}

            {activeTab === 'playground' && <PlaygroundTab policies={policies} />}

            {activeTab === 'policies' && (
              <PoliciesTab policies={policies} onRefreshPolicies={loadData} />
            )}

            {activeTab === 'audit' && <AuditTab initialEventId={selectedAuditEventId} />}

            {activeTab === 'regression' && <RegressionTab runs={runs} />}

            {activeTab === 'findings' && <FindingsTab />}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#090d18] px-6 py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-400">TraceGuard AI</span>
            <span>—</span>
            <span>Zero-Trust Security Gateway for Tool-Using Autonomous Agents</span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
            <span>Server: Python / FastAPI</span>
            <span>Client: React / TypeScript / Vite</span>
            <span>Confidential Synthetic Data Only</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
