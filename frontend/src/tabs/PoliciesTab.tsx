import React, { useState } from 'react';
import {
  Layers,
  Shield,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  RotateCcw,
  Plus,
  Save,
  Sliders,
  AlertTriangle,
} from 'lucide-react';
import { PolicySet, PolicyRule } from '../types';
import { setActivePolicy, resetDefaultPolicies, savePolicy } from '../services/api';

interface PoliciesTabProps {
  policies: PolicySet[];
  onRefreshPolicies: () => void;
}

export const PoliciesTab: React.FC<PoliciesTabProps> = ({ policies, onRefreshPolicies }) => {
  const activePolicy = policies.find((p) => p.is_active) || policies[0];
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>(activePolicy?.id || '');
  const [currentPolicy, setCurrentPolicy] = useState<PolicySet | null>(activePolicy);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const selectedPolicy = policies.find((p) => p.id === selectedPolicyId) || activePolicy;

  React.useEffect(() => {
    if (selectedPolicy) {
      setCurrentPolicy(JSON.parse(JSON.stringify(selectedPolicy)));
    }
  }, [selectedPolicyId, policies]);

  const handleSwitchActive = async () => {
    if (!currentPolicy) return;
    setStatusMessage(null);
    setErrorMessage(null);
    try {
      await setActivePolicy(currentPolicy.id);
      setStatusMessage(`Policy set '${currentPolicy.name}' is now ACTIVE.`);
      onRefreshPolicies();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to switch policy.');
    }
  };

  const handleResetDefaults = async () => {
    if (!confirm('Reset policies to factory defaults (Strict Zero-Trust + Permissive)?')) return;
    setStatusMessage(null);
    setErrorMessage(null);
    try {
      await resetDefaultPolicies();
      setStatusMessage('Restored default policy sets successfully.');
      onRefreshPolicies();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to reset.');
    }
  };

  const handleToggleRule = async (ruleId: string) => {
    if (!currentPolicy) return;
    const updatedRules = currentPolicy.rules.map((r) =>
      r.id === ruleId ? { ...r, enabled: !r.enabled } : r
    );
    const updatedPolicy = { ...currentPolicy, rules: updatedRules };
    setCurrentPolicy(updatedPolicy);

    try {
      await savePolicy(updatedPolicy);
      setStatusMessage(`Rule '${ruleId}' toggled.`);
      onRefreshPolicies();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to update rule.');
    }
  };

  if (!currentPolicy) return null;

  return (
    <div className="space-y-6">
      {/* Policy Engine Header */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl p-5 shadow space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400" />
              <span>Policy Engine & Guardrail Management</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Configure fine-grained zero-trust rules for files, SQL statements, and email dispatches.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleResetDefaults}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Restore Factory Defaults</span>
            </button>
            {!currentPolicy.is_active && (
              <button
                onClick={handleSwitchActive}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow transition"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Set as Active Gateway Policy</span>
              </button>
            )}
          </div>
        </div>

        {/* Policy Selector & Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Selected Policy Set</label>
            <select
              value={selectedPolicyId}
              onChange={(e) => setSelectedPolicyId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
            >
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} {p.is_active ? '★ ACTIVE' : ''}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Default Action (Zero-Trust)</label>
            <div className="bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 font-mono text-rose-400 font-bold">
              DENY BY DEFAULT
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Active Rules Count</label>
            <div className="bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 font-mono text-emerald-400 font-bold">
              {currentPolicy.rules.filter((r) => r.enabled).length} / {currentPolicy.rules.length} Rules Enabled
            </div>
          </div>
        </div>

        {/* Status Alerts */}
        {statusMessage && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{statusMessage}</span>
          </div>
        )}
        {errorMessage && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Rules Table */}
      <div className="bg-[#0d1322] border border-slate-800 rounded-xl overflow-hidden shadow">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">{currentPolicy.name} Rules</h3>
            <p className="text-xs text-slate-400">{currentPolicy.description}</p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Priority-ordered evaluation (Lower number = Evaluated first)
          </span>
        </div>

        <div className="divide-y divide-slate-800">
          {currentPolicy.rules.map((rule) => (
            <div
              key={rule.id}
              className={`p-4 transition flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                rule.enabled ? 'hover:bg-slate-800/30' : 'bg-slate-950/40 opacity-60'
              }`}
            >
              <div className="space-y-1.5 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs font-bold text-slate-200">{rule.id}</span>
                  <span className="text-xs font-semibold text-white">{rule.name}</span>
                  <span
                    className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase ${
                      rule.action === 'allow'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    }`}
                  >
                    ACTION: {rule.action}
                  </span>
                  <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-slate-800 text-indigo-300 border border-slate-700">
                    TOOL: {rule.tool}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">Priority: {rule.priority}</span>
                </div>
                <p className="text-xs text-slate-400">{rule.description}</p>

                {/* Parameters Preview */}
                {rule.parameters && Object.keys(rule.parameters).length > 0 && (
                  <div className="text-[11px] font-mono text-slate-400 flex items-center gap-2 pt-1">
                    <span className="text-slate-500">Params:</span>
                    <code className="text-slate-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {JSON.stringify(rule.parameters)}
                    </code>
                  </div>
                )}
              </div>

              {/* Toggle switch */}
              <div className="flex items-center gap-3">
                <button
                  onClick={() => handleToggleRule(rule.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition border ${
                    rule.enabled
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                      : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200'
                  }`}
                >
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
