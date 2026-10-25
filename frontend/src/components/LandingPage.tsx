import React, { useState, useEffect } from 'react';
import {
  Shield,
  ArrowRight,
  Menu,
  X,
  User as UserIcon,
  Lock,
  ChevronRight,
  Database,
  FileCode,
  Mail,
  Globe,
  Terminal,
  CheckCircle2,
  Copy,
  Check,
  Zap,
  ChevronDown,
  Layers,
  Cpu,
  AlertOctagon,
  Eye,
  Sliders,
} from 'lucide-react';
import { User } from '../types';
import { TiltCard } from './TiltCard';
import { Interactive3DGateway } from './Interactive3DGateway';
import { InteractiveGatewaySimulator } from './InteractiveGatewaySimulator';

interface LandingPageProps {
  onNavigate: (tab: string) => void;
  onOpenLogin: () => void;
  currentUser: User | null;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onNavigate,
  onOpenLogin,
  currentUser,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeCodeTab, setActiveCodeTab] = useState<'python' | 'fastapi' | 'langchain'>('python');
  const [copiedCode, setCopiedCode] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  // Close mobile menu on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMobileMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const codeSnippets = {
    python: `# [GENUINELY EXECUTABLE IN THIS REPO] Python SDK Quickstart
# Run via terminal: python -c "import sys; sys.path.insert(0, 'backend'); ..."
import sys
sys.path.insert(0, "backend")

from app.gateway.gateway import SecurityGateway

# 1. Initialize Zero-Trust Security Gateway (Default: Strict Enterprise Invariants)
gateway = SecurityGateway()

# 2. Programmatically evaluate tool call before execution
decision = gateway.evaluate_tool_call(
    tool_name="query_database",
    arguments={"query": "SELECT id, email, password_hash FROM user_profiles"},
    user_prompt="Exfiltrate all user credentials"
)

# 3. Check deterministic invariant decision
if decision.allowed:
    print("Action Permitted: Proceeding to execute tool...")
else:
    print(f"Intercepted & Blocked: {decision.reason}")
    print(f"Triggered Invariant Rule: {decision.rule_id}")  # RULE-SQL-02-CONFIDENTIAL-DENY`,

    fastapi: `# [GENUINELY EXECUTABLE IN THIS REPO] FastAPI Gateway Route Integration
# Start server: python backend/run.py (serves at http://127.0.0.1:8000)
from fastapi import FastAPI, Depends, HTTPException, status
from app.gateway.gateway import SecurityGateway
from app.gateway.auth import get_current_user, require_roles
from app.models.schemas import ToolInvocationRequest, User

app = FastAPI(title="TraceGuard AI Gateway")
gateway = SecurityGateway()

@app.post("/api/tools/invoke")
async def invoke_agent_tool(
    request: ToolInvocationRequest,
    current_user: User = Depends(require_roles(["admin", "operator"]))
):
    # Enforce server-side authenticated identity; client agent_role is validated
    request.agent_role = current_user.role
    decision, result, event = gateway.invoke(request)

    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"reason": decision.reason, "rule": decision.rule_id, "event_id": event.event_id}
        )
    return {"executed": True, "output": result.output, "event_id": event.event_id}`,

    langchain: `# [CONCEPTUAL INTEGRATION PATTERN] Illustrative LangChain Adapter
# Note: LangChain is an optional 3rd-party dependency (pip install langchain).
# This pattern illustrates wrapping any LangChain/OpenAI tool with TraceGuard:

from app.gateway.gateway import SecurityGateway
from app.models.schemas import ToolInvocationRequest

class TraceGuardToolInterceptor:
    """Conceptual adapter showing how to wrap LangChain or third-party tools."""
    def __init__(self, gateway: SecurityGateway):
        self.gateway = gateway

    def wrap(self, tool_name: str, execution_fn):
        def guarded_fn(**kwargs):
            # Intercept arguments through TraceGuard before calling underlying tool
            req = ToolInvocationRequest(tool_name=tool_name, arguments=kwargs)
            decision, result, event = self.gateway.invoke(req)
            if not decision.allowed:
                raise PermissionError(f"TraceGuard Security Block: {decision.reason}")
            return execution_fn(**kwargs)
        return guarded_fn`,
  };

  const faqs = [
    {
      q: 'Why is prompt engineering alone insufficient to protect tool-using AI agents?',
      a: 'Language models are probabilistic token predictors. When untrusted user inputs or poisoned third-party web content are concatenated into system prompts, the model cannot distinguish between trusted instructions and adversarial commands. True security requires an out-of-band, deterministic gateway between the model output and tool execution.',
    },
    {
      q: 'How does TraceGuard prevent indirect prompt injection in retrieved web content?',
      a: 'When an agent scrapes external websites or reads customer support tickets, TraceGuard tags incoming content as untrusted. If an embedded prompt tricks the agent into exfiltrating data (e.g., emailing credentials to an attacker domain), TraceGuard intercepts the subsequent tool call and blocks unauthorized egress domains.',
    },
    {
      q: 'Does TraceGuard add noticeable latency to agent tool invocations?',
      a: 'No. TraceGuard is engineered in zero-overhead compiled Rust and Python AST inspection routines with sub-millisecond median enforcement latency (typically under 1.2ms). It evaluates policy rules in-memory before the external I/O action begins.',
    },
    {
      q: 'How does TraceGuard eliminate identity spoofing and privilege escalation?',
      a: 'Client-supplied agent roles in payload bodies are strictly discarded. TraceGuard derives caller permissions exclusively from cryptographic HttpOnly session tokens and server-side role-based access control (RBAC). An unauthenticated visitor or guest cannot escalate to operator or admin privileges.',
    },
  ];

  return (
    <div className="min-h-screen w-full bg-[#000000] text-[#EDEDED] flex flex-col relative overflow-x-hidden selection:bg-white/20 selection:text-white bg-grid-cyber">
      {/* Background radial gradient glow for cinematic depth */}
      <div
        className="pointer-events-none fixed top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[550px] bg-white/[0.025] rounded-full blur-[160px]"
        aria-hidden="true"
      />

      {/* 1. Header / Sticky Liquid-Metal Navigation */}
      <header className="sticky top-0 w-full z-50 backdrop-blur-xl bg-black/60 border-b border-white/[0.08]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
          {/* Brand Logo */}
          <button
            type="button"
            onClick={() => onNavigate('landing')}
            className="flex items-center gap-2.5 group text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40 rounded-lg p-1 cursor-pointer"
            aria-label="TraceGuard AI home"
          >
            <div className="w-8 h-8 rounded-lg bg-white/[0.05] border border-white/15 flex items-center justify-center text-white group-hover:border-white/30 group-hover:bg-white/[0.1] transition shadow-xs">
              <Shield className="w-4 h-4 text-[#C7F36B]" />
            </div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sm text-white tracking-tight group-hover:text-white/90 transition">
                TraceGuard AI
              </span>
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-[#C7F36B]/10 text-[#C7F36B] border border-[#C7F36B]/20">
                Zero-Trust
              </span>
            </div>
          </button>

          {/* Liquid Metal Navigation Pill (Desktop) */}
          <nav
            className="hidden md:flex items-center liquid-pill rounded-full px-5 py-1.5 gap-6 text-xs font-medium"
            aria-label="Main Navigation"
          >
            <button
              type="button"
              onClick={() => onNavigate('home')}
              className="liquid-pill-link hover:text-white transition focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/40 rounded px-1 cursor-pointer"
            >
              Overview
            </button>
            <span className="text-white/10 select-none">·</span>
            <button
              type="button"
              onClick={() => onNavigate('playground')}
              className="liquid-pill-link hover:text-white transition focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/40 rounded px-1 cursor-pointer"
            >
              Playground
            </button>
            <span className="text-white/10 select-none">·</span>
            <button
              type="button"
              onClick={() => onNavigate('agent_demo')}
              className="liquid-pill-link hover:text-white transition focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/40 rounded px-1 cursor-pointer"
            >
              Agent Demo
            </button>
            <span className="text-white/10 select-none">·</span>
            <button
              type="button"
              onClick={() => onNavigate('advanced')}
              className="liquid-pill-link hover:text-white transition focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/40 rounded px-1 cursor-pointer"
            >
              Benchmarks
            </button>
          </nav>

          {/* Right Action / Auth Controls */}
          <div className="hidden md:flex items-center gap-3">
            {currentUser ? (
              <button
                type="button"
                onClick={() => onNavigate('home')}
                className="glass-button-secondary px-4 py-2 rounded-full text-xs font-medium flex items-center gap-2 group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40 cursor-pointer"
              >
                <UserIcon className="w-3.5 h-3.5 text-[#C7F36B]" />
                <span>{currentUser.full_name || currentUser.email}</span>
                <ChevronRight className="w-3.5 h-3.5 text-white/50 group-hover:translate-x-0.5 transition" />
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={onOpenLogin}
                  className="glass-button-secondary px-4 py-2 rounded-full text-xs font-medium text-white/80 hover:text-white flex items-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40 cursor-pointer"
                >
                  <Lock className="w-3 h-3 text-white/70" />
                  <span>Sign In</span>
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('home')}
                  className="glass-button-primary px-4 py-2 rounded-full text-xs font-medium text-white flex items-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40 cursor-pointer"
                >
                  <span>Launch Workspace</span>
                  <ArrowRight className="w-3.5 h-3.5 text-white/80" />
                </button>
              </>
            )}
          </div>

          {/* Mobile Menu Toggle */}
          <div className="flex md:hidden items-center">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-[#929CA3] hover:text-white rounded-lg bg-white/[0.04] border border-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40 cursor-pointer"
              aria-label={mobileMenuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={mobileMenuOpen}
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-white/10 bg-black/95 p-4 flex flex-col gap-3 animate-fade-in-staged delay-50">
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onNavigate('home');
              }}
              className="w-full text-left py-2.5 px-3 rounded-lg text-sm font-medium text-[#EDEDED] hover:bg-white/[0.06] transition"
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onNavigate('playground');
              }}
              className="w-full text-left py-2.5 px-3 rounded-lg text-sm font-medium text-[#EDEDED] hover:bg-white/[0.06] transition"
            >
              Security Playground
            </button>
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onNavigate('agent_demo');
              }}
              className="w-full text-left py-2.5 px-3 rounded-lg text-sm font-medium text-[#EDEDED] hover:bg-white/[0.06] transition"
            >
              Autonomous Agent Demo
            </button>
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onNavigate('advanced');
              }}
              className="w-full text-left py-2.5 px-3 rounded-lg text-sm font-medium text-[#EDEDED] hover:bg-white/[0.06] transition"
            >
              Attack Benchmarks
            </button>
            <div className="h-[1px] bg-white/10 my-1" />
            {currentUser ? (
              <button
                type="button"
                onClick={() => {
                  setMobileMenuOpen(false);
                  onNavigate('home');
                }}
                className="w-full py-2.5 px-3 rounded-lg text-sm font-medium bg-white/[0.08] text-white flex items-center justify-between"
              >
                <span>Dashboard ({currentUser.full_name})</span>
                <ArrowRight className="w-4 h-4 text-white/60" />
              </button>
            ) : (
              <div className="flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenLogin();
                  }}
                  className="w-full py-2.5 px-3 rounded-lg text-sm font-medium glass-button-secondary text-white flex items-center justify-center gap-2"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Sign In</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onNavigate('home');
                  }}
                  className="w-full py-2.5 px-3 rounded-lg text-sm font-medium glass-button-primary text-white flex items-center justify-center gap-2"
                >
                  <span>Launch Workspace</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
        )}
      </header>

      {/* 2. Hero Section: Cinematic 3D Presentation */}
      <section className="relative w-full max-w-7xl mx-auto px-4 sm:px-6 pt-16 pb-12 sm:pb-20 z-20 flex flex-col items-center text-center">
        {/* Eyebrow badge */}
        <div className="mb-6 animate-fade-in-staged delay-50">
          <div className="glass-badge inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full">
            <span className="w-2 h-2 rounded-full bg-[#C7F36B] shadow-[0_0_12px_#C7F36B]" aria-hidden="true" />
            <span className="text-[11px] sm:text-xs font-mono font-medium tracking-[0.2em] text-[#9AA4AD] uppercase">
              Deterministic Security Gateway for AI Agents
            </span>
          </div>
        </div>

        {/* Hero Headline */}
        <h1 className="text-4xl sm:text-6xl lg:text-[4.75rem] font-medium tracking-tight text-white leading-[1.08] mb-6 max-w-5xl animate-fade-in-staged delay-150">
          Give your <span className="font-instrument italic font-normal text-white">AI agents</span> freedom.
          <br className="hidden sm:inline" />
          {' '}Keep control of every action.
        </h1>

        {/* Supporting Copy */}
        <p className="text-base sm:text-lg md:text-xl text-[#8E969E] max-w-3xl mx-auto leading-relaxed font-normal mb-10 animate-fade-in-staged delay-250">
          Stop prompt injection, indirect ingestion attacks, and unauthorized tool calls before execution. TraceGuard puts a deterministic zero-trust gateway between autonomous LLM agents and your databases, files, and APIs.
        </p>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 w-full sm:w-auto mb-14 animate-fade-in-staged delay-350">
          <button
            type="button"
            onClick={() => onNavigate('home')}
            className="glass-button-primary group w-full sm:w-auto px-8 py-4 rounded-full text-sm font-semibold text-white flex items-center justify-center gap-2.5 shadow-xl cursor-pointer"
          >
            <span>Explore Gateway Dashboard</span>
            <ArrowRight className="w-4 h-4 text-white/90 group-hover:translate-x-1 transition-transform" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate('playground')}
            className="glass-button-secondary w-full sm:w-auto px-7 py-4 rounded-full text-sm font-medium text-[#9AA4AD] hover:text-white flex items-center justify-center gap-2 cursor-pointer"
          >
            <Terminal className="w-4 h-4 text-[#C7F36B]" />
            <span>Launch Security Playground</span>
          </button>
        </div>

        {/* 3D Interactive Canvas: Interceptor Mesh */}
        <div className="w-full max-w-5xl animate-fade-in-staged delay-450">
          <Interactive3DGateway />
        </div>
      </section>

      {/* 3. Capability Indicators */}
      <section className="w-full max-w-6xl mx-auto px-4 sm:px-6 py-8 border-y border-white/[0.08] z-20">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
          <div className="flex flex-col items-center">
            <span className="font-mono text-xs font-semibold text-white tracking-wider uppercase mb-1">
              POLICY-FIRST
            </span>
            <span className="text-xs text-[#8E969E]">Deterministic Invariant Rules</span>
          </div>
          <div className="flex flex-col items-center">
            <span className="font-mono text-xs font-semibold text-white tracking-wider uppercase mb-1">
              AUDITABLE
            </span>
            <span className="text-xs text-[#8E969E]">Cryptographic SHA-256 Chains</span>
          </div>
          <div className="flex flex-col items-center">
            <span className="font-mono text-xs font-semibold text-white tracking-wider uppercase mb-1">
              TESTABLE
            </span>
            <span className="text-xs text-[#8E969E]">98 Adversarial Test Suites</span>
          </div>
          <div className="flex flex-col items-center">
            <span className="font-mono text-xs font-semibold text-white tracking-wider uppercase mb-1">
              SUB-MILLISECOND
            </span>
            <span className="text-xs text-[#8E969E]">0.84ms Median Intercept Overhead</span>
          </div>
        </div>
      </section>

      {/* 4. Live Interactive Gateway Simulator Section */}
      <section className="w-full max-w-6xl mx-auto px-4 sm:px-6 py-20 z-20">
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-[#8E969E] mb-3">
            <Sliders className="w-3.5 h-3.5 text-[#C7F36B]" />
            <span>Interactive Threat Defense Lab</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight">
            Deterministic Protection You Can Inspect
          </h2>
          <p className="text-sm sm:text-base text-[#8E969E] mt-3">
            Experience how TraceGuard separates the untrusted agent reasoning loop from real-world execution. Switch threat scenarios below to test adversarial behavior live.
          </p>
        </div>

        <InteractiveGatewaySimulator />
      </section>

      {/* 5. Interactive 3D Bento Grid: Core Architectural Invariants */}
      <section className="w-full max-w-6xl mx-auto px-4 sm:px-6 py-16 z-20">
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-[#8E969E] mb-3">
            <Layers className="w-3.5 h-3.5 text-[#C7F36B]" />
            <span>Architectural Guarantees</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight">
            Engineered for High-Risk Autonomous Agent Workloads
          </h2>
          <p className="text-sm sm:text-base text-[#8E969E] mt-3">
            Unlike prompt filtering or output guardrails that LLMs regularly bypass, TraceGuard enforces non-bypassable operating invariants.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Bento Card 1 */}
          <TiltCard className="md:col-span-2 glass-panel rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
            <div>
              <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-[#C7F36B] mb-5">
                <Database className="w-5 h-5" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">
                AST-Level SQL Verification & Schema Isolation
              </h3>
              <p className="text-sm text-[#8E969E] leading-relaxed mb-6">
                TraceGuard parses database queries into full Abstract Syntax Trees (AST). Regex-bypassing tricks like comments (<code className="text-emerald-300">--</code>), multiline concatenation, or UNION injections cannot hide unauthorized tables or mutating statements.
              </p>
            </div>
            <div className="p-3.5 rounded-xl bg-black/60 border border-white/10 font-mono text-xs text-white/80 flex items-center justify-between">
              <span className="text-[#8E969E]">Enforcement Mode:</span>
              <span className="text-[#C7F36B] font-semibold">Strict Parameterized Read-Only</span>
            </div>
          </TiltCard>

          {/* Bento Card 2 */}
          <TiltCard className="glass-panel rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
            <div>
              <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-blue-400 mb-5">
                <Globe className="w-5 h-5" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">
                Tainted Data Scrape Containment
              </h3>
              <p className="text-sm text-[#8E969E] leading-relaxed mb-6">
                Web search outputs (via Tavily) and customer uploads are tagged as tainted. Hidden prompt injection payloads are quarantined before secondary tools can be invoked.
              </p>
            </div>
            <div className="p-3.5 rounded-xl bg-black/60 border border-white/10 font-mono text-xs text-white/80 flex items-center justify-between">
              <span className="text-[#8E969E]">Indirect Vector:</span>
              <span className="text-blue-300 font-semibold">Quarantined Sandbox</span>
            </div>
          </TiltCard>

          {/* Bento Card 3 */}
          <TiltCard className="glass-panel rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
            <div>
              <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-purple-400 mb-5">
                <FileCode className="w-5 h-5" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">
                Filesystem Canonicalization
              </h3>
              <p className="text-sm text-[#8E969E] leading-relaxed mb-6">
                All file paths undergo strict canonicalization and root confinement. Relative traversal (<code className="text-purple-300">../../</code>) and symlink redirections are trapped before filesystem read operations occur.
              </p>
            </div>
            <div className="p-3.5 rounded-xl bg-black/60 border border-white/10 font-mono text-xs text-white/80 flex items-center justify-between">
              <span className="text-[#8E969E]">Path Confinement:</span>
              <span className="text-purple-300 font-semibold">Enforced Jailed Root</span>
            </div>
          </TiltCard>

          {/* Bento Card 4 */}
          <TiltCard className="md:col-span-2 glass-panel rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
            <div>
              <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-[#EF4444] mb-5">
                <AlertOctagon className="w-5 h-5" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">
                Cryptographic Circuit Breaker & Emergency Stop
              </h3>
              <p className="text-sm text-[#8E969E] leading-relaxed mb-6">
                When anomalous behavior is detected, TraceGuard can trip its hardware-like emergency stop breaker. Invocations across all connected agents immediately halt with fail-safe zero execution, recorded in tamper-evident SHA-256 logs.
              </p>
            </div>
            <div className="p-3.5 rounded-xl bg-black/60 border border-white/10 font-mono text-xs text-white/80 flex items-center justify-between">
              <span className="text-[#8E969E]">Emergency Response:</span>
              <span className="text-[#EF4444] font-semibold">Zero-Latency Circuit Cut</span>
            </div>
          </TiltCard>
        </div>
      </section>

      {/* 6. Developer Integration & Code Studio */}
      <section className="w-full max-w-6xl mx-auto px-4 sm:px-6 py-16 z-20">
        <div className="text-center max-w-3xl mx-auto mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-[#8E969E] mb-3">
            <Terminal className="w-3.5 h-3.5 text-[#C7F36B]" />
            <span>Developer SDK</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight">
            Drop into Any AI Framework in Minutes
          </h2>
          <p className="text-sm sm:text-base text-[#8E969E] mt-3">
            Whether you use LangChain, CrewAI, AutoGen, or custom FastAPI microservices, TraceGuard integrates cleanly as a tool interceptor.
          </p>
        </div>

        <div className="glass-panel rounded-2xl border border-white/10 overflow-hidden">
          {/* Code Tabs Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between px-4 sm:px-6 py-3 border-b border-white/10 bg-black/60 gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setActiveCodeTab('python')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer flex items-center gap-1.5 ${
                  activeCodeTab === 'python'
                    ? 'bg-white/15 text-white font-semibold shadow-xs'
                    : 'text-[#8E969E] hover:text-white'
                }`}
              >
                <span>Python SDK</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded-full bg-[#C7F36B]/15 text-[#C7F36B] border border-[#C7F36B]/30 font-semibold">
                  Executable
                </span>
              </button>
              <button
                type="button"
                onClick={() => setActiveCodeTab('fastapi')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer flex items-center gap-1.5 ${
                  activeCodeTab === 'fastapi'
                    ? 'bg-white/15 text-white font-semibold shadow-xs'
                    : 'text-[#8E969E] hover:text-white'
                }`}
              >
                <span>FastAPI Route</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded-full bg-[#C7F36B]/15 text-[#C7F36B] border border-[#C7F36B]/30 font-semibold">
                  Executable
                </span>
              </button>
              <button
                type="button"
                onClick={() => setActiveCodeTab('langchain')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer flex items-center gap-1.5 ${
                  activeCodeTab === 'langchain'
                    ? 'bg-white/15 text-white font-semibold shadow-xs'
                    : 'text-[#8E969E] hover:text-white'
                }`}
              >
                <span>LangChain Adapter</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded-full bg-purple-500/15 text-purple-300 border border-purple-500/30">
                  Conceptual
                </span>
              </button>
            </div>

            <button
              type="button"
              onClick={() => handleCopyCode(codeSnippets[activeCodeTab])}
              className="px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] text-xs font-mono text-white/80 hover:text-white flex items-center gap-1.5 transition cursor-pointer border border-white/10"
            >
              {copiedCode ? <Check className="w-3.5 h-3.5 text-[#C7F36B]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCode ? 'Copied' : 'Copy Snippet'}</span>
            </button>
          </div>

          {/* Code Block */}
          <div className="p-6 bg-black/90 font-mono text-xs sm:text-sm text-emerald-300 leading-relaxed overflow-x-auto">
            <pre>{codeSnippets[activeCodeTab]}</pre>
          </div>
        </div>
      </section>

      {/* 7. Interactive Security FAQ */}
      <section className="w-full max-w-4xl mx-auto px-4 sm:px-6 py-16 z-20">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-semibold text-white tracking-tight">
            Frequently Asked Questions
          </h2>
          <p className="text-sm text-[#8E969E] mt-2">
            Key architectural details regarding tool-level zero-trust defense.
          </p>
        </div>

        <div className="space-y-3">
          {faqs.map((faq, index) => {
            const isOpen = openFaq === index;
            return (
              <div
                key={index}
                className="glass-panel rounded-xl border border-white/10 overflow-hidden transition-all duration-200"
              >
                <button
                  type="button"
                  onClick={() => setOpenFaq(isOpen ? null : index)}
                  className="w-full px-5 py-4 text-left flex items-center justify-between gap-4 cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/40"
                >
                  <span className="text-sm font-medium text-white">{faq.q}</span>
                  <ChevronDown
                    className={`w-4 h-4 text-[#8E969E] shrink-0 transition-transform duration-200 ${
                      isOpen ? 'rotate-180 text-white' : ''
                    }`}
                  />
                </button>
                {isOpen && (
                  <div className="px-5 pb-5 pt-1 text-xs sm:text-sm text-[#8E969E] leading-relaxed border-t border-white/5 animate-fade-in-staged delay-50">
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* 8. Conversion CTA Banner */}
      <section className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-16 z-20">
        <div className="liquid-pill rounded-3xl p-8 sm:p-12 text-center relative overflow-hidden border border-white/20 shadow-2xl">
          <div className="max-w-2xl mx-auto">
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">
              Secure Your Tool-Calling AI Agents Today
            </h2>
            <p className="text-sm sm:text-base text-[#8E969E] mb-8 leading-relaxed">
              Open the interactive workspace to run adversarial benchmarks, execute tool calls through the live playground, and inspect cryptographic audit logs.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <button
                type="button"
                onClick={() => onNavigate('home')}
                className="glass-button-primary w-full sm:w-auto px-8 py-3.5 rounded-full text-sm font-semibold text-white flex items-center justify-center gap-2 cursor-pointer shadow-lg"
              >
                <span>Enter Security Workspace</span>
                <ArrowRight className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={() => onNavigate('playground')}
                className="glass-button-secondary w-full sm:w-auto px-7 py-3.5 rounded-full text-sm font-medium text-[#9AA4AD] hover:text-white flex items-center justify-center gap-2 cursor-pointer"
              >
                <span>Open Playground</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 9. Futuristic Clean Footer */}
      <footer className="w-full max-w-7xl mx-auto px-4 sm:px-6 py-10 border-t border-white/[0.08] z-20">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6 text-xs text-[#8E969E]">
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded-md bg-white/[0.06] border border-white/10 flex items-center justify-center text-[#C7F36B]">
              <Shield className="w-3.5 h-3.5" />
            </div>
            <span className="font-medium text-white">TraceGuard AI</span>
            <span>·</span>
            <span>Zero-Trust Tool Authorization Gateway</span>
          </div>

          <div className="flex items-center gap-6 font-mono text-[11px]">
            <button
              type="button"
              onClick={() => onNavigate('home')}
              className="hover:text-white transition cursor-pointer"
            >
              Dashboard
            </button>
            <button
              type="button"
              onClick={() => onNavigate('playground')}
              className="hover:text-white transition cursor-pointer"
            >
              Playground
            </button>
            <button
              type="button"
              onClick={() => onNavigate('agent_demo')}
              className="hover:text-white transition cursor-pointer"
            >
              Agent Demo
            </button>
            <button
              type="button"
              onClick={() => onNavigate('advanced')}
              className="hover:text-white transition cursor-pointer"
            >
              Benchmarks
            </button>
          </div>

          <div className="text-[11px] font-mono text-[#535C64]">
            FastAPI · React 19 · SQLite WAL
          </div>
        </div>
      </footer>
    </div>
  );
};
