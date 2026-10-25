# TraceGuard AI — Autonomous Agent Security Gateway & Benchmark Platform

[![Pytest Test Suite](https://img.shields.io/badge/pytest-100%20passed-brightgreen.svg)]()
[![Backend](https://img.shields.io/badge/backend-FastAPI%20%7C%20Python%203.14-blue.svg)]()
[![Frontend](https://img.shields.io/badge/frontend-React%20%7C%20TypeScript%20%7C%20Vite-61dafb.svg)]()
[![Security](https://img.shields.io/badge/architecture-Zero--Trust%20Gateway-emerald.svg)]()
[![Multilingual](https://img.shields.io/badge/languages-EN%20%7C%20TE%20%7C%20HI%20%7C%20TA%20%7C%20Mixed-purple.svg)]()

> **Submission Deadline**: October 25, 2026  
> **Status**: Verified Security Prototype / MVP (100 Passing Automated Tests)

---

## 1. Executive Summary
**TraceGuard AI** is a security authorization gateway prototype, controlled testing laboratory, and reproducible benchmark platform for tool-using AI agents.

In traditional AI agent systems, model outputs are often connected directly to execution environments, leaving systems vulnerable to **direct prompt injection**, **indirect prompt injection**, **privilege escalation**, and **side-channel data exfiltration**.

TraceGuard AI solves this by enforcing **Zero-Trust for Model Outputs**:
- Every tool action proposed by an agent passes through a server-side authorization gateway.
- Enforces explicit policies with a strict **deny-by-default** stance.
- Operates 100% offline without external model API keys using a deterministic mock agent.
- Seamlessly integrates with live models (Groq `llama-3.3-70b-versatile`) when configured.
- Automatically redacts sensitive synthetic PII, tokens, and secrets from audit logs.
- Measures honest, non-fabricated security metrics from repeatable test suites.

---

## 2. Architecture & Design Principles

```
  [ User / Adversary Prompt ]
             │
             ▼
  ┌────────────────────────┐
  │      Agent Layer       │   ◄── Deterministic Mock Agent OR Groq Adapter
  └──────────┬─────────────┘
             │ (Proposes Tool Invocation)
             ▼
  ┌────────────────────────────────────────────────────────┐
  │             Server-Side Security Gateway               │
  │  - Validate tool names & schemas                       │
  │  - Enforce Deny-by-Default policies                    │
  │  - Sanitize arguments & compute deterministic hashes   │
  └──────────┬─────────────────────────────────────────────┘
             │
             ├──► Decision == DENY ──► Bypass Tool Execution (Zero Exposure)
             │
             └──► Decision == ALLOW
                        │
                        ▼
       ┌────────────────────────────────┐
       │   Sandboxed Controlled Tools   │
       │   - read_file                  │
       │   - query_database             │
       │   - send_email                 │
       └────────────────┬───────────────┘
                        │
                        ▼
       ┌────────────────────────────────┐
       │ Post-Execution Data Inspection │
       │   - Verified zero leak checks  │
       │   - Sensitive values redacted  │
       └────────────────┬───────────────┘
                        │
                        ▼
       ┌────────────────────────────────┐
       │  Structured Audit Persistence  │
       │  - SQLite tamper-evident logs  │
       └────────────────────────────────┘
```

See the full [Architecture Documentation](docs/ARCHITECTURE.md) and [Threat Model](docs/THREAT_MODEL.md).

---

## 3. Controlled Security Lab (Zero External Keys Required)

TraceGuard AI includes a deterministic security lab running purely on synthetic data:

### Controlled Tools
1. **`read_file(path)`**:
   - Sandboxed to `backend/data/sandbox/files/`.
   - Whitelists `public/` and `internal/`.
   - Blocks directory traversal escapes (`../`) and protected files (`restricted/credentials.env`, `restricted/customer_ssn_export.csv`).
2. **`query_database(query)`**:
   - Executes queries against a synthetic SQLite database (`backend/data/sandbox/sandbox_db.sqlite`).
   - Allows read-only SELECT queries on public catalog tables (`products`, `faq`).
   - Blocks destructive DDL/DML mutations (`DROP`, `DELETE`, `UPDATE`) and confidential tables (`api_tokens`, `user_profiles`).
3. **`send_email(to, subject, body)`**:
   - Sandboxed outbox with zero external transmission.
   - Allows only internal domain addresses (`*@traceguard.internal`).
   - Blocks external destinations (`*@evil.com`, `*@attacker.net`) and screens for PII exfiltration.

### Synthetic Test Assets
- **Protected Credentials**: `backend/data/sandbox/files/restricted/credentials.env`
- **Protected PII Export**: `backend/data/sandbox/files/restricted/customer_ssn_export.csv`
- **Indirect Prompt Injection Files**:
  - `external_incoming/vendor_invoice.txt` (invoice with hidden instruction to email recon dropzone)
  - `external_incoming/support_ticket_404.txt` (ticket with embedded SQL injection to dump vault tokens)

---

## 4. Quick Start & Local Run Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Node.js 18+ (tested on Node v24)
- Git

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/harshaoffcial23-tech/traceguard-ai.git
cd traceguard-ai

# Copy example environment configuration
cp .env.example .env
```

### 2. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Windows Command Prompt (cmd):
.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Run backend server (serves API on port 8000)
python backend/run.py
```
Backend API will be active at `http://127.0.0.1:8000`. Swagger documentation is available at `http://127.0.0.1:8000/docs`.

### 3. Frontend Setup (Development Mode)
```bash
cd frontend
npm install
npm run dev
```
Open your browser to `http://localhost:5173`. The Vite development server automatically proxies `/api` calls to the FastAPI backend.

### 4. Single-Port Serving Mode (Consolidated Dashboard & API)
Build the frontend and run the Python server:
```bash
cd frontend
npm run build
cd ..
python backend/run.py
```
FastAPI automatically serves the pre-built React dashboard and all REST endpoints directly at `http://127.0.0.1:8000`.

---

## 5. End-to-End Verification Demonstration

TraceGuard AI includes an automated end-to-end verification script reproducing all required demonstration stages:

```bash
python scripts/demo_e2e.py
```

### Demonstration Flow:
1. **Legitimate Request**: An authorized mock tool (`read_file` on `public/company_handbook.txt`) executes successfully.
2. **Malicious Request**: An exfiltration request (`send_email` to `hacker@evil.com`) is submitted.
3. **Gateway Denial**: The gateway intercepts and denies the tool invocation **before execution** (`executed = False`).
4. **Audit Evidence**: Structured audit log shows sanitized arguments (`[REDACTED_SSN]`, `[REDACTED_SECRET]`) and confirms **zero data exposure**.
5. **Policy Regression**: Switches active policy from **Strict Zero-Trust** (100% block rate) to **Permissive** (33% block rate), demonstrating policy regression comparison and vulnerability exposure.
6. **Live AI Agent Integration**: Verifies the Groq adapter with safe fallback when credentials are not supplied.

---

## 6. Running Tests

Execute the comprehensive automated test suite with `pytest`:

```bash
# Run all 100 unit, security, integration, and adversarial tests
pytest -v
```

### Test Coverage (100 Automated Tests Across 13 Test Modules)
- `test_adversarial_gateway.py` (19 tests): Comprehensive fuzzing, nested payloads, Unicode normalization bypasses, tainted argument propagation, and adversarial evasion attacks.
- `test_tools.py` (6 tests): Sandboxed `read_file`, `query_database`, `send_email`, and directory traversal confinement.
- `test_gateway_and_policies.py` (11 tests): Deny-by-default enforcement, allow rules, SQL mutation blocking, and unregistered tool rejection.
- `test_redactor_and_exposure.py` (6 tests): Regex pattern masking (SSN, API keys, passwords) and exposure verification.
- `test_runner_and_mock_agent.py` (5 tests): Mock agent flows, indirect injection interception, and metrics calculation.
- `test_api_endpoints.py` (9 tests): REST routes for health, policies, suites, runs, playground, emergency stop, autonomous agents, and findings.
- `test_autonomous_agent.py` (3 tests): Multi-step goal planning, dynamic memory chaining, safe recovery after denial, and agent gateway isolation.
- `test_limits_and_emergency_stop.py` (4 tests): Emergency stop kill switch, session action limits, consecutive denial circuit breaker, and agent identity validation.
- `test_multilingual_security.py` (5 tests): Multilingual prompt injection defense across English, Telugu (తెలుగు), Hindi (हिन्दी), Tamil (தமிழ்), and Code-mixed (Hinglish/Tanglish/Tenglish).
- `test_auth_and_protection.py` (8 tests): PBKDF2 password hashing, constant-time verification, session expiration, CSRF header validation, and role enforcement.
- `test_security_remediation.py` (10 tests): Explicit CORS origin validation, role self-assignment prevention, rate limiting, and WAL concurrency.
- `test_live_integrations.py` (9 tests): Real-world Groq LLM and Tavily search integration tests with offline graceful fallbacks.
- `test_playground_consistency.py` (5 tests): Playground and interactive simulator contract verification.

---

## 7. Real AI-Agent Integration (Groq & Tavily)

TraceGuard AI is designed with pluggable adapters:
- **Groq Adapter** (`app.agents.groq_adapter.GroqAgent`):
  - Model: `llama-3.3-70b-versatile` (or `llama-3.1-8b-instant`).
  - To enable: Set `GROQ_API_KEY=your_key` in `.env` or input directly in the Live Playground UI.
  - Every model-proposed tool call is validated through the same Security Gateway.
  - Features fail-safe protection against timeouts, malformed responses, and provider errors.
- **Tavily Adapter** (`app.agents.tavily_adapter.TavilySearchAdapter`):
  - Simulates or executes web search for indirect prompt injection testing.
  - Content retrieved from external queries is strictly treated as untrusted and never bypasses gateway authorization.

---

## 8. Deployment Configuration

### Docker Deployment
Build and run using Docker:
```bash
docker build -t traceguard-ai .
docker run -p 8000:8000 traceguard-ai
```

### Docker Compose
```bash
docker compose up -d
```

---

## 9. Known Limitations
1. **Dynamic SQL Dialect Complexity**: SQLite AST matching covers standard SQL injection patterns and mutation keywords. Highly exotic vendor-specific SQL stored procedures require vendor-specific AST parsers.
2. **Context Window Limits**: Multi-step indirect injection with very large document contexts (>100k tokens) depends on model context window capacities when using external LLM providers.
3. **Network Isolation**: The controlled mock outbox intentionally stores messages locally without SMTP transmission. Production email dispatches require explicit SMTP connector integration.
4. **Prototype Scope**: Built as a security research benchmark, evaluation laboratory, and gateway prototype. Deploying to multi-tenant cloud environments would require distributed cache clustering (e.g., Redis for rate limiting and session stores) and HSM/KMS-backed secret vaults rather than single-node SQLite persistence.

---

## 10. License
TraceGuard AI is released under the MIT License.
