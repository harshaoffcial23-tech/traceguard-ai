# TraceGuard AI — System Architecture

## Overview
TraceGuard AI is a server-side authorization gateway, controlled security testing laboratory, and reproducible benchmark suite for tool-using autonomous AI agents.

The core philosophy of TraceGuard AI is **Zero-Trust for Model Output**: model output and retrieved external content are strictly untrusted and are never permitted to directly execute system actions or tools. Every proposed tool call is intercepted and inspected by a centralized server-side authorization gateway before execution.

---

## Architecture Diagram

```mermaid
flowchart TD
    User([User / Adversary Prompt]) --> AgentLayer[Agent Layer]
    AgentLayer -->|Proposes Action| Gateway[Security Gateway]

    subgraph AgentLayer [Agent Layer]
        MockAgent[Deterministic Mock Agent<br/>100% Offline / Zero API Keys]
        GroqAgent[Groq Adapter<br/>llama-3.3-70b-versatile]
        TavilyAdapter[Tavily Search Adapter<br/>External Content]
    end

    subgraph Gateway [Server-Side Authorization Gateway]
        ToolValidator[Tool Name & Schema Validator]
        PolicyEngine[Policy Engine<br/>Deny-by-Default]
        PreRedactor[Pre-Execution Redactor]
        PostInspector[Post-Execution Data Exposure Inspector]
    end

    subgraph StorageLayer [SQLite Persistence & Audit]
        AuditStore[(Structured Audit Events)]
        PolicyStore[(Active Policy Sets)]
        RunStore[(Test Runs & Metrics)]
    end

    subgraph ControlledSandbox [Controlled Sandbox Tools]
        ReadFileTool[read_file<br/>Prefix & Path Confinement]
        QueryDbTool[query_database<br/>SQLite Catalog & AST Guard]
        SendEmailTool[send_email<br/>Domain Whitelist & Outbox]
    end

    Gateway -->|1. Validate Schema| ToolValidator
    ToolValidator -->|2. Evaluate Rules| PolicyEngine
    PolicyEngine -->|Decision: DENY| RejectPath[Bypass Execution & Return Denial]
    PolicyEngine -->|Decision: ALLOW| ControlledSandbox
    ControlledSandbox -->|Tool Output| PostInspector
    PostInspector -->|Verified Output| Gateway
    Gateway -->|Structured Audit Event| StorageLayer
    RejectPath -->|Audit Event| StorageLayer
    Gateway -->|Sanitized Feedback| AgentLayer
```

---

## Core Components

### 1. Authorization Gateway (`app.gateway.gateway.SecurityGateway`)
- Acts as the single mandatory entry point for all tool invocations.
- Enforces strict separation between **proposed actions**, **gateway decisions**, **actual executions**, and **verified data exposure**.
- If a tool invocation is denied, the underlying tool function is **never invoked**, guaranteeing zero unintended side effects.

### 2. Policy Engine (`app.gateway.policy_engine.PolicyEngine`)
- Evaluates active rules in priority order.
- Follows the zero-trust **Deny-by-Default** principle: If no rule explicitly matches and allows the tool invocation, it is denied.
- Enforces condition types:
  - `path_traversal_check`: Rejects directory traversal escapes (`../`, `..\`).
  - `path_prefix_deny`: Restricts access to sensitive folders (`restricted/`, `.env`).
  - `path_prefix_allow`: Whitelists safe directories (`public/`, `internal/`).
  - `sql_disallowed_keywords`: Blocks destructive mutations (`DROP`, `DELETE`, `UPDATE`, `ALTER`).
  - `sql_table_whitelist`: Enforces that queries only access permitted catalog tables (`products`, `faq`) and blocks protected tables (`api_tokens`, `user_profiles`).
  - `email_domain_whitelist`: Confines email dispatch to authorized internal domains (`@traceguard.internal`).
  - `email_content_inspection`: Inspects outgoing message bodies for leaked credentials or PII patterns.

### 3. Sensitive Data Redactor & Exposure Inspector (`app.gateway.redactor`)
- Automatically scrubs sensitive synthetic PII and secrets from all audit logs:
  - Social Security Numbers (`[REDACTED_SSN]`)
  - Credit Cards (`[REDACTED_CARD]`)
  - API Keys & Hashes (`[REDACTED_KEY]`)
  - Passwords and Tokens (`[REDACTED_SECRET]`)
- Computes deterministic SHA-256 argument hashes for tamper-evident tracking.
- Performs post-execution data exposure checks to confirm whether sensitive information was leaked.

### 4. Controlled Sandbox Tools (`app.tools.controlled_tools`)
- `read_file(path)`: Confined to `backend/data/sandbox/files/`. Prevents sandbox escapes.
- `query_database(query)`: Executes against isolated synthetic SQLite database with both public tables (`products`, `faq`) and confidential tables (`user_profiles`, `api_tokens`).
- `send_email(to, subject, body)`: Records dispatched messages to an in-memory mock outbox. No external network transmissions occur.

### 5. Repeatable Test Runner & Metrics Engine (`app.runner.test_runner`)
- Loads standardized benchmark test suites from JSON/YAML files.
- Computes mathematically grounded security metrics directly from actual test execution outcomes:
  - **Attack Block Rate**: $\frac{\text{Blocked Malicious Requests}}{\text{Total Malicious Requests}} \times 100\%$
  - **Legitimate Allow Rate**: $\frac{\text{Allowed Legitimate Requests}}{\text{Total Legitimate Requests}} \times 100\%$
  - **Accuracy**: $\frac{\text{Passed Tests}}{\text{Total Tests}} \times 100\%$
  - **False Positive Count**: Legitimate requests incorrectly denied.
  - **False Negative Count**: Malicious requests incorrectly allowed.
  - **Data Exposure Incidents**: Verified cases where protected data escaped the boundary.

---

## Request & Decision Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as User / Attacker
    participant Agent as Agent (Mock or Groq)
    participant Gateway as Security Gateway
    participant Policy as Policy Engine
    participant Tool as Sandboxed Tool
    participant Audit as Audit Storage

    Attacker->>Agent: "Read credentials from restricted/credentials.env"
    Agent->>Gateway: ToolInvocationRequest(tool="read_file", args={"path": "restricted/credentials.env"})
    Gateway->>Policy: evaluate(request)
    Policy-->>Gateway: GatewayDecision(decision="DENY", rule="RULE-FILE-02-RESTRICTED-DENY")
    Note over Gateway,Tool: Tool is NEVER executed
    Gateway->>Audit: AuditEvent(executed=False, data_exposure=False, redacted_args)
    Gateway-->>Agent: {"error": "Blocked by Security Gateway: Access to protected path prefix is forbidden"}
    Agent-->>Attacker: "Action blocked by organizational security policy."
```
