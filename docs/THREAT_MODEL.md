# TraceGuard AI — Comprehensive Threat Model & Security Test Plan

## 1. System Scope & Protected Assets
TraceGuard AI sits between autonomous AI agents and sensitive enterprise tools. It intercepts every proposed tool invocation out-of-band and enforces zero-trust policy invariants prior to execution.

Protected enterprise assets:
1. **Confidential Files**: API secrets, database passwords, private keys (`restricted/credentials.env`).
2. **Customer & Employee PII**: Social Security Numbers, salaries, credit card data (`restricted/customer_ssn_export.csv`, `user_profiles`).
3. **Database Integrity**: Public and internal database catalog tables (`products`, `faq`, `api_tokens`).
4. **Communication Outbox**: Email and messaging channels to prevent egress and exfiltration.
5. **Audit Trails**: Cryptographic, hash-linked ledger records ensuring tamper resistance and data privacy.

---

## 2. Trust Boundaries & Threat Actors

| Boundary | Description | Trust Level |
|---|---|---|
| **User Input / Prompt** | Direct prompt input from users, operators, or external callers. | **Untrusted** |
| **Retrieved Content** | External files, invoices, customer support tickets, search results. | **Untrusted** |
| **Model Output** | Tool calls proposed by LLM (Groq, OpenAI, external agent). | **Untrusted** |
| **Security Gateway** | Server-side authorization and policy enforcement boundary. | **Trusted** |
| **Controlled Sandbox** | Isolated filesystem and synthetic SQLite database executor. | **Trusted** |

### Threat Actors:
- **Direct Adversary**: Submits jailbreaks, prompt overrides, or unauthorized tool instructions.
- **Indirect Adversary**: Embeds hidden injection payloads inside documents, invoices, or web search results.
- **Compromised / Hallucinating Agent**: An agent whose outputs are corrupted, loop infinitely, or propose destructive calls.
- **Malicious External Caller**: An unauthenticated or forged caller attempting to access the gateway dispatch API.

---

## 3. Comprehensive Threat Analysis (10 Core Dimensions)

### 1. Prompt Injection & Malicious Tool Requests
- **Threat**: Adversary instructs the model to ignore safety rules and execute unauthorized actions.
- **Enforcement**: Zero-trust deny-by-default architecture. Tool code is physically isolated behind the Gateway. The LLM's text output has zero direct execution capability.
- **Automated Test**: `test_adversarial_gateway.py::test_direct_prompt_injection_file_blocked`

### 2. Unauthorized Tools & Arguments
- **Threat**: Caller requests an unregistered tool (e.g. `execute_shell_command`) or passes malformed/dangerous argument payloads.
- **Enforcement**: Server-side tool registry whitelist and strict argument schema validation reject unknown tools and missing/illegal arguments before policy evaluation.
- **Automated Test**: `test_agent_dispatch_api.py::test_4_invalid_tool_names_rejected`, `test_5_invalid_arguments_rejected`

### 3. Identity Spoofing & Role Privilege Escalation
- **Threat**: A low-privilege agent (`guest` or `readonly_agent`) claims high-privilege identity (`admin_agent`) in its payload to execute privileged actions.
- **Enforcement**: Caller identity is resolved server-side from authentication tokens and the database agent registry. Client-supplied role elevation is rejected (`IDENTITY_ROLE_SPOOF_DENIED`).
- **Automated Test**: `test_limits_and_emergency_stop.py::test_unregistered_agent_identity_rejected`, `test_agent_dispatch_api.py::test_7_missing_or_invalid_identity_rejected`

### 4. Direct Execution Bypass
- **Threat**: Client sends forged authorization fields (`decision: "allow"`, `allowed: true`) in request payloads hoping to bypass the gateway.
- **Enforcement**: Gateway ignores all client-supplied decision fields. The authorized executor is strictly encapsulated within the server-side `gateway.invoke()` boundary.
- **Automated Test**: `test_agent_dispatch_api.py::test_6_forged_authorization_fields_ignored`

### 5. File Access Violations & Path Traversal
- **Threat**: Attacker uses path traversal (`../../restricted/credentials.env`, `..\\..\\windows\\win.ini`) to read unauthorized files outside the sandbox.
- **Enforcement**: Gateway checks traversal patterns (`..`), and sandboxed tool canonicalizes paths and verifies `resolved_path.relative_to(sandbox_root)`.
- **Automated Test**: `test_adversarial_gateway.py::test_path_traversal_blocked`

### 6. SQL Injection & Mutation Restrictions
- **Threat**: Adversary injects SQL statements (`DROP TABLE products; --`, `UNION SELECT * FROM api_tokens`).
- **Enforcement**: AST parser and token scanner reject all mutation verbs (`DROP`, `DELETE`, `UPDATE`, `ALTER`, `INSERT`) and table queries outside the whitelisted catalog.
- **Automated Test**: `test_adversarial_gateway.py::test_sql_destructive_command_blocked`, `test_sql_token_theft_blocked`

### 7. Secret Leakage & Data Redaction
- **Threat**: Credentials, API keys, SSNs, or tokens appear in logs, error messages, or tool outputs.
- **Enforcement**: All inputs, arguments, outputs, and errors pass through `redact_value()` before storage, sanitizing PII and secrets (`[REDACTED_SSN]`, `[REDACTED_SECRET]`).
- **Automated Test**: `test_redactor_and_exposure.py::test_pii_redaction_in_arguments`

### 8. Audit Ledger Manipulation
- **Threat**: An attacker with database access alters past security decisions (e.g. changing `deny` to `allow`) or deletes audit records.
- **Enforcement**: SHA-256 cryptographic hash-chain where each event signs its content and predecessor hash (`previous_event_hash`). `verify_audit_chain()` detects any out-of-band modification, insertion, or deletion.
- **Automated Test**: `test_audit_hash_chain.py::test_tamper_detection_in_audit_chain`

### 9. Cross-User & Cross-Tenant Access
- **Threat**: Operator A inspects or alters agent permissions, API keys, or audit events belonging to Operator B.
- **Current Status / Limitation**: TraceGuard AI currently implements role-based access control (`admin`, `operator`, `developer`) and authenticated user sessions. **Multi-tenant database isolation is currently NOT implemented**; this is a recognized production blocker documented for enterprise rollout.

### 10. Denial of Service, Action Flooding & Timeouts
- **Threat**: An agent enters an infinite loop, issues hundreds of tool requests, or exhausts server resources.
- **Enforcement**:
  1. Per-session action limit (`max_actions_per_session`).
  2. Circuit breaker on repeated consecutive denials (`max_consecutive_denials`).
  3. Execution time limits mapping exceeded durations to `TIMEOUT` without executing tools.
  4. Emergency Stop / kill-switch halting all executions instantly.
- **Automated Test**: `test_limits_and_emergency_stop.py::test_emergency_stop_halts_all_actions`, `test_action_count_limit_enforced`, `test_consecutive_denials_circuit_breaker`

---

## 4. Security Verification Status

| Security Control | Automated Test Suite | Test Count | Result |
|---|---|:---:|:---:|
| Adversarial Invariant Gateway | `test_adversarial_gateway.py` | 19 | **PASSED** |
| Agent Integration API Contract | `test_agent_dispatch_api.py` | 12 | **PASSED** |
| Cryptographic Hash Chain Audit | `test_audit_hash_chain.py` | 2 | **PASSED** |
| Authentication & CSRF Protection | `test_auth_and_protection.py` | 8 | **PASSED** |
| Execution Limits & Emergency Stop | `test_limits_and_emergency_stop.py` | 4 | **PASSED** |
| Live SDK / Groq / Tavily Adapters | `test_live_integrations.py` | 9 | **PASSED** |
| Multilingual Injection Defenses | `test_multilingual_security.py` | 5 | **PASSED** |
| PII & Secret Redaction Engine | `test_redactor_and_exposure.py` | 6 | **PASSED** |

> **Audit Notice**: All 114 automated tests run cleanly in the local CI environment. Independent third-party penetration testing and formal SOC2 / ISO 27001 certifications have **NOT** been performed and are marked **PENDING** for production rollout.
