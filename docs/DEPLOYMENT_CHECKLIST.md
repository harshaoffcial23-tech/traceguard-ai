# TraceGuard AI — Deployment Readiness & Production Operations

## 1. Architecture & Execution Model
TraceGuard AI operates as an out-of-band reverse proxy and policy enforcement point for autonomous AI agents.

```
+------------------+         +-------------------------------+         +-----------------------+
|  External Agent  | ------> |  TraceGuard Security Gateway  | ------> | Controlled Tool Sand- |
| (OpenAI / Groq / |         | - Schema Validation           |         | box (Files / DB /     |
|  LangChain / SDK)| <------ | - Zero-Trust Policy Engine    |         | Simulated Outbox)     |
+------------------+         | - Tamper-Evident Hash Chain   |         +-----------------------+
                             +-------------------------------+
```

---

## 2. Environment Variables & Secret Configuration

Configure secrets exclusively through environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Never commit real secrets to source control.

| Environment Variable | Description | Production Requirement | Default in Dev |
|---|---|---|---|
| `APP_ENV` | Runtime environment (`production`, `staging`, `development`) | Required | `development` |
| `GROQ_API_KEY` | API key for live Groq LLM inference | Required for live agent mode | Empty (offline harness) |
| `TAVILY_API_KEY` | API key for Tavily live web research | Optional | Empty (simulated research) |
| `COOKIE_SECURE` | Enforces `Secure` flag on session cookies | **Must be `true` in production (HTTPS)** | `false` in dev HTTP |
| `SECRET_KEY` | PBKDF2 / Session hashing salt key | **Must generate 64+ char random hex** | Internal default |
| `TRACEGUARD_DEV_KEY` | Internal development dispatch token | **Disable / rotate in production** | `tg_agent_dev_token_2026` |

---

## 3. Health Checks & Probes

| Endpoint | Method | Expected Status | Purpose |
|---|:---:|:---:|---|
| `/api/health` | `GET` | `200 OK` | Liveness and readiness probe for Kubernetes / load balancers. Returns service status, policy set name, and provider connectivity. |
| `/api/gateway/emergency-stop` | `GET` | `200 OK` | Reports whether the operational kill-switch is engaged (`STOPPED` vs `OPERATIONAL`). |
| `/api/audit/verify-chain` | `GET` | `200 OK` | Continuous integrity probe: verifies the SHA-256 cryptographic hash-chain across all recorded audit events. |

---

## 4. Structured Logging & Error Handling

1. **Fail-Closed Principle**:
   - If policy evaluation fails, unhandled exceptions occur, or database connectivity drops, the gateway fails closed (`DENY` or `ERROR`). Tools are never executed.
2. **Safe Error Masking**:
   - Stack traces, database connection strings, and internal system paths are masked in API responses. Clients receive structured error messages (`Blocked by Security Gateway: ...`).
3. **PII and Secret Redaction**:
   - All tool arguments and outputs are scrubbed through `redact_value()` before persisting to SQLite or logging to stdout.

---

## 5. Limitations & Production Blockers

The following items are identified as pre-production requirements for multi-tenant enterprise deployment:

1. **Multi-Tenancy Isolation**:
   - *Current State*: The platform enforces role-based access control (`admin`, `operator`, `developer`) and per-agent identities. All records reside within a shared SQLite database.
   - *Production Blocker*: True cryptographic or schema-level multi-tenant database isolation is not implemented. For multi-tenant hosting, migrate to Postgres with Row-Level Security (RLS) or dedicated tenant schemas.
2. **Database Engine**:
   - *Current State*: High-performance SQLite with Write-Ahead Logging (`WAL`) mode and 5000ms busy timeouts.
   - *Production Recommendation*: High-concurrency deployments (>1,000 requests/sec) should migrate to clustered PostgreSQL.
3. **Independent Penetration Testing**:
   - *Current State*: 114 automated tests covering all OWASP LLM categories.
   - *Production Blocker*: Formal third-party penetration testing and SOC2 compliance audits are marked **PENDING**.

---

## 6. Pre-Deployment Verification Checklist

- [ ] All 114 automated tests pass cleanly (`.venv\Scripts\python.exe -m pytest`).
- [ ] Frontend builds with zero TypeScript errors (`npm --prefix frontend run build`).
- [ ] Integration client runs successfully (`python examples/external_agent_client.py`).
- [ ] No `.env` or real API keys committed to Git repository.
- [ ] Git working tree is clean and synchronized with upstream.
- [ ] Audit hash-chain verification reports valid signature status.
- [ ] Emergency stop toggle halts tool executions in under 5ms.
- [ ] Outbox email tool remains strictly isolated to mock delivery (zero external network emails).
