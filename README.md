# PhaseOne10841 — Defensive Agent Security Gateway (Agent EDR)

**phaseone-core v0.5.0**

Watches autonomous agents the way CrowdStrike watches endpoints — **outside** the agent, not via prompt-only hope.

> **DEFENSIVE ONLY.** No exploit PoCs, attack payloads, malware, or offensive tooling. The lab uses inert fixtures and detectors only.

**A product of [Veracity Integrity LLC](https://VeracityIntegrity.com)** · https://VeracityIntegrity.com  
Website concept: [PhaseOne10841.me](https://phaseone10841.me)

> **Repository access:** The PhaseOne10841 product repository is **private** (commercial / licensed distribution). Contact Veracity Integrity LLC via https://VeracityIntegrity.com for access, evaluation, or deployment support. This README documents the software as shipped to authorized operators.

---

## What it is

PhaseOne10841 is a **defensive Agent EDR / security gateway** for LLM agents and agent frameworks. It sits in the path of:

- OpenAI-compatible chat completions
- Tool calls (HTTP, filesystem, shell, MCP)
- Agent-to-agent (A2A) messages
- Untrusted tool / RAG / MCP results

…and applies **policy enforcement, recording, detection, human approval, canaries, SIEM export, metrics, and alerts** — without requiring the agent itself to “behave.”

### Who it’s for

| Audience | Use |
|----------|-----|
| **Security / platform teams** | Put a control plane in front of agents before production tool access |
| **AI engineering leads** | Route LangChain / CrewAI / OpenAI SDK traffic through a single gateway |
| **SOC / detection engineers** | Consume JSONL / webhooks / Prometheus metrics; tune YAML detection rules |
| **Compliance / risk** | Audit admin actions, approvals, session replay, secret egress blocks |

---

## Architecture

```mermaid
flowchart LR
  subgraph Clients
    A[Agents / SDKs]
    B[A2A peers]
    C[Tool hooks]
  end
  subgraph PhaseOne["PhaseOne10841 Gateway"]
    G[Hono proxy + middleware]
    P[Policy YAML]
    R[Detection rules]
    E[Enforce / approve]
    M[Metrics / alerts]
  end
  subgraph Data
    DB[(Postgres)]
    CAN[Canaries]
    SIEM[SIEM JSONL / webhooks]
  end
  D[Dashboard MFA + RBAC]
  U[Upstream LLM mock/OpenAI/Ollama/OpenRouter]

  A --> G
  B --> G
  C --> G
  G --> E
  E --> P
  E --> R
  E --> DB
  E --> CAN
  E --> M
  M --> SIEM
  G --> U
  D --> G
  D --> DB
```

**Security model:** Enforcement lives **outside** the model. Agents cannot “talk their way” past gateway deny/approval/canary checks. Prompts are scanned; tools are evaluated against YAML policy; high-severity events can page a webhook.

---

## Features by phase

### Phase 1 — Core gateway
- OpenAI-compatible `/v1/chat/completions` proxy
- YAML policy (domains default-deny, shell deny-by-default, FS roots, destructive → approval)
- Postgres event recorder + sessions
- Harmless canary markers + detector
- Basic dashboard

### Phase 2 — Agent defenses
- Prompt-injection scanner (source-classified)
- Tool Permission Analyzer
- A2A firewall (trust levels)
- Lab harness (inert stubs + labeled fixtures)

### Phase 3 — Operations
- Terminal `npm run onboard`
- MFA admin console (email OTP)
- Approval UX + timeout / expire
- SIEM ECS-ish JSONL + webhook
- Secret-egress hardening + deep redaction
- MCP allowlist on `mcp_call`
- Deep session replay
- Policy editor (safe YAML)

### Phase 4 — Product hardening
| Feature | Behavior |
|---------|----------|
| **Admin audit log** | Login, approve/deny, policy save, export, settings, canary rotate, A2A trust |
| **Policy save path** | Validated YAML; backup previous version; reject invalid / disallowed keys |
| **Detection rules engine** | Sigma-ish YAML in `rules/` |
| **Canary management** | List, safely rotate markers, show last trigger |
| **A2A trust admin** | List/set trust levels via API + settings UI |
| **Health & readiness** | `/healthz`, `/readyz`; Compose healthchecks |
| **Prometheus metrics** | `/metrics` |
| **Framework adapters** | OpenAI-compatible + stubs for LangChain, CrewAI, Claude-style |
| **Alerting** | Webhook on canary / injection blocked / approval timeout |
| **RBAC lite** | Admin vs viewer emails |

### Phase 5 — Deployable local product (this release)
| Feature | Behavior |
|---------|----------|
| **OpenAPI** | [`docs/openapi.yaml`](docs/openapi.yaml) covering gateway + admin auth surface |
| **Rate limiting** | OTP request limits; API abuse limits on public-ish endpoints; documented in [`docs/operations.md`](docs/operations.md) |
| **Retention & cleanup** | `npm run retention` (+ onboard env `PHASEONE_RETENTION_DAYS`) |
| **Backup / restore** | `npm run backup` / `./scripts/restore.sh` — Postgres + policy + rules |
| **Docker harden** | `restart: unless-stopped`, non-root `user: 1000:1000`, extended healthchecks, resource-limit notes |
| **Smoke tests** | `npm run smoke` after `docker compose up` |
| **Admin UX** | Ops / Phase 5 nav: retention, rate limits, cookie/security notes |
| **Security defaults** | Shared security headers + CSP; Secure cookie docs (`PHASEONE_SECURE_COOKIES`) |
| **Adapter docs** | Copy-paste OpenAI / curl / Python “point through PhaseOne” examples |

---

## Quick start — local Docker (Phase 5)

### 1. Onboard

```bash
npm install
npm run onboard                 # interactive — Veracity Integrity banner
# or CI / non-interactive:
npm run onboard -- --defaults
```

Writes `.env` with MFA emails, SMTP or OTP fallback, DB, session secret, upstreams, SIEM, alerts, rules, **retention**, **API/OTP rate limits**, **backup dir**, ports.

### 2. Compose up

```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| Gateway | http://localhost:8080 |
| Dashboard | http://localhost:3000 |
| Postgres | localhost:5432 (`phaseone` / `phaseone` / `phaseone`) |
| OpenAPI | [`docs/openapi.yaml`](docs/openapi.yaml) |

```bash
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/readyz
curl -s http://localhost:8080/metrics | head
curl -s http://localhost:3000/healthz
```

### 3. Smoke test

```bash
npm run smoke
```

Hits healthz/readyz/metrics, mock chat path, policy deny (dangerous shell), canary detect, Phase 5 ops endpoint.

### 4. MFA login (dashboard)

1. Open http://localhost:3000  
2. Enter an allowlisted **admin** or **viewer** email  
3. **Send code** → read OTP from logs / `PHASEONE_OTP_FALLBACK_FILE` if SMTP unset  
4. Enter code → console (viewers are read-only)

Disable auth for local demos only: `PHASEONE_DASHBOARD_AUTH=false` (not recommended).

### 5. Unit tests (no Docker required)

```bash
npm install
npm test
```

### 6. Lab / permissions / retention / backup

```bash
npm run lab
npm run permissions
npm run retention -- --dry-run --days 30
npm run backup
```

---

## Configuration reference

Prefer `npm run onboard`. Key variables (see `.env.example`):

| Variable | Purpose |
|----------|---------|
| `PHASEONE_ADMIN_EMAILS` | Comma-separated admins (full access) |
| `PHASEONE_VIEWER_EMAILS` | Comma-separated viewers (read-only) |
| `PHASEONE_DASHBOARD_AUTH` | `true`/`false` |
| `PHASEONE_SESSION_SECRET` | Session signing material (auto-generated by onboard) |
| `PHASEONE_OTP_FALLBACK_FILE` | Dev OTP log path when SMTP unset |
| `PHASEONE_SECURE_COOKIES` | `true` when serving dashboard over HTTPS |
| `SMTP_*` | Optional OTP email delivery |
| `DATABASE_URL` | Postgres |
| `UPSTREAM_PROVIDER` | `mock` \| `openai` \| `ollama` \| `openrouter` |
| `GATEWAY_PORT` / `DASHBOARD_PORT` / `GATEWAY_URL` | Ports / dashboard→gateway |
| `PHASEONE_APPROVAL_TIMEOUT_MS` | Approval wait/expire |
| `PHASEONE_SIEM_WEBHOOK_URL` | SIEM batch webhook |
| `PHASEONE_ALERT_WEBHOOK_URL` | High-severity alert webhook |
| `PHASEONE_RULES_DIR` | Detection rules directory |
| `PHASEONE_METRICS_ENABLED` | Metrics flag |
| `PHASEONE_RETENTION_DAYS` | Event retention (default 30) |
| `PHASEONE_API_RATE_LIMIT` | Gateway API abuse limit per window (default 120) |
| `PHASEONE_API_RATE_WINDOW_MS` | API rate window (default 60000) |
| `PHASEONE_OTP_RATE_LIMIT` | OTP requests per window (default 5) |
| `PHASEONE_BACKUP_DIR` | Backup output root (default `./backups`) |
| `PHASEONE_POLICY_PATH` | Override policy YAML path |

Full ops detail: [`docs/operations.md`](docs/operations.md).

---

## Policy, rules, canaries, A2A, SIEM, metrics, alerts

### Policy (`policy/default-policy.yaml`)

- Domains allowlist / default-deny · Shell deny-by-default · FS roots  
- Secrets / canaries block-on-detect · MCP server allowlist + deny_tools  
- Destructive → human approval · `approval.timeout_ms`  
- Admin save validates known keys only and **backs up** the previous file under `policy/backups/`

### Detection rules (`rules/*.yaml`)

Lightweight Sigma-ish rules matching event fields.

### Canaries

Harmless fake markers under `canaries/files/`. Detection fires when values appear in tool args/egress.

### Metrics & alerts

```bash
curl -s http://localhost:8080/metrics
curl -s http://localhost:8080/v1/phaseone/alerts/config
curl -s http://localhost:8080/v1/phaseone/ops
```

---

## Dashboard overview

Behind MFA: **Overview · Incidents · Approvals · Session replay · Agents · Canaries · Injections · A2A trust · Permissions · Policy · SIEM export · Detection rules · Audit log · Lab monitor · Ops / Phase 5 · Settings**

- **Admins** can approve/deny, save policy, rotate canaries, set A2A trust, test alerts  
- **Viewers** see the same read APIs but mutating routes return `403`
- **Ops / Phase 5** shows retention, rate limits, and cookie/security defaults

---

## Point agents through the proxy

### OpenAI-compatible (supported)

```ts
import OpenAI from 'openai';

const client = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: 'unused-for-mock',
  defaultHeaders: {
    'X-PhaseOne-Agent-Id': 'my-agent',
    'X-PhaseOne-Session-Id': crypto.randomUUID(),
  },
});
```

Copy-paste examples (Node, curl, Python) live in [`adapters/README.md`](adapters/README.md).

| `UPSTREAM_PROVIDER` | Notes |
|---------------------|--------|
| `mock` (default) | Inert local echo — no API key |
| `openai` | `OPENAI_API_KEY` + `OPENAI_BASE_URL` |
| `ollama` | `OLLAMA_BASE_URL` |
| `openrouter` | `OPENROUTER_API_KEY` + `OPENROUTER_BASE_URL` |

---

## Lab (defensive only)

`lab/` provides **inert** fake services and labeled `PHASEONE_TEST_*` fixtures. See `lab/README.md`.

> Attack simulators and offensive labs are **out of scope**.

---

## OWASP Agentic themes (high level)

| Theme | PhaseOne control |
|-------|------------------|
| Prompt injection / untrusted content | Scanner + optional block; scan tool/RAG/MCP results |
| Excessive agency / over-permissioned tools | Permission Analyzer; policy allow/deny; destructive → approval |
| Sensitive data / credential leakage | Secret egress patterns; redaction; canaries |
| Insecure plugin / MCP use | MCP server + tool allowlists on `mcp_call` |
| Agent-to-agent trust | A2A firewall with trust levels + injection scan |
| Insufficient monitoring | Event store, session replay, audit log, metrics, alerts, SIEM, retention |

---

## Development & testing

```bash
npm install
npm test                 # vitest — unit tests, no Docker
npm run build            # tsc
npm run migrate          # apply db/migrations/*.sql
npm run smoke            # post-compose smoke (needs services up)
npm run retention -- --dry-run
npm run backup
npm run dev:gateway
npm run dev:dashboard
```

Layout:

```
PhaseOne10841ME/
  scripts/             # onboard, smoke, retention, backup, restore
  docs/                # openapi.yaml, operations.md
  gateway/             # proxy + enforce + phase3/4/5 routes
  policy/              # YAML + engine + backups/
  rules/               # Sigma-ish detection rules
  recorder/            # Postgres + export + timeline
  canaries/            # markers + detector + manager
  dashboard/           # MFA UI + RBAC + Ops view
  adapters/            # framework stubs + copy-paste docs
  lab/                 # inert fixtures
  shared/              # secrets, metrics, audit, rbac, alerting, rate-limit, retention
  db/migrations/
  tests/
  backups/             # npm run backup output
```

---

## What works vs stubbed

| Feature | Status |
|---------|--------|
| Onboard + MFA + RBAC lite | **Works** |
| Audit, rules, metrics, alerts, canary rotate | **Works** (Phase 4) |
| Rate limits, retention, backup/restore, smoke, OpenAPI | **Works** (Phase 5) |
| SIEM JSONL + webhook, deep replay, approval timeout | **Works** (Phase 3) |
| Chat proxy + policy + canaries/secrets | **Works** |
| Injection / permissions / A2A / lab | **Works** (Phase 2) |
| Framework adapters | **OpenAI works**; LangChain/CrewAI/Claude = docs + thin stubs |
| In-process OS syscall interception | **Stubbed** — use `/v1/phaseone/tools/enforce` |
| Full MCP wire proxy | **Stubbed** — `mcp_call` enforce + lab fake-mcp |
| Attack simulator / offensive labs | **Out of scope** |

---

## Roadmap (indicative)

- Richer rule language (aggregations, time windows)  
- Deeper framework SDKs (official LangChain / CrewAI packages)  
- Optional signed canary packages for production deployments  
- Multi-tenant org controls beyond email allowlists  
- Hardened SMTP/OIDC SSO for enterprise MFA  

Roadmap items are aspirational and may change; contact Veracity Integrity LLC for commercial roadmap discussions.

---

## License & company

MIT — Copyright (c) 2026 **Veracity Integrity LLC** — see `LICENSE`.

**https://VeracityIntegrity.com**

Product concept site: https://phaseone10841.me  

Private product repository — distribution to authorized customers and partners only.
