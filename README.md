# PhaseOne10841 — phaseone-core v0.3

**Defensive Agent Security Gateway** (Agent EDR foundation).  
Watches autonomous agents the way CrowdStrike watches endpoints — **outside** the agent, not via prompt-only hope.

> DEFENSIVE ONLY. No exploit PoCs, attack payloads, or offensive tooling.

**A product of [Veracity Integrity LLC](https://VeracityIntegrity.com)** · https://VeracityIntegrity.com  
Website concept: [PhaseOne10841.me](https://phaseone10841.me)

## What you get

| Component | Role |
|-----------|------|
| **onboard** | `npm run onboard` — interactive CLI writes `.env` (MFA, SMTP/fallback, DB, secrets, SIEM, ports) |
| **gateway** | OpenAI-compatible `/v1/chat/completions` proxy + policy enforcement + approval API + Phase 2/3 scanners |
| **policy** | YAML engine: domain default-deny, shell deny-by-default, MCP allowlist, secret egress, approval timeout, SIEM |
| **recorder** | Postgres event store + deep session replay chain + SIEM JSONL/webhook export |
| **canaries** | Harmless marker files + detector (high-severity on touch) |
| **dashboard** | MFA-gated admin UI: overview, incidents, replay, approvals, policy, agents, canaries, injection, A2A, permissions, lab, SIEM, settings |
| **lab/** | Inert fake services + labeled TEST fixtures + detector monitor |
| **examples** | Sample client through the proxy |

## Quick start

### 1. Onboard (recommended)

```bash
npm install
npm run onboard                 # interactive — Veracity Integrity banner
# or for CI / non-interactive:
npm run onboard -- --defaults
```

This writes `.env` with:

- Admin email(s) for MFA OTP
- SMTP **or** console/dev OTP fallback (`PHASEONE_OTP_FALLBACK_FILE`)
- `DATABASE_URL`, auto-generated `PHASEONE_SESSION_SECRET`
- Gateway upstreams, dashboard ports
- Optional SIEM webhook, approval timeout

### 2. Compose

```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| Gateway | http://localhost:8080 |
| Dashboard | http://localhost:3000 |
| Postgres | localhost:5432 (`phaseone` / `phaseone` / `phaseone`) |

Health: `curl http://localhost:8080/health`

### 3. MFA login (dashboard)

1. Open http://localhost:3000
2. Enter an allowlisted admin email (`PHASEONE_ADMIN_EMAILS`)
3. Click **Send code**
4. If SMTP is unset: read the OTP from the dashboard container logs or `PHASEONE_OTP_FALLBACK_FILE` (default `/tmp/phaseone-otp.log`)
5. Enter the 6-digit code → admin console

Disable auth for local demos only: `PHASEONE_DASHBOARD_AUTH=false` (not recommended).

### Tests (no Docker required)

```bash
npm install
npm test
```

### Lab harness / permission analyzer

```bash
npm run lab
npm run permissions
```

## Architecture (Phase 3)

```
                    ┌─────────────────────────────────────────┐
   Agents / SDKs ──►│  Gateway (Hono) + security middleware    │
   A2A peers     ──►│   • chat completions proxy              │
   Tool hooks    ──►│   • /tools/enforce + approval wait/poll │
                    │   • injection / secret-egress / MCP     │
                    │   • SIEM JSONL + webhook export         │
                    │   • deep session replay                 │
                    └───────────┬─────────────────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
         Policy YAML      Recorder/Postgres    Canaries
              │                 │
              ▼                 ▼
         Lab stubs        Dashboard UI (MFA)
```

## Phase 3 features

| Feature | Behavior |
|---------|----------|
| **Terminal onboard** | `npm run onboard` / `--defaults` writes branded `.env` |
| **MFA admin console** | Email OTP (+ SMTP or console/fallback); CSRF-protected mutations |
| **Approval UX** | Risk, reason, expires_at, resolution notes; gateway wait/poll + timeout → expire |
| **SIEM export** | ECS-ish JSONL download + optional webhook sink |
| **Secret-egress hardening** | Broader patterns, deep object redaction in recorder/export |
| **MCP allowlist** | Server + deny_tools / allow_tools enforcement on `mcp_call` |
| **Deep session replay** | Ordered chain agent→tool→args(redacted)→dest→result→next |
| **Policy editor** | Safe YAML PUT (known keys only) from dashboard |

### Useful Phase 3 APIs

```bash
# Session replay (rich timeline)
curl -s http://localhost:8080/v1/phaseone/sessions/<id>/replay

# SIEM JSONL
curl -s 'http://localhost:8080/v1/phaseone/export/events.jsonl?limit=100'

# Webhook sink
curl -s http://localhost:8080/v1/phaseone/export/webhook \
  -H 'content-type: application/json' \
  -d '{"url":"https://siem.example/hooks/phaseone"}'

# Tool enforce with approval wait
curl -s http://localhost:8080/v1/phaseone/tools/enforce \
  -H 'content-type: application/json' \
  -d '{"agent_id":"my-agent","tool_name":"delete_file","arguments":{"path":"/tmp/x"},"wait_for_approval":false}'
```

## Phase 2 defenses (still included)

| Defense | Behavior |
|---------|----------|
| **Prompt-injection scanner** | Source-classified detection; optional block on untrusted |
| **Tool Permission Analyzer** | Capability matrix + excessive-agency findings |
| **A2A Firewall** | Trust levels + injection scan on peer messages |
| **Lab harness** | Inert stubs + labeled `PHASEONE_TEST_INJECTION_*` fixtures |

## Point agents through the proxy

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

### Upstream providers

| `UPSTREAM_PROVIDER` | Notes |
|---------------------|--------|
| `mock` (default) | Inert local echo — no API key needed |
| `openai` | Uses `OPENAI_API_KEY` + `OPENAI_BASE_URL` |
| `ollama` | Uses `OLLAMA_BASE_URL` |
| `openrouter` | Uses `OPENROUTER_API_KEY` + `OPENROUTER_BASE_URL` |

## Policy highlights

See `policy/default-policy.yaml` (v0.3):

- Domains allowlist / default-deny · Shell deny-by-default · FS roots
- Secrets / canaries block-on-detect · MCP server allowlist + deny_tools
- Destructive → human approval · `approval.timeout_ms` / expire_on_timeout
- `siem` JSONL defaults · prompt_injection / a2a / permission_analyzer

## Dashboard views (behind MFA)

Overview · Incidents · Approvals · Session replay · Agents · Canaries · Injections · A2A trust · Permissions · Policy editor · SIEM export · Lab monitor · Settings

## Layout

```
PhaseOne10841ME/
  scripts/onboard.ts   # terminal installer
  docker-compose.yml
  gateway/             # proxy + enforce + middleware + phase3 routes
  policy/              # YAML + engine
  recorder/            # Postgres + export + rich timeline
  canaries/
  dashboard/           # MFA UI + auth
  lab/
  db/migrations/       # 001_init + 002_phase3
  tests/
  shared/
```

## What works vs stubbed

| Feature | Status |
|---------|--------|
| Onboard CLI + MFA dashboard | **Works** (Phase 3) |
| SIEM JSONL + webhook | **Works** (Phase 3) |
| Approval timeout / deep replay | **Works** (Phase 3) |
| Chat proxy + policy + canaries/secrets | **Works** |
| Injection / permissions / A2A / lab | **Works** (Phase 2) |
| In-process OS syscall interception | **Stubbed** — use `/v1/phaseone/tools/enforce` |
| Full MCP wire proxy | **Stubbed** — `mcp_call` enforce + lab fake-mcp |
| Attack simulator / offensive labs | **Out of scope** |

## License

MIT — Copyright (c) 2026 Veracity Integrity LLC — see `LICENSE`.  
https://VeracityIntegrity.com
