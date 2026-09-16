# PhaseOne10841 — phaseone-core v0.1

**Defensive Agent Security Gateway** (Agent EDR foundation).  
Watches autonomous agents the way CrowdStrike watches endpoints — **outside** the agent, not via prompt-only hope.

> DEFENSIVE ONLY. No exploit PoCs, attack payloads, or offensive tooling.

Website concept: [PhaseOne10841.me](https://phaseone10841.me)

## What you get

| Component | Role |
|-----------|------|
| **gateway** | OpenAI-compatible `/v1/chat/completions` proxy + policy enforcement + approval API |
| **policy** | YAML engine: domain default-deny, shell deny-by-default, path/credential blocks, secret egress, MCP allowlist, spawn limits, destructive approval |
| **recorder** | Postgres event store (tool → args → destination → result) |
| **canaries** | Harmless marker files + detector (high-severity on touch) |
| **dashboard** | Counts, incidents, approval controls, session timeline/replay |
| **examples** | Sample client through the proxy |

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

Services:

| Service | URL |
|---------|-----|
| Gateway | http://localhost:8080 |
| Dashboard | http://localhost:3000 |
| Postgres | localhost:5432 (`phaseone` / `phaseone` / `phaseone`) |

Health: `curl http://localhost:8080/health`

### Run the example client

```bash
docker compose up -d
npm install
npm run example
# or: GATEWAY_URL=http://localhost:8080 npx tsx examples/sample-client.ts
```

### Tests (no Docker required)

```bash
npm install
npm test
```

## Point agents through the proxy

Any OpenAI-compatible SDK can target the gateway:

```ts
import OpenAI from 'openai';

const client = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: 'unused-for-mock', // upstream key is configured on the gateway
  defaultHeaders: {
    'X-PhaseOne-Agent-Id': 'my-agent',
    'X-PhaseOne-Session-Id': crypto.randomUUID(),
  },
});

const res = await client.chat.completions.create({
  model: 'phaseone-mock', // or your upstream model id
  messages: [{ role: 'user', content: 'Hello' }],
});
```

### Upstream providers

Set in `.env` / compose:

| `UPSTREAM_PROVIDER` | Notes |
|---------------------|--------|
| `mock` (default) | Inert local echo — no API key needed |
| `openai` | Uses `OPENAI_API_KEY` + `OPENAI_BASE_URL` |
| `ollama` | Uses `OLLAMA_BASE_URL` (default `http://host.docker.internal:11434/v1`) |
| `openrouter` | Uses `OPENROUTER_API_KEY` + `OPENROUTER_BASE_URL` |

Restart gateway after changing provider: `docker compose up -d gateway`

### Tool enforcement (sidecar hook)

Agents / runtimes should call the enforce API **before** executing tools:

```bash
curl -s http://localhost:8080/v1/phaseone/tools/enforce \
  -H 'content-type: application/json' \
  -d '{
    "agent_id": "my-agent",
    "session_id": "…",
    "tool_name": "http_request",
    "arguments": {"url":"https://evil.example","method":"GET"}
  }'
```

Denied actions return `403` and are logged. Destructive tools return `202` with an `approval_id` until approved in the dashboard or via:

```bash
curl -X POST http://localhost:8080/v1/phaseone/approvals/<id>/approve
curl -X POST http://localhost:8080/v1/phaseone/approvals/<id>/deny
```

## Policy highlights

See `policy/default-policy.yaml`:

- **Domains**: allowlist / default-deny
- **Shell**: deny-by-default with safe command allow_patterns
- **Filesystem**: blocked `.env`, SSH keys, credential dirs; allowed roots only
- **Secrets**: pattern detection on egress
- **Canaries**: marker values from `canaries/files/*` → deny + critical event
- **MCP**: server allowlist
- **Spawn**: max depth
- **Destructive**: `delete_file`, DROP, force-push, etc. → human approval queue

## Canaries

Harmless markers in `canaries/files/`:

- `AWS_PRODUCTION_KEY.txt`
- `customer_database_password.txt`
- `github_admin_token.txt`
- `production.env`
- `payroll.csv`

**Do not replace with real secrets.** They exist so detectors can fire safely.

## Dashboard

http://localhost:3000 shows:

- Active agents, tool calls, shell, domains, blocked, canaries, prompt-injection hits, A2A, approvals
- Click an incident → session timeline / replay
- Approve / deny destructive actions

## Layout

```
PhaseOne10841ME/
  docker-compose.yml
  Dockerfile
  README.md
  .env.example
  gateway/       # OpenAI-compatible proxy + enforcement
  policy/        # YAML + engine
  recorder/      # Postgres writers / queries
  canaries/      # marker files + detector
  dashboard/     # web UI
  db/            # SQL migrations
  examples/      # sample client
  tests/         # vitest policy + canary/secret tests
  shared/        # types, secret + injection helpers
```

## What works vs stubbed (v0.1)

| Feature | Status |
|---------|--------|
| Chat completions proxy (mock/openai/ollama/openrouter) | **Works** |
| Policy engine (real checks) | **Works** |
| Event recording to Postgres | **Works** |
| Canary + secret detection | **Works** |
| Destructive approval queue + API + dashboard | **Works** |
| Prompt-injection detector (heuristics) | **Works** (detect only) |
| Dashboard counts + timeline | **Works** |
| Tool/HTTP/FS/shell/MCP monitoring hooks | **Works** via enforce + event APIs |
| In-process OS syscall FS/shell interception | **Stubbed** — agents must route tools through `/v1/phaseone/tools/enforce` |
| Full MCP protocol proxy | **Stubbed** — `mcp_call` enforce path logs/blocks; not a full MCP wire proxy |
| Multi-tenant SaaS | Out of scope |

## License

MIT — see `LICENSE`.
