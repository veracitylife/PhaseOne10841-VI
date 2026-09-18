# Operator MCP (Phase 8 #4)

**PhaseOne10841** management MCP for trusted operator agents.  
**DEFENSIVE ONLY** — read-mostly by default; mutations require admin token, MFA, and RBAC.

Veracity Integrity LLC · https://VeracityIntegrity.com

---

## Overview

The Operator MCP exposes gateway management endpoints as MCP tools over HTTP JSON-RPC. It is intended for **local operator automation** (dashboard assistants, runbooks) — not for agent workloads.

- Package: `@phaseone/operator-mcp` (`mcp-server/`)
- Default bind: `127.0.0.1:8090`
- Gateway proxy target: `GATEWAY_URL` (default `http://127.0.0.1:8080`)

---

## Running

```bash
export PHASEONE_OPERATOR_MCP_TOKEN="<rotate-me>"
export GATEWAY_URL="http://127.0.0.1:8080"
npm run operator-mcp
```

Or via bin:

```bash
tsx mcp-server/src/index.ts
```

Health check: `GET http://127.0.0.1:8090/health`

---

## JSON-RPC API

Endpoint: `POST http://127.0.0.1:8090/`

| Method | Description |
|--------|-------------|
| `initialize` | MCP handshake |
| `tools/list` | List available tools |
| `tools/call` | Invoke a tool (`params.name`, `params.arguments`) |
| `ping` | No-op health |

Example — list tools:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }
```

Example — health:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": { "name": "phaseone_health", "arguments": {} }
}
```

---

## Tools

### Read tools (no admin token)

| Tool | Gateway route | Notes |
|------|---------------|-------|
| `phaseone_health` | `GET /health` | DB + service status |
| `phaseone_gatekeeper_status` | `GET /v1/phaseone/gatekeeper/status` | Queue, pending count, state |
| `phaseone_pending` | `GET /v1/phaseone/gatekeeper/pending` | Actions awaiting confirmation |
| `phaseone_metrics` | `GET /v1/phaseone/metrics` | Counters + Prometheus text |
| `phaseone_recent_events` | `GET /v1/phaseone/events` | Optional `limit`, `event_type`, `session_id`, `severity` |

### Write tools (admin token required)

| Tool | Gateway route | Arguments |
|------|---------------|-----------|
| `phaseone_confirm` | `POST /v1/phaseone/gatekeeper/confirm/:id` | `id`, optional `actor_email` |
| `phaseone_deny` | `POST /v1/phaseone/gatekeeper/deny/:id` | `id`, optional `actor_email` |
| `phaseone_override` | `POST /v1/phaseone/gatekeeper/config` or `.../overrides/cleanup` | `operation`: `gatekeeper_config` \| `cleanup_overrides`; for config: `enabled`, `dry_run` |

---

## Security

### Localhost binding

Default host is **`127.0.0.1`**. Do not expose this service on `0.0.0.0` without additional network controls (mTLS, VPN, reverse proxy with auth).

Override only when required:

```bash
export PHASEONE_OPERATOR_MCP_HOST=127.0.0.1
```

### Write authentication

Write tools require **both**:

1. **`X-PhaseOne-Admin-Token`** request header matching server env `PHASEONE_OPERATOR_MCP_TOKEN`
2. **MFA-authenticated operator session + RBAC** — the MCP server documents this expectation; the gateway enforces operator roles on management APIs. Operators must complete MFA in the dashboard (or IdP) before performing confirm/deny/override actions. Human confirmation dialogs in the dashboard remain the source of truth for destructive gatekeeper actions.

Optional audit actor header:

```http
X-PhaseOne-Actor: ops@example.com
```

**Tokens are never logged** — audit records strip token-like fields.

### Rate limiting

Management (write) calls are rate-limited in-memory (default **30 per minute** per actor/global key). Excess calls return structured `rate_limited` errors.

### Audit trail

Every management call is:

1. Logged to **stdout** as structured JSON
2. Optionally POSTed to **`POST /v1/phaseone/audit`** on the gateway when `GATEWAY_URL` is set

Action names: `operator_mcp.<tool_name>`.

### Defensive errors

If the gateway is unreachable, tools return structured JSON errors (`gateway_unreachable`, `gateway_error`) — never stack traces or secrets.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` / `PHASEONE_OPERATOR_MCP_PORT` | `8090` | HTTP listen port |
| `PHASEONE_OPERATOR_MCP_HOST` | `127.0.0.1` | Bind address |
| `GATEWAY_URL` | `http://127.0.0.1:8080` | PhaseOne gateway base URL |
| `PHASEONE_OPERATOR_MCP_TOKEN` | — | Admin token for write tools (must match `X-PhaseOne-Admin-Token`) |

---

## MCP client configuration (example)

```json
{
  "mcpServers": {
    "phaseone-operator": {
      "url": "http://127.0.0.1:8090/",
      "headers": {
        "X-PhaseOne-Admin-Token": "${PHASEONE_OPERATOR_MCP_TOKEN}",
        "X-PhaseOne-Actor": "ops@example.com"
      }
    }
  }
}
```

---

## Related

- [RECOMMENDATIONS.md #4](RECOMMENDATIONS.md) — approved scope
- [gatekeeper.md](gatekeeper.md) — gatekeeper API reference
- [PHASE8_PLAN.md](PHASE8_PLAN.md) — implementation waves
