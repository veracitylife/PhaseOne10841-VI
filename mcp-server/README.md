# @phaseone/operator-mcp

Read-mostly **Operator MCP** for PhaseOne10841 trusted operator agents.  
**DEFENSIVE ONLY** — localhost binding, audited management calls, token-gated writes.

## Quick start

```bash
# From repo root (gateway should be running on :8080)
export PHASEONE_OPERATOR_MCP_TOKEN="your-admin-token"
npm run operator-mcp
```

Server listens on `127.0.0.1:8090` by default.

## JSON-RPC

`POST /` with JSON-RPC 2.0:

- `initialize`
- `tools/list`
- `tools/call` — `{ "name": "phaseone_health", "arguments": {} }`

Write tools require header `X-PhaseOne-Admin-Token` matching `PHASEONE_OPERATOR_MCP_TOKEN`.

## Tools

| Tool | Access |
|------|--------|
| `phaseone_health` | read |
| `phaseone_gatekeeper_status` | read |
| `phaseone_pending` | read |
| `phaseone_metrics` | read |
| `phaseone_recent_events` | read |
| `phaseone_confirm` | write (admin token) |
| `phaseone_deny` | write (admin token) |
| `phaseone_override` | write (admin token) |

Full documentation: [docs/operator-mcp.md](../docs/operator-mcp.md)
