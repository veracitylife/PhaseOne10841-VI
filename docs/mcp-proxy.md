# Selective MCP wire proxy

**Phase 8 Wave B #3** · phaseone-core v0.8.0  
**Veracity Integrity LLC** · https://VeracityIntegrity.com

DEFENSIVE ONLY — proxies allowlisted MCP servers with the same policy, approval, and audit path as tools.

## Endpoint

`POST /v1/mcp/proxy`

```json
{
  "server": "lab-fake-mcp",
  "request": {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": { "name": "echo", "arguments": { "text": "hello" } }
  },
  "agent_id": "my-agent",
  "session_id": "optional-uuid",
  "dry_run": false
}
```

## Allowlist

Servers must appear in policy `mcp.allow_servers`. Inspect with:

```bash
curl -s http://localhost:8080/v1/mcp/proxy/allowlist
```

Upstream URLs (optional) via env JSON map — never trust client-supplied URLs alone:

```bash
PHASEONE_MCP_SERVER_URLS='{"filesystem":"http://127.0.0.1:3100/mcp"}'
PHASEONE_MCP_PROXY_TIMEOUT_MS=15000
```

When a server is allowlisted but has no upstream URL, the proxy returns a **stub** result (lab/demo) and still runs injection scanning + audit (`event_type: mcp_proxy`).

## Controls

- Tool calls map to existing `mcp_call` enforce
- Injection scanning on responses (`untrusted` source)
- Timeouts prevent hung upstreams
- Destructive MCP tools still follow approval policy

See also: [operator-mcp.md](operator-mcp.md) for the management MCP (separate process).
