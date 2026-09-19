/**
 * Selective MCP wire proxy — allowlisted servers only, policy + injection scan + audit.
 * DEFENSIVE ONLY.
 */

import type { Hono } from 'hono';
import { getPolicy } from '../../../policy/src/engine.js';
import { enforceToolCall, newSessionId } from '../enforce.js';
import { runInjectionScan } from '../scanner.js';
import { scanPromptInjection } from '../../../shared/src/prompt-injection.js';
import { recordEvent, ensureSession } from '../../../recorder/src/recorder.js';
import type { GatewayConfig } from '../config.js';

function scanMcpResult(text: string): { blocked: boolean; score: number; matches: unknown[] } {
  const scan = scanPromptInjection(text, {
    source: 'untrusted',
    blockMode: true,
    minBlockSeverity: 'medium',
  });
  return {
    blocked: scan.shouldBlock,
    score: scan.hits.length,
    matches: scan.hits,
  };
}

export interface McpJsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

const DEFAULT_TIMEOUT_MS = Number(process.env.PHASEONE_MCP_PROXY_TIMEOUT_MS ?? 15_000);

function mcpServerAllowed(server: string): boolean {
  const p = getPolicy();
  const allow = p.mcp?.allow_servers ?? [];
  if (p.mcp?.mode === 'allowlist') {
    return allow.includes(server) || allow.includes('*');
  }
  return !allow.length || allow.includes(server);
}

function extractToolName(params: Record<string, unknown> | undefined): string | undefined {
  if (!params) return undefined;
  if (typeof params.name === 'string') return params.name;
  const tool = params.tool as Record<string, unknown> | undefined;
  if (tool && typeof tool.name === 'string') return tool.name;
  return undefined;
}

/**
 * Forward JSON-RPC to an allowlisted MCP HTTP endpoint.
 * Server URLs come from PHASEONE_MCP_SERVER_URLS JSON map — never from client body alone.
 */
function resolveServerUrl(server: string): string | null {
  try {
    const map = JSON.parse(process.env.PHASEONE_MCP_SERVER_URLS ?? '{}') as Record<string, string>;
    return map[server] ?? null;
  } catch {
    return null;
  }
}

export function registerMcpProxyRoutes(app: Hono, _cfg: GatewayConfig): void {
  /**
   * POST /v1/mcp/proxy
   * Body: { server, request: JSON-RPC, agent_id?, session_id? }
   */
  app.post('/v1/mcp/proxy', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      server?: string;
      request?: McpJsonRpcRequest;
      agent_id?: string;
      session_id?: string;
      dry_run?: boolean;
    };

    const server = (body.server ?? '').trim();
    const rpc = body.request ?? {};
    const agentId = body.agent_id ?? c.req.header('x-phaseone-agent-id') ?? 'mcp-proxy-agent';
    const sessionId =
      body.session_id ?? c.req.header('x-phaseone-session-id') ?? newSessionId();

    if (!server) {
      return c.json({ error: 'server required', code: 'mcp.proxy.server_required' }, 400);
    }
    if (!mcpServerAllowed(server)) {
      await recordEvent({
        session_id: sessionId,
        agent_id: agentId,
        event_type: 'mcp_proxy',
        severity: 'high',
        decision: 'deny',
        decision_reason: `MCP server not allowlisted: ${server}`,
        metadata: { server, method: rpc.method },
      }).catch(() => undefined);
      return c.json(
        { error: `MCP server not allowlisted: ${server}`, code: 'mcp.proxy.not_allowlisted' },
        403
      );
    }

    await ensureSession(sessionId, agentId, { upstream: 'mcp-proxy', model: server });

    const method = rpc.method ?? 'unknown';
    const toolName = extractToolName(rpc.params);
    const isToolCall = method === 'tools/call' || method === 'tools/invoke';

    if (isToolCall) {
      const decision = await enforceToolCall({
        sessionId,
        agentId,
        toolName: 'mcp_call',
        toolArgs: {
          server,
          tool: toolName ?? 'unknown',
          arguments: rpc.params?.arguments ?? rpc.params ?? {},
        },
      });
      if (!decision.allowed) {
        await recordEvent({
          session_id: sessionId,
          agent_id: agentId,
          event_type: 'mcp_proxy',
          severity: 'high',
          tool_name: toolName,
          decision: 'deny',
          decision_reason: decision.decision.reason,
          metadata: { server, method, policy: decision.decision.ruleId },
        }).catch(() => undefined);
        return c.json(
          {
            jsonrpc: '2.0',
            id: rpc.id ?? null,
            error: {
              code: -32000,
              message: `PhaseOne policy denied MCP tool: ${decision.decision.reason}`,
              data: { ruleId: decision.decision.ruleId },
            },
          },
          403
        );
      }
    }

    if (body.dry_run) {
      return c.json({
        ok: true,
        dry_run: true,
        server,
        method,
        tool: toolName,
        message: 'Policy check passed; upstream not called',
      });
    }

    const upstreamUrl = resolveServerUrl(server);
    if (!upstreamUrl) {
      // Lab / demo mode: echo a structured stub without calling external servers
      const stubResult = {
        jsonrpc: '2.0',
        id: rpc.id ?? null,
        result: {
          content: [
            {
              type: 'text',
              text: `PhaseOne MCP proxy stub for allowlisted server "${server}" method "${method}". Configure PHASEONE_MCP_SERVER_URLS to forward.`,
            },
          ],
          isError: false,
          phaseone_proxy: true,
        },
      };

      const scan = scanMcpResult(JSON.stringify(stubResult.result));
      await runInjectionScan({
        sessionId,
        agentId,
        text: JSON.stringify(stubResult.result),
        source: 'untrusted',
        channel: 'mcp_payload',
      }).catch(() => undefined);

      await recordEvent({
        session_id: sessionId,
        agent_id: agentId,
        event_type: 'mcp_proxy',
        severity: scan.blocked ? 'high' : 'info',
        tool_name: toolName,
        decision: scan.blocked ? 'deny' : 'allow',
        decision_reason: scan.blocked ? 'injection scan blocked MCP stub result' : 'mcp proxy stub',
        metadata: { server, method, stub: true, injection: scan },
        result: stubResult.result,
      }).catch(() => undefined);

      if (scan.blocked) {
        return c.json(
          {
            jsonrpc: '2.0',
            id: rpc.id ?? null,
            error: { code: -32001, message: 'MCP result blocked by injection scanner' },
          },
          403
        );
      }
      return c.json(stubResult);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(upstreamUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          jsonrpc: rpc.jsonrpc ?? '2.0',
          id: rpc.id ?? null,
          method,
          params: rpc.params ?? {},
        }),
        signal: controller.signal,
      });
      const rawText = await res.text();
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(rawText) as Record<string, unknown>;
      } catch {
        parsed = { raw: rawText.slice(0, 2000) };
      }

      const scanTarget = JSON.stringify(parsed.result ?? parsed);
      const scan = scanMcpResult(scanTarget);
      await runInjectionScan({
        sessionId,
        agentId,
        text: scanTarget,
        source: 'untrusted',
        channel: 'mcp_payload',
      }).catch(() => undefined);

      await recordEvent({
        session_id: sessionId,
        agent_id: agentId,
        event_type: 'mcp_proxy',
        severity: scan.blocked || !res.ok ? 'high' : 'info',
        tool_name: toolName,
        destination: upstreamUrl,
        decision: scan.blocked ? 'deny' : res.ok ? 'allow' : 'deny',
        decision_reason: scan.blocked
          ? 'injection scan blocked MCP response'
          : res.ok
            ? 'mcp proxy forward'
            : `upstream HTTP ${res.status}`,
        metadata: { server, method, status: res.status, injection: scan },
        result: parsed,
      }).catch(() => undefined);

      if (scan.blocked) {
        return c.json(
          {
            jsonrpc: '2.0',
            id: rpc.id ?? null,
            error: { code: -32001, message: 'MCP result blocked by injection scanner' },
          },
          403
        );
      }
      return c.json(parsed, res.status as 200);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'mcp proxy failed';
      await recordEvent({
        session_id: sessionId,
        agent_id: agentId,
        event_type: 'mcp_proxy',
        severity: 'high',
        tool_name: toolName,
        decision: 'deny',
        decision_reason: msg,
        metadata: { server, method },
      }).catch(() => undefined);
      return c.json(
        {
          jsonrpc: '2.0',
          id: rpc.id ?? null,
          error: { code: -32002, message: msg },
        },
        502
      );
    } finally {
      clearTimeout(timer);
    }
  });

  app.get('/v1/mcp/proxy/allowlist', (c) => {
    const p = getPolicy();
    return c.json({
      mode: p.mcp?.mode ?? 'allowlist',
      allow_servers: p.mcp?.allow_servers ?? [],
      allow_tools: p.mcp?.allow_tools ?? [],
      deny_tools: p.mcp?.deny_tools ?? [],
      configured_upstreams: Object.keys(
        (() => {
          try {
            return JSON.parse(process.env.PHASEONE_MCP_SERVER_URLS ?? '{}') as Record<
              string,
              string
            >;
          } catch {
            return {};
          }
        })()
      ),
    });
  });
}
