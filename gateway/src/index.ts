import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { loadConfig, resolveUpstream } from './config.js';
import { forwardChatCompletions } from './upstream/proxy.js';
import {
  enforceToolCall,
  enforceEgressText,
  scanMessagesForThreats,
  scanToolResultContent,
  newSessionId,
} from './enforce.js';
import { loadPolicy } from '../../policy/src/engine.js';
import { redactSecrets } from '../../shared/src/secrets.js';
import {
  recordEvent,
  ensureSession,
  listEvents,
  listApprovals,
  resolveApproval,
  getDashboardCounts,
  listRecentIncidents,
  getApproval,
} from '../../recorder/src/recorder.js';
import { healthCheck } from '../../recorder/src/db.js';
import { listCanaryFiles } from '../../canaries/src/detector.js';
import { analyzePermissions, formatReportText } from './permissions.js';
import { processA2AMessage } from './a2a-firewall.js';
import { runInjectionScan, getInjectionPolicy } from './scanner.js';
import { listInjectionRules } from '../../shared/src/prompt-injection.js';
import { registerPhase3Routes } from './routes/phase3.js';
import { registerPhase4Routes } from './routes/phase4.js';
import { registerPhase5Routes } from './routes/phase5.js';
import { registerPhase7Routes } from './routes/phase7.js';
import { registerGatekeeperRoutes } from './routes/gatekeeper.js';
import { registerMcpProxyRoutes } from './routes/mcp-proxy.js';
import { registerOrgRoutes } from './routes/orgs.js';
import { registerGatewayMiddleware } from './middleware/index.js';
import { getRichSessionTimeline } from '../../recorder/src/recorder.js';

const cfg = loadConfig();
loadPolicy(cfg.policyPath);

const app = new Hono();
registerGatewayMiddleware(app);
app.use('*', cors());

app.get('/health', async (c) => {
  const dbOk = await healthCheck();
  return c.json({
    status: dbOk ? 'ok' : 'degraded',
    service: 'phaseone-gateway',
    product: 'PhaseOne10841',
    vendor: 'Veracity Integrity LLC',
    site: 'https://VeracityIntegrity.com',
    version: cfg.productVersion,
    upstream: resolveUpstream(cfg).label,
    db: dbOk,
  });
});

app.get('/v1/models', (c) => {
  const upstream = resolveUpstream(cfg).label;
  return c.json({
    object: 'list',
    data: [
      {
        id: upstream === 'mock' ? 'phaseone-mock' : 'upstream-default',
        object: 'model',
        owned_by: 'phaseone',
      },
    ],
  });
});

/**
 * OpenAI-compatible chat completions proxy with policy hooks.
 * Headers:
 *   X-PhaseOne-Agent-Id
 *   X-PhaseOne-Session-Id
 */
app.post('/v1/chat/completions', async (c) => {
  const agentId = c.req.header('x-phaseone-agent-id') ?? c.req.header('x-agent-id') ?? 'agent-default';
  const sessionId = c.req.header('x-phaseone-session-id') ?? c.req.header('x-session-id') ?? newSessionId();
  const body = (await c.req.json()) as Record<string, unknown>;
  const messages = (body.messages as Array<{ role?: string; content?: unknown }>) ?? [];
  const model = typeof body.model === 'string' ? body.model : 'unknown';
  const upstream = resolveUpstream(cfg);

  await ensureSession(sessionId, agentId, { model, upstream: upstream.label });
  await recordEvent({
    session_id: sessionId,
    agent_id: agentId,
    event_type: 'session.start',
    severity: 'info',
    metadata: { model, upstream: upstream.label },
  });

  // Prompt-injection / canary scan with source classification + optional block
  const threatScan = await scanMessagesForThreats(sessionId, agentId, messages);
  if (threatScan.blocked) {
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'prompt_injection.blocked',
      severity: 'high',
      decision: 'deny',
      decision_reason: threatScan.reason,
    });
    return c.json(
      {
        error: {
          message: `PhaseOne10841 blocked request: ${threatScan.reason}`,
          type: 'phaseone_prompt_injection',
          code: 'prompt_injection.block',
        },
      },
      403
    );
  }

  // Egress scan: block chat payloads that leak canaries/secrets to upstream when configured
  const egressBlob = messages.map((m) => (typeof m.content === 'string' ? m.content : '')).join('\n');
  const egressCheck = await enforceEgressText(sessionId, agentId, egressBlob, upstream.baseUrl);
  if (
    !egressCheck.allowed &&
    (egressCheck.decision.matchedCanaries?.length || egressCheck.decision.matchedSecrets?.length)
  ) {
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'chat.completion',
      severity: 'critical',
      decision: 'deny',
      decision_reason: egressCheck.decision.reason,
    });
    return c.json(egressCheck.blockedResponse, 403);
  }

  const pendingTools =
    (body.phaseone_tool_calls as Array<{ id?: string; name: string; arguments: unknown }>) ?? [];

  for (const tool of pendingTools) {
    const args =
      typeof tool.arguments === 'string'
        ? (() => {
            try {
              return JSON.parse(tool.arguments);
            } catch {
              return { raw: tool.arguments };
            }
          })()
        : tool.arguments;
    const result = await enforceToolCall({
      sessionId,
      agentId,
      toolName: tool.name,
      toolArgs: args,
    });
    if (!result.allowed) {
      return c.json(result.blockedResponse, result.pendingApproval ? 202 : 403);
    }
  }

  await recordEvent({
    session_id: sessionId,
    agent_id: agentId,
    event_type: 'chat.completion',
    severity: 'info',
    decision: 'allow',
    decision_reason: 'forwarding to upstream',
    metadata: {
      model,
      message_count: messages.length,
      prompt_preview: redactSecrets(
        messages
          .slice(-3)
          .map((m) => `${m.role}: ${typeof m.content === 'string' ? m.content : '[complex]'}`)
          .join(' | ')
          .slice(0, 500)
      ),
    },
  });

  try {
    const { status, data } = await forwardChatCompletions(cfg, body);
    const responseData =
      typeof data === 'object' && data
        ? {
            ...(data as object),
            phaseone: {
              session_id: sessionId,
              agent_id: agentId,
              upstream: upstream.label,
              gateway: 'phaseone-core/0.1.1',
            },
          }
        : data;

    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'tool.result',
      severity: 'info',
      decision: 'allow',
      result: { upstream_status: status },
      metadata: { kind: 'chat.completion.response' },
    });

    c.header('X-PhaseOne-Session-Id', sessionId);
    c.header('X-PhaseOne-Agent-Id', agentId);
    return c.json(responseData, status as 200);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'upstream error';
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'chat.completion',
      severity: 'high',
      decision: 'deny',
      decision_reason: message,
    });
    return c.json({ error: { message, type: 'upstream_error' } }, 502);
  }
});

/** Explicit tool enforcement endpoint (sidecar / agent SDK hook) */
app.post('/v1/phaseone/tools/enforce', async (c) => {
  const body = await c.req.json<{
    agent_id?: string;
    session_id?: string;
    tool_name: string;
    arguments?: unknown;
    wait_for_approval?: boolean;
  }>();
  const agentId = body.agent_id ?? 'agent-default';
  const sessionId = body.session_id ?? newSessionId();
  const result = await enforceToolCall({
    sessionId,
    agentId,
    toolName: body.tool_name,
    toolArgs: body.arguments ?? {},
    waitForApproval: body.wait_for_approval,
  });
  if (!result.allowed) {
    return c.json(
      {
        allowed: false,
        pending_approval: !!result.pendingApproval,
        approval_id: result.approvalId,
        decision: result.decision,
        error: result.blockedResponse?.error,
      },
      result.pendingApproval ? 202 : 403
    );
  }
  return c.json({ allowed: true, decision: result.decision, session_id: sessionId, agent_id: agentId });
});

/** Scan untrusted tool result / retrieved context / MCP payload */
app.post('/v1/phaseone/scan/untrusted', async (c) => {
  const body = await c.req.json<{
    agent_id?: string;
    session_id?: string;
    content: unknown;
    channel?: string;
  }>();
  const agentId = body.agent_id ?? 'agent-default';
  const sessionId = body.session_id ?? newSessionId();
  const result = await scanToolResultContent(
    sessionId,
    agentId,
    body.content,
    body.channel ?? 'untrusted_payload'
  );
  if (!result.allowed) {
    return c.json({ allowed: false, decision: result.decision, error: result.blockedResponse?.error }, 403);
  }
  return c.json({ allowed: true, decision: result.decision, session_id: sessionId });
});

/** Prompt-injection scanner API */
app.post('/v1/phaseone/scan/injection', async (c) => {
  const body = await c.req.json<{
    agent_id?: string;
    session_id?: string;
    text: string;
    source?: 'user' | 'system' | 'untrusted';
    channel?: string;
  }>();
  const sessionId = body.session_id ?? newSessionId();
  const agentId = body.agent_id ?? 'agent-default';
  const result = await runInjectionScan({
    sessionId,
    agentId,
    text: body.text ?? '',
    source: body.source ?? 'untrusted',
    channel: body.channel,
  });
  return c.json(
    {
      blocked: result.blocked,
      scan: result.scan,
      policy: getInjectionPolicy(),
      session_id: sessionId,
    },
    result.blocked ? 403 : 200
  );
});

app.get('/v1/phaseone/scan/injection/rules', (c) => {
  return c.json({ rules: listInjectionRules() });
});

/** Tool Permission Analyzer */
app.post('/v1/phaseone/permissions/analyze', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as {
    agent_id?: string;
    declared_tools?: string[];
    capabilities?: Record<string, boolean>;
    record?: boolean;
    session_id?: string;
  };
  const report = analyzePermissions({
    agent_id: body.agent_id ?? 'policy-default',
    declared_tools: body.declared_tools,
    capabilities: body.capabilities as never,
  });

  if (body.record) {
    const sessionId = body.session_id ?? newSessionId();
    await recordEvent({
      session_id: sessionId,
      agent_id: report.agent_id,
      event_type: 'permission.findings',
      severity: report.summary.max_severity === 'critical' ? 'critical' : report.summary.max_severity === 'high' ? 'high' : 'medium',
      decision: report.findings.length ? 'deny' : 'allow',
      decision_reason: `${report.findings.length} permission findings`,
      metadata: {
        finding_ids: report.findings.map((f) => f.id),
        summary: report.summary,
      },
    });
  }

  return c.json(report);
});

app.get('/v1/phaseone/permissions/analyze', (c) => {
  const agentId = c.req.query('agent_id') ?? 'policy-default';
  const format = c.req.query('format');
  const report = analyzePermissions({ agent_id: agentId });
  if (format === 'text') {
    return c.text(formatReportText(report));
  }
  return c.json(report);
});

/** Agent-to-Agent firewall */
app.post('/v1/phaseone/a2a/message', async (c) => {
  const body = await c.req.json<{
    from_agent_id: string;
    to_agent_id: string;
    session_id?: string;
    content: string;
    trust_level?: string;
    metadata?: Record<string, unknown>;
  }>();
  const decision = await processA2AMessage({
    from_agent_id: body.from_agent_id,
    to_agent_id: body.to_agent_id,
    session_id: body.session_id,
    content: body.content ?? '',
    trust_level: body.trust_level as never,
    metadata: body.metadata,
  });

  const status =
    decision.action === 'allow' ? 200 : decision.action === 'quarantine' ? 202 : 403;
  return c.json(
    {
      allowed: decision.action === 'allow',
      action: decision.action,
      trust_level: decision.trust_level,
      reason: decision.reason,
      session_id: decision.session_id,
      injection_hits: decision.injection_hits,
      quarantined: decision.quarantined ?? false,
    },
    status
  );
});

/** Record arbitrary observable hook (HTTP/FS/shell/MCP) from integrations */
app.post('/v1/phaseone/events', async (c) => {
  const body = await c.req.json<{
    session_id?: string;
    agent_id?: string;
    event_type: string;
    severity?: string;
    tool_name?: string;
    tool_args?: unknown;
    destination?: string;
    result?: unknown;
    metadata?: Record<string, unknown>;
  }>();
  const sessionId = body.session_id ?? newSessionId();
  const agentId = body.agent_id ?? 'agent-default';
  const event = await recordEvent({
    session_id: sessionId,
    agent_id: agentId,
    event_type: body.event_type as never,
    severity: (body.severity as never) ?? 'info',
    tool_name: body.tool_name,
    tool_args: body.tool_args,
    destination: body.destination,
    result: body.result,
    metadata: body.metadata,
  });
  return c.json(event, 201);
});

app.get('/v1/phaseone/events', async (c) => {
  const sessionId = c.req.query('session_id');
  const severity = c.req.query('severity');
  const eventType = c.req.query('event_type');
  const limit = Number(c.req.query('limit') ?? 100);
  const events = await listEvents({ sessionId, severity, eventType, limit });
  return c.json({ data: events });
});

app.get('/v1/phaseone/sessions/:id/timeline', async (c) => {
  const agentId = c.req.query('agent_id') || undefined;
  const rich = await getRichSessionTimeline(c.req.param('id'), { agentId });
  return c.json({
    session_id: rich.session_id,
    agent_filter: rich.agent_filter,
    events: rich.events,
    steps: rich.steps,
  });
});

app.get('/v1/phaseone/stats', async (c) => {
  const counts = await getDashboardCounts();
  return c.json(counts);
});

app.get('/v1/phaseone/incidents', async (c) => {
  const incidents = await listRecentIncidents(Number(c.req.query('limit') ?? 50));
  return c.json({ data: incidents });
});

app.get('/v1/phaseone/approvals', async (c) => {
  const status = c.req.query('status');
  const data = await listApprovals(status);
  return c.json({ data });
});

app.get('/v1/phaseone/approvals/:id', async (c) => {
  const approval = await getApproval(c.req.param('id'));
  if (!approval) return c.json({ error: 'not found' }, 404);
  return c.json(approval);
});

app.post('/v1/phaseone/approvals/:id/approve', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as {
    resolved_by?: string;
    note?: string;
    resolution_note?: string;
  };
  const approval = await resolveApproval(
    c.req.param('id'),
    'approved',
    body.resolved_by ?? 'dashboard',
    body.resolution_note ?? body.note
  );
  if (!approval) return c.json({ error: 'not found or already resolved' }, 404);
  return c.json(approval);
});

app.post('/v1/phaseone/approvals/:id/deny', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as {
    resolved_by?: string;
    note?: string;
    resolution_note?: string;
  };
  const approval = await resolveApproval(
    c.req.param('id'),
    'denied',
    body.resolved_by ?? 'dashboard',
    body.resolution_note ?? body.note
  );
  if (!approval) return c.json({ error: 'not found or already resolved' }, 404);
  return c.json(approval);
});

app.get('/v1/phaseone/canaries', (c) => {
  return c.json({
    files: listCanaryFiles(),
    note: 'Markers are harmless fakes. Detection fires when values appear in tool args/egress.',
  });
});

app.get('/v1/phaseone/policy', (c) => {
  const policy = loadPolicy(cfg.policyPath);
  return c.json(policy);
});

registerPhase3Routes(app, cfg);
registerPhase4Routes(app, cfg);
registerPhase5Routes(app, cfg);
registerPhase7Routes(app, cfg);
registerGatekeeperRoutes(app, cfg);
registerMcpProxyRoutes(app, cfg);
registerOrgRoutes(app, cfg);

const port = cfg.port;
console.log(`PhaseOne10841 Agent Security Gateway v0.1.1 — Veracity Integrity LLC`);
console.log(`Listening on :${port} (upstream=${resolveUpstream(cfg).label}) · https://VeracityIntegrity.com`);
serve({ fetch: app.fetch, port, hostname: '0.0.0.0' });

export default app;
