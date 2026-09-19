/**
 * Operator MCP tool definitions and handlers.
 * Proxies read/write management calls to the PhaseOne gateway.
 * DEFENSIVE ONLY.
 */

import { auditManagementCall } from './audit.js';

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

export interface ToolResult {
  ok: boolean;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export interface ToolsConfig {
  gatewayUrl: string;
  adminToken?: string;
}

export interface ToolCallContext extends ToolsConfig {
  adminTokenHeader?: string;
  actor?: string;
}

const WRITE_TOOLS = new Set(['phaseone_confirm', 'phaseone_deny', 'phaseone_override']);

export const TOOL_DEFINITIONS: McpToolDefinition[] = [
  {
    name: 'phaseone_health',
    description: 'Gateway health and database readiness summary.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'phaseone_gatekeeper_status',
    description: 'Gatekeeper worker status, queue size, and pending confirmation count.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'phaseone_pending',
    description: 'List gatekeeper actions awaiting human confirmation.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'phaseone_metrics',
    description: 'PhaseOne counters and Prometheus text snapshot.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'phaseone_recent_events',
    description: 'Recent recorded security events from the event store.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Max events (default 50, max 200)' },
        event_type: { type: 'string', description: 'Filter by event_type' },
        session_id: { type: 'string', description: 'Filter by session_id' },
        severity: { type: 'string', description: 'Filter by severity' },
      },
    },
  },
  {
    name: 'phaseone_confirm',
    description:
      'Confirm a pending gatekeeper action. Requires MFA-authenticated operator session, RBAC, and X-PhaseOne-Admin-Token.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Pending confirmation id' },
        actor_email: { type: 'string', description: 'Operator email for audit trail' },
      },
      required: ['id'],
    },
  },
  {
    name: 'phaseone_deny',
    description:
      'Deny a pending gatekeeper action. Requires MFA-authenticated operator session, RBAC, and X-PhaseOne-Admin-Token.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Pending confirmation id' },
        actor_email: { type: 'string', description: 'Operator email for audit trail' },
      },
      required: ['id'],
    },
  },
  {
    name: 'phaseone_override',
    description:
      'Apply gatekeeper runtime overrides (config toggle or cleanup expired overrides). Requires MFA-authenticated operator session, RBAC, and X-PhaseOne-Admin-Token.',
    inputSchema: {
      type: 'object',
      properties: {
        operation: {
          type: 'string',
          enum: ['gatekeeper_config', 'cleanup_overrides'],
          description: 'Override operation to perform',
        },
        enabled: { type: 'boolean', description: 'Enable/disable gatekeeper (gatekeeper_config)' },
        dry_run: { type: 'boolean', description: 'Gatekeeper dry-run mode (gatekeeper_config)' },
        actor_email: { type: 'string', description: 'Operator email for audit trail' },
      },
      required: ['operation'],
    },
  },
];

export function isWriteTool(name: string): boolean {
  return WRITE_TOOLS.has(name);
}

export function verifyAdminToken(ctx: ToolCallContext): boolean {
  const expected = ctx.adminToken ?? process.env.PHASEONE_OPERATOR_MCP_TOKEN;
  if (!expected) return false;
  const provided = ctx.adminTokenHeader;
  if (!provided) return false;
  return provided === expected;
}

export class ManagementRateLimiter {
  private readonly maxPerWindow: number;
  private readonly windowMs: number;
  private readonly buckets = new Map<string, number[]>();

  constructor(maxPerWindow = 30, windowMs = 60_000) {
    this.maxPerWindow = maxPerWindow;
    this.windowMs = windowMs;
  }

  check(key = 'global'): { allowed: boolean; retry_after_ms?: number } {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const hits = (this.buckets.get(key) ?? []).filter((t) => t > cutoff);

    if (hits.length >= this.maxPerWindow) {
      const oldest = hits[0] ?? now;
      return { allowed: false, retry_after_ms: Math.max(0, oldest + this.windowMs - now) };
    }

    hits.push(now);
    this.buckets.set(key, hits);
    return { allowed: true };
  }

  reset(): void {
    this.buckets.clear();
  }
}

export const managementRateLimiter = new ManagementRateLimiter();

export interface GatewayError {
  ok: false;
  error: string;
  code: 'gateway_unreachable' | 'gateway_error' | 'unauthorized' | 'rate_limited' | 'invalid_args';
  status?: number;
  detail?: unknown;
}

function textResult(data: unknown, ok = true): ToolResult {
  return {
    ok,
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
    isError: !ok,
  };
}

function gatewayError(
  code: GatewayError['code'],
  error: string,
  extra?: Partial<GatewayError>
): ToolResult {
  const payload: GatewayError = { ok: false, error, code, ...extra };
  return textResult(payload, false);
}

async function gatewayFetch(
  gatewayUrl: string,
  path: string,
  init?: RequestInit
): Promise<{ ok: true; status: number; data: unknown } | GatewayError> {
  const base = gatewayUrl.replace(/\/$/, '');
  const url = `${base}${path}`;

  try {
    const res = await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(10_000),
    });

    const contentType = res.headers.get('content-type') ?? '';
    let data: unknown;
    if (contentType.includes('application/json')) {
      data = await res.json().catch(() => null);
    } else {
      data = await res.text().catch(() => '');
    }

    if (!res.ok) {
      return {
        ok: false,
        error: `Gateway returned ${res.status}`,
        code: 'gateway_error',
        status: res.status,
        detail: data,
      };
    }

    return { ok: true, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'Gateway unreachable',
      code: 'gateway_unreachable',
    };
  }
}

async function runReadTool(
  name: string,
  args: Record<string, unknown>,
  ctx: ToolCallContext
): Promise<ToolResult> {
  const start = Date.now();
  let path = '';
  let init: RequestInit | undefined;

  switch (name) {
    case 'phaseone_health':
      path = '/health';
      break;
    case 'phaseone_gatekeeper_status':
      path = '/v1/phaseone/gatekeeper/status';
      break;
    case 'phaseone_pending':
      path = '/v1/phaseone/gatekeeper/pending';
      break;
    case 'phaseone_metrics':
      path = '/v1/phaseone/metrics';
      break;
    case 'phaseone_recent_events': {
      const limit = Math.min(Number(args.limit ?? 50), 200);
      const params = new URLSearchParams({ limit: String(limit) });
      if (typeof args.event_type === 'string') params.set('event_type', args.event_type);
      if (typeof args.session_id === 'string') params.set('session_id', args.session_id);
      if (typeof args.severity === 'string') params.set('severity', args.severity);
      path = `/v1/phaseone/events?${params.toString()}`;
      break;
    }
    default:
      return gatewayError('invalid_args', `Unknown read tool: ${name}`);
  }

  const result = await gatewayFetch(ctx.gatewayUrl, path, init);
  const duration = Date.now() - start;

  await auditManagementCall(ctx.gatewayUrl, {
    tool: name,
    category: 'read',
    ok: result.ok,
    actor: ctx.actor,
    duration_ms: duration,
    error: result.ok ? undefined : result.error,
    detail: result.ok ? undefined : { code: result.code, status: result.status },
  });

  if (!result.ok) {
    return gatewayError(result.code, result.error, {
      status: result.status,
      detail: result.detail,
    });
  }

  return textResult(result.data);
}

async function runWriteTool(
  name: string,
  args: Record<string, unknown>,
  ctx: ToolCallContext
): Promise<ToolResult> {
  if (!verifyAdminToken(ctx)) {
    await auditManagementCall(ctx.gatewayUrl, {
      tool: name,
      category: 'write',
      ok: false,
      actor: ctx.actor,
      error: 'unauthorized',
      detail: { reason: 'missing_or_invalid_admin_token' },
    });
    return gatewayError(
      'unauthorized',
      'Write tools require a valid X-PhaseOne-Admin-Token header (or PHASEONE_OPERATOR_MCP_TOKEN env). ' +
        'Operator must have an active MFA-authenticated session and RBAC role permitting gatekeeper management.'
    );
  }

  const rateKey = ctx.actor ?? 'global';
  const rate = managementRateLimiter.check(rateKey);
  if (!rate.allowed) {
    await auditManagementCall(ctx.gatewayUrl, {
      tool: name,
      category: 'write',
      ok: false,
      actor: ctx.actor,
      error: 'rate_limited',
      detail: { retry_after_ms: rate.retry_after_ms },
    });
    return gatewayError('rate_limited', 'Management call rate limit exceeded', {
      detail: { retry_after_ms: rate.retry_after_ms },
    });
  }

  const start = Date.now();
  let path = '';
  let init: RequestInit = {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  };

  const actorEmail =
    typeof args.actor_email === 'string' ? args.actor_email : ctx.actor ?? 'operator-mcp';

  switch (name) {
    case 'phaseone_confirm': {
      const id = args.id;
      if (typeof id !== 'string' || !id) {
        return gatewayError('invalid_args', 'id is required');
      }
      path = `/v1/phaseone/gatekeeper/confirm/${encodeURIComponent(id)}`;
      init.body = JSON.stringify({ actor_email: actorEmail });
      break;
    }
    case 'phaseone_deny': {
      const id = args.id;
      if (typeof id !== 'string' || !id) {
        return gatewayError('invalid_args', 'id is required');
      }
      path = `/v1/phaseone/gatekeeper/deny/${encodeURIComponent(id)}`;
      init.body = JSON.stringify({ actor_email: actorEmail });
      break;
    }
    case 'phaseone_override': {
      const operation = args.operation;
      if (operation === 'cleanup_overrides') {
        path = '/v1/phaseone/gatekeeper/overrides/cleanup';
        init.body = JSON.stringify({ actor_email: actorEmail });
      } else if (operation === 'gatekeeper_config') {
        path = '/v1/phaseone/gatekeeper/config';
        const body: Record<string, unknown> = { actor_email: actorEmail };
        if (typeof args.enabled === 'boolean') body.enabled = args.enabled;
        if (typeof args.dry_run === 'boolean') body.dry_run = args.dry_run;
        init.body = JSON.stringify(body);
      } else {
        return gatewayError(
          'invalid_args',
          'operation must be gatekeeper_config or cleanup_overrides'
        );
      }
      break;
    }
    default:
      return gatewayError('invalid_args', `Unknown write tool: ${name}`);
  }

  const result = await gatewayFetch(ctx.gatewayUrl, path, init);
  const duration = Date.now() - start;

  await auditManagementCall(ctx.gatewayUrl, {
    tool: name,
    category: 'write',
    ok: result.ok,
    actor: actorEmail,
    duration_ms: duration,
    error: result.ok ? undefined : result.error,
    detail: {
      ...(result.ok ? {} : { code: result.code, status: result.status }),
      args: sanitizeArgs(args),
    },
  });

  if (!result.ok) {
    return gatewayError(result.code, result.error, {
      status: result.status,
      detail: result.detail,
    });
  }

  return textResult(result.data);
}

function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (/token|secret|password/i.test(k)) continue;
    out[k] = v;
  }
  return out;
}

export async function handleToolCall(
  name: string,
  args: Record<string, unknown>,
  ctx: ToolCallContext
): Promise<ToolResult> {
  const tool = TOOL_DEFINITIONS.find((t) => t.name === name);
  if (!tool) {
    return gatewayError('invalid_args', `Unknown tool: ${name}`);
  }

  if (isWriteTool(name)) {
    return runWriteTool(name, args, ctx);
  }
  return runReadTool(name, args, ctx);
}
