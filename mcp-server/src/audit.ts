/**
 * Operator MCP audit helper — console logging + optional gateway audit POST.
 * DEFENSIVE ONLY — never log tokens or secrets.
 */

export interface AuditRecord {
  tool: string;
  category: 'read' | 'write';
  ok: boolean;
  actor?: string;
  detail?: Record<string, unknown>;
  error?: string;
  duration_ms?: number;
}

function sanitizeDetail(detail?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!detail) return undefined;
  const blocked = new Set([
    'token',
    'admin_token',
    'password',
    'secret',
    'api_key',
    'authorization',
  ]);
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(detail)) {
    if (blocked.has(key.toLowerCase())) continue;
    out[key] = value;
  }
  return out;
}

export function logAudit(record: AuditRecord): void {
  const line = {
    ts: new Date().toISOString(),
    component: 'operator-mcp',
    tool: record.tool,
    category: record.category,
    ok: record.ok,
    actor: record.actor ?? 'operator-mcp',
    duration_ms: record.duration_ms,
    error: record.error,
    detail: sanitizeDetail(record.detail),
  };
  console.log(JSON.stringify(line));
}

export async function postGatewayAudit(
  gatewayUrl: string,
  record: AuditRecord
): Promise<void> {
  if (!gatewayUrl) return;

  const url = `${gatewayUrl.replace(/\/$/, '')}/v1/phaseone/audit`;
  const body = {
    actor_email: record.actor ?? 'operator-mcp',
    action: `operator_mcp.${record.tool}`,
    resource: record.category,
    detail: {
      ok: record.ok,
      error: record.error,
      duration_ms: record.duration_ms,
      ...sanitizeDetail(record.detail),
    },
  };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      console.error(
        JSON.stringify({
          ts: new Date().toISOString(),
          component: 'operator-mcp',
          event: 'audit_post_failed',
          status: res.status,
        })
      );
    }
  } catch (err) {
    console.error(
      JSON.stringify({
        ts: new Date().toISOString(),
        component: 'operator-mcp',
        event: 'audit_post_error',
        message: err instanceof Error ? err.message : 'unknown',
      })
    );
  }
}

export async function auditManagementCall(
  gatewayUrl: string | undefined,
  record: AuditRecord
): Promise<void> {
  logAudit(record);
  if (gatewayUrl) {
    await postGatewayAudit(gatewayUrl, record);
  }
}
