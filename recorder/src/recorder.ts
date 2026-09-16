import { randomUUID } from 'node:crypto';
import type {
  AgentEvent,
  ApprovalRequest,
  ApprovalRisk,
  EventSeverity,
  TimelineStep,
} from '../../shared/src/types.js';
import { redactSecretsDeep } from '../../shared/src/secrets.js';
import { getPool } from './db.js';

export async function ensureSession(
  sessionId: string,
  agentId: string,
  opts?: { model?: string; upstream?: string; metadata?: Record<string, unknown> }
): Promise<void> {
  const pool = getPool();
  await pool.query(
    `INSERT INTO sessions (id, agent_id, model, upstream, metadata)
     VALUES ($1, $2, $3, $4, $5::jsonb)
     ON CONFLICT (id) DO NOTHING`,
    [
      sessionId,
      agentId,
      opts?.model ?? null,
      opts?.upstream ?? null,
      JSON.stringify(opts?.metadata ?? {}),
    ]
  );
  await pool.query(
    `INSERT INTO agents (id, last_seen_at)
     VALUES ($1, NOW())
     ON CONFLICT (id) DO UPDATE SET last_seen_at = NOW()`,
    [agentId]
  );
}

export async function recordEvent(event: AgentEvent): Promise<AgentEvent> {
  const pool = getPool();
  const id = event.id ?? randomUUID();
  await ensureSession(event.session_id, event.agent_id);

  const safeArgs = event.tool_args != null ? redactSecretsDeep(event.tool_args) : null;
  const safeResult = event.result != null ? redactSecretsDeep(event.result) : null;
  const safeMeta = redactSecretsDeep(event.metadata ?? {});

  const result = await pool.query(
    `INSERT INTO events (
      id, session_id, agent_id, event_type, severity, timestamp,
      tool_name, tool_args, destination, result, decision, decision_reason,
      metadata, parent_event_id
    ) VALUES (
      $1,$2,$3,$4,$5,COALESCE($6::timestamptz, NOW()),
      $7,$8::jsonb,$9,$10::jsonb,$11,$12,$13::jsonb,$14
    ) RETURNING *`,
    [
      id,
      event.session_id,
      event.agent_id,
      event.event_type,
      event.severity,
      event.timestamp ?? null,
      event.tool_name ?? null,
      JSON.stringify(safeArgs),
      event.destination ?? null,
      JSON.stringify(safeResult),
      event.decision ?? null,
      event.decision_reason ?? null,
      JSON.stringify(safeMeta),
      event.parent_event_id ?? null,
    ]
  );
  return mapEvent(result.rows[0]);
}

export async function createApproval(req: ApprovalRequest): Promise<ApprovalRequest> {
  const pool = getPool();
  await ensureSession(req.session_id, req.agent_id);
  const safePayload = redactSecretsDeep(req.payload ?? {});
  const result = await pool.query(
    `INSERT INTO approvals (
      session_id, agent_id, action_type, payload, status, reason,
      risk, note, expires_at
    )
     VALUES ($1,$2,$3,$4::jsonb,'pending',$5,$6,$7,$8::timestamptz)
     RETURNING *`,
    [
      req.session_id,
      req.agent_id,
      req.action_type,
      JSON.stringify(safePayload),
      req.reason ?? null,
      req.risk ?? null,
      req.note ?? null,
      req.expires_at ?? null,
    ]
  );
  return mapApproval(result.rows[0]);
}

export async function resolveApproval(
  id: string,
  status: 'approved' | 'denied' | 'expired',
  resolvedBy = 'dashboard',
  resolutionNote?: string | null
): Promise<ApprovalRequest | null> {
  const pool = getPool();
  const result = await pool.query(
    `UPDATE approvals
     SET status = $2, resolved_at = NOW(), resolved_by = $3,
         resolution_note = COALESCE($4, resolution_note)
     WHERE id = $1 AND status = 'pending'
     RETURNING *`,
    [id, status, resolvedBy, resolutionNote ?? null]
  );
  if (!result.rowCount) return null;
  const approval = mapApproval(result.rows[0]);
  await recordEvent({
    session_id: approval.session_id,
    agent_id: approval.agent_id,
    event_type: status === 'expired' ? 'approval.expired' : 'approval.resolved',
    severity: status === 'expired' ? 'medium' : 'info',
    decision: status === 'approved' ? 'allow' : 'deny',
    decision_reason: `approval ${status} by ${resolvedBy}${resolutionNote ? `: ${resolutionNote}` : ''}`,
    metadata: { approval_id: id, status, resolution_note: resolutionNote ?? null },
  });
  return approval;
}

export async function listApprovals(status?: string): Promise<ApprovalRequest[]> {
  const pool = getPool();
  const result = status
    ? await pool.query(`SELECT * FROM approvals WHERE status = $1 ORDER BY created_at DESC LIMIT 100`, [
        status,
      ])
    : await pool.query(`SELECT * FROM approvals ORDER BY created_at DESC LIMIT 100`);
  return result.rows.map(mapApproval);
}

export async function getApproval(id: string): Promise<ApprovalRequest | null> {
  const pool = getPool();
  const result = await pool.query(`SELECT * FROM approvals WHERE id = $1`, [id]);
  if (!result.rowCount) return null;
  return mapApproval(result.rows[0]);
}

export async function listEvents(opts: {
  sessionId?: string;
  agentId?: string;
  severity?: EventSeverity | string;
  eventType?: string;
  limit?: number;
}): Promise<AgentEvent[]> {
  const pool = getPool();
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (opts.sessionId) {
    params.push(opts.sessionId);
    clauses.push(`session_id = $${params.length}`);
  }
  if (opts.agentId) {
    params.push(opts.agentId);
    clauses.push(`agent_id = $${params.length}`);
  }
  if (opts.severity) {
    params.push(opts.severity);
    clauses.push(`severity = $${params.length}`);
  }
  if (opts.eventType) {
    params.push(opts.eventType);
    clauses.push(`event_type = $${params.length}`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  params.push(opts.limit ?? 100);
  const result = await pool.query(
    `SELECT * FROM events ${where} ORDER BY timestamp DESC LIMIT $${params.length}`,
    params
  );
  return result.rows.map(mapEvent);
}

export async function getSessionTimeline(sessionId: string): Promise<AgentEvent[]> {
  const pool = getPool();
  const result = await pool.query(
    `SELECT * FROM events WHERE session_id = $1 ORDER BY timestamp ASC`,
    [sessionId]
  );
  return result.rows.map(mapEvent);
}

/** Phase 3: ordered chain agent→tool→args(redacted)→dest→result→next */
export function buildTimelineSteps(events: AgentEvent[]): TimelineStep[] {
  const ordered = [...events].sort((a, b) => {
    const ta = a.timestamp ? Date.parse(a.timestamp) : 0;
    const tb = b.timestamp ? Date.parse(b.timestamp) : 0;
    return ta - tb;
  });
  return ordered.map((e, index) => {
    const next = ordered[index + 1];
    const argsRedacted = e.tool_args != null ? redactSecretsDeep(e.tool_args) : undefined;
    const resultRedacted = e.result != null ? redactSecretsDeep(e.result) : undefined;
    return {
      index,
      event_id: e.id ?? `idx-${index}`,
      timestamp: e.timestamp,
      agent_id: e.agent_id,
      event_type: e.event_type,
      severity: e.severity,
      tool_name: e.tool_name ?? null,
      args_redacted: argsRedacted,
      destination: e.destination ?? null,
      result: resultRedacted,
      decision: e.decision ?? null,
      decision_reason: e.decision_reason ?? null,
      next_event_id: next?.id ?? null,
      parent_event_id: e.parent_event_id ?? null,
      chain: {
        agent: e.agent_id,
        tool: e.tool_name ?? null,
        args: argsRedacted,
        dest: e.destination ?? null,
        result: resultRedacted,
        next: next?.id ?? null,
      },
    };
  });
}

export async function getRichSessionTimeline(
  sessionId: string,
  opts?: { agentId?: string }
): Promise<{ session_id: string; agent_filter?: string; steps: TimelineStep[]; events: AgentEvent[] }> {
  let events = await getSessionTimeline(sessionId);
  if (opts?.agentId) {
    events = events.filter((e) => e.agent_id === opts.agentId);
  }
  return {
    session_id: sessionId,
    agent_filter: opts?.agentId,
    steps: buildTimelineSteps(events),
    events,
  };
}

export async function listAgents(): Promise<
  Array<{ id: string; display_name?: string | null; last_seen_at?: string; spawn_depth?: number }>
> {
  const pool = getPool();
  const result = await pool.query(`SELECT * FROM agents ORDER BY last_seen_at DESC LIMIT 200`);
  return result.rows.map((row) => ({
    id: String(row.id),
    display_name: (row.display_name as string) ?? null,
    last_seen_at: row.last_seen_at ? new Date(row.last_seen_at as string).toISOString() : undefined,
    spawn_depth: Number(row.spawn_depth ?? 0),
  }));
}

export async function listSessions(limit = 50): Promise<
  Array<{ id: string; agent_id: string; model?: string | null; started_at?: string; upstream?: string | null }>
> {
  const pool = getPool();
  const result = await pool.query(
    `SELECT id, agent_id, model, upstream, started_at FROM sessions ORDER BY started_at DESC LIMIT $1`,
    [limit]
  );
  return result.rows.map((row) => ({
    id: String(row.id),
    agent_id: String(row.agent_id),
    model: (row.model as string) ?? null,
    upstream: (row.upstream as string) ?? null,
    started_at: row.started_at ? new Date(row.started_at as string).toISOString() : undefined,
  }));
}

export async function getDashboardCounts(): Promise<Record<string, number>> {
  const pool = getPool();
  const q = async (sql: string) => {
    const r = await pool.query(sql);
    return Number(r.rows[0]?.c ?? 0);
  };
  const [
    agents,
    toolCalls,
    shell,
    domains,
    blocked,
    canary,
    a2a,
    a2aBlocked,
    promptInj,
    permissionFindings,
    labHits,
    pendingApprovals,
    sessions,
    secretHits,
    mcpCalls,
  ] = await Promise.all([
    q(`SELECT COUNT(*)::int AS c FROM agents WHERE last_seen_at > NOW() - INTERVAL '1 hour'`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type = 'tool.call'`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type = 'shell.exec'`),
    q(
      `SELECT COUNT(DISTINCT destination)::int AS c FROM events WHERE destination IS NOT NULL AND event_type IN ('http.request','tool.call')`
    ),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE decision = 'deny'`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type = 'canary.trigger'`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type = 'a2a.message'`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type IN ('a2a.blocked','a2a.quarantined')`),
    q(
      `SELECT COUNT(*)::int AS c FROM events WHERE event_type IN ('prompt_injection.detected','prompt_injection.blocked')`
    ),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type = 'permission.findings'`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type = 'lab.detector_hit'`),
    q(`SELECT COUNT(*)::int AS c FROM approvals WHERE status = 'pending'`),
    q(`SELECT COUNT(*)::int AS c FROM sessions`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type IN ('secret.detected','secret.blocked')`),
    q(`SELECT COUNT(*)::int AS c FROM events WHERE event_type IN ('mcp.call','mcp.denied')`),
  ]);
  return {
    agents,
    tool_calls: toolCalls,
    shell_commands: shell,
    external_domains: domains,
    blocked_actions: blocked,
    canary_triggers: canary,
    a2a_messages: a2a,
    a2a_blocks: a2aBlocked,
    prompt_injection_hits: promptInj,
    permission_findings: permissionFindings,
    lab_detector_hits: labHits,
    pending_approvals: pendingApprovals,
    sessions,
    secret_hits: secretHits,
    mcp_calls: mcpCalls,
  };
}

export async function listRecentIncidents(limit = 50): Promise<AgentEvent[]> {
  const pool = getPool();
  const result = await pool.query(
    `SELECT * FROM events
     WHERE severity IN ('high','critical') OR decision = 'deny' OR event_type IN ('canary.trigger','secret.detected','secret.blocked','approval.requested','prompt_injection.blocked','a2a.blocked','a2a.quarantined','permission.findings','lab.detector_hit','mcp.denied','approval.expired')
     ORDER BY timestamp DESC LIMIT $1`,
    [limit]
  );
  return result.rows.map(mapEvent);
}

function mapEvent(row: Record<string, unknown>): AgentEvent {
  return {
    id: String(row.id),
    session_id: String(row.session_id),
    agent_id: String(row.agent_id),
    event_type: row.event_type as AgentEvent['event_type'],
    severity: row.severity as AgentEvent['severity'],
    timestamp: row.timestamp ? new Date(row.timestamp as string).toISOString() : undefined,
    tool_name: (row.tool_name as string) ?? null,
    tool_args: row.tool_args,
    destination: (row.destination as string) ?? null,
    result: row.result,
    decision: (row.decision as AgentEvent['decision']) ?? null,
    decision_reason: (row.decision_reason as string) ?? null,
    metadata: (row.metadata as Record<string, unknown>) ?? {},
    parent_event_id: row.parent_event_id ? String(row.parent_event_id) : null,
  };
}

function mapApproval(row: Record<string, unknown>): ApprovalRequest {
  return {
    id: String(row.id),
    session_id: String(row.session_id),
    agent_id: String(row.agent_id),
    action_type: String(row.action_type),
    payload: row.payload,
    status: row.status as ApprovalRequest['status'],
    reason: (row.reason as string) ?? null,
    risk: (row.risk as ApprovalRisk) ?? null,
    note: (row.note as string) ?? null,
    resolution_note: (row.resolution_note as string) ?? null,
    expires_at: row.expires_at ? new Date(row.expires_at as string).toISOString() : null,
    created_at: row.created_at ? new Date(row.created_at as string).toISOString() : undefined,
    resolved_at: row.resolved_at ? new Date(row.resolved_at as string).toISOString() : null,
    resolved_by: (row.resolved_by as string) ?? null,
  };
}
