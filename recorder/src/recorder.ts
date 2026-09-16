import { randomUUID } from 'node:crypto';
import type { AgentEvent, ApprovalRequest, EventSeverity } from '../../shared/src/types.js';
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
      JSON.stringify(event.tool_args ?? null),
      event.destination ?? null,
      JSON.stringify(event.result ?? null),
      event.decision ?? null,
      event.decision_reason ?? null,
      JSON.stringify(event.metadata ?? {}),
      event.parent_event_id ?? null,
    ]
  );
  return mapEvent(result.rows[0]);
}

export async function createApproval(req: ApprovalRequest): Promise<ApprovalRequest> {
  const pool = getPool();
  await ensureSession(req.session_id, req.agent_id);
  const result = await pool.query(
    `INSERT INTO approvals (session_id, agent_id, action_type, payload, status, reason)
     VALUES ($1,$2,$3,$4::jsonb,'pending',$5)
     RETURNING *`,
    [
      req.session_id,
      req.agent_id,
      req.action_type,
      JSON.stringify(req.payload ?? {}),
      req.reason ?? null,
    ]
  );
  return mapApproval(result.rows[0]);
}

export async function resolveApproval(
  id: string,
  status: 'approved' | 'denied',
  resolvedBy = 'dashboard'
): Promise<ApprovalRequest | null> {
  const pool = getPool();
  const result = await pool.query(
    `UPDATE approvals
     SET status = $2, resolved_at = NOW(), resolved_by = $3
     WHERE id = $1 AND status = 'pending'
     RETURNING *`,
    [id, status, resolvedBy]
  );
  if (!result.rowCount) return null;
  const approval = mapApproval(result.rows[0]);
  await recordEvent({
    session_id: approval.session_id,
    agent_id: approval.agent_id,
    event_type: 'approval.resolved',
    severity: 'info',
    decision: status === 'approved' ? 'allow' : 'deny',
    decision_reason: `approval ${status} by ${resolvedBy}`,
    metadata: { approval_id: id, status },
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
  };
}

export async function listRecentIncidents(limit = 50): Promise<AgentEvent[]> {
  const pool = getPool();
  const result = await pool.query(
    `SELECT * FROM events
     WHERE severity IN ('high','critical') OR decision = 'deny' OR event_type IN ('canary.trigger','secret.detected','approval.requested','prompt_injection.blocked','a2a.blocked','a2a.quarantined','permission.findings','lab.detector_hit')
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
    created_at: row.created_at ? new Date(row.created_at as string).toISOString() : undefined,
    resolved_at: row.resolved_at ? new Date(row.resolved_at as string).toISOString() : null,
    resolved_by: (row.resolved_by as string) ?? null,
  };
}
