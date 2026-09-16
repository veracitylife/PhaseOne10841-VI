/**
 * Admin audit log — records dashboard admin actions with actor email + timestamp.
 * In-memory ring buffer always; Postgres when DATABASE_URL is reachable.
 */

import { randomUUID } from 'node:crypto';
import { Metrics } from './metrics.js';

export interface AuditEntry {
  id: string;
  actor_email: string;
  action: string;
  resource?: string | null;
  detail?: Record<string, unknown>;
  ip?: string | null;
  created_at: string;
}

const MAX_MEMORY = 2000;
const memoryLog: AuditEntry[] = [];

export type AuditAction =
  | 'login'
  | 'logout'
  | 'approve'
  | 'deny'
  | 'policy.save'
  | 'policy.dry_run'
  | 'export'
  | 'settings'
  | 'canary.rotate'
  | 'a2a.trust'
  | 'alert.test'
  | string;

export async function recordAudit(input: {
  actor_email: string;
  action: AuditAction;
  resource?: string;
  detail?: Record<string, unknown>;
  ip?: string;
}): Promise<AuditEntry> {
  const entry: AuditEntry = {
    id: randomUUID(),
    actor_email: input.actor_email.toLowerCase(),
    action: input.action,
    resource: input.resource ?? null,
    detail: input.detail ?? {},
    ip: input.ip ?? null,
    created_at: new Date().toISOString(),
  };
  memoryLog.unshift(entry);
  if (memoryLog.length > MAX_MEMORY) memoryLog.length = MAX_MEMORY;
  Metrics.audit(input.action);

  try {
    const { getPool } = await import('../../recorder/src/db.js');
    await getPool().query(
      `INSERT INTO admin_audit_log (id, actor_email, action, resource, detail, ip, created_at)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7::timestamptz)`,
      [
        entry.id,
        entry.actor_email,
        entry.action,
        entry.resource,
        JSON.stringify(entry.detail ?? {}),
        entry.ip,
        entry.created_at,
      ]
    );
  } catch {
    // DB optional for unit tests / degraded mode — memory still holds entry
  }
  return entry;
}

export async function listAudit(opts?: {
  limit?: number;
  actor?: string;
  action?: string;
}): Promise<AuditEntry[]> {
  const limit = Math.min(opts?.limit ?? 100, 500);
  try {
    const { getPool } = await import('../../recorder/src/db.js');
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (opts?.actor) {
      params.push(opts.actor.toLowerCase());
      clauses.push(`actor_email = $${params.length}`);
    }
    if (opts?.action) {
      params.push(opts.action);
      clauses.push(`action = $${params.length}`);
    }
    params.push(limit);
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const result = await getPool().query(
      `SELECT id, actor_email, action, resource, detail, ip, created_at
       FROM admin_audit_log ${where}
       ORDER BY created_at DESC LIMIT $${params.length}`,
      params
    );
    if (result.rows.length) {
      return result.rows.map((r) => ({
        id: r.id,
        actor_email: r.actor_email,
        action: r.action,
        resource: r.resource,
        detail: r.detail ?? {},
        ip: r.ip,
        created_at: r.created_at?.toISOString?.() ?? String(r.created_at),
      }));
    }
  } catch {
    // fall through to memory
  }

  let items = [...memoryLog];
  if (opts?.actor) items = items.filter((e) => e.actor_email === opts.actor!.toLowerCase());
  if (opts?.action) items = items.filter((e) => e.action === opts.action);
  return items.slice(0, limit);
}

export function __testResetAudit(): void {
  memoryLog.length = 0;
}

export function __testPeekAudit(): AuditEntry[] {
  return [...memoryLog];
}
