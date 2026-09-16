/**
 * Event retention / cleanup helpers — DEFENSIVE operations only.
 * PhaseOne10841 — Veracity Integrity LLC
 */
import type pg from 'pg';

export interface RetentionConfig {
  /** Days to keep events (and orphaned sessions after event purge) */
  retentionDays: number;
  /** Also prune resolved approvals older than retention */
  pruneApprovals: boolean;
  /** Also prune admin_audit older than retention (if table exists) */
  pruneAudit: boolean;
  dryRun: boolean;
}

export interface RetentionResult {
  ok: boolean;
  retention_days: number;
  dry_run: boolean;
  events_deleted: number;
  sessions_deleted: number;
  approvals_deleted: number;
  audit_deleted: number;
  cutoff: string;
  error?: string;
}

export function loadRetentionConfig(overrides: Partial<RetentionConfig> = {}): RetentionConfig {
  return {
    retentionDays: Number(
      overrides.retentionDays ?? process.env.PHASEONE_RETENTION_DAYS ?? 30
    ),
    pruneApprovals:
      overrides.pruneApprovals ??
      (process.env.PHASEONE_RETENTION_PRUNE_APPROVALS ?? 'true').toLowerCase() !== 'false',
    pruneAudit:
      overrides.pruneAudit ??
      (process.env.PHASEONE_RETENTION_PRUNE_AUDIT ?? 'true').toLowerCase() !== 'false',
    dryRun:
      overrides.dryRun ??
      (process.env.PHASEONE_RETENTION_DRY_RUN ?? 'false').toLowerCase() === 'true',
  };
}

export async function runRetentionCleanup(
  query: (sql: string, params?: unknown[]) => Promise<{ rowCount: number | null; rows: unknown[] }>,
  cfg: RetentionConfig
): Promise<RetentionResult> {
  const days = Math.max(1, Math.floor(cfg.retentionDays));
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const result: RetentionResult = {
    ok: true,
    retention_days: days,
    dry_run: cfg.dryRun,
    events_deleted: 0,
    sessions_deleted: 0,
    approvals_deleted: 0,
    audit_deleted: 0,
    cutoff,
  };

  try {
    if (cfg.dryRun) {
      const ev = await query(
        `SELECT COUNT(*)::int AS c FROM events WHERE timestamp < $1::timestamptz`,
        [cutoff]
      );
      const sess = await query(
        `SELECT COUNT(*)::int AS c FROM sessions s
         WHERE s.started_at < $1::timestamptz
           AND NOT EXISTS (SELECT 1 FROM events e WHERE e.session_id = s.id)`,
        [cutoff]
      );
      result.events_deleted = (ev.rows[0] as { c: number })?.c ?? 0;
      result.sessions_deleted = (sess.rows[0] as { c: number })?.c ?? 0;
      if (cfg.pruneApprovals) {
        const ap = await query(
          `SELECT COUNT(*)::int AS c FROM approvals
           WHERE status <> 'pending' AND COALESCE(resolved_at, created_at) < $1::timestamptz`,
          [cutoff]
        );
        result.approvals_deleted = (ap.rows[0] as { c: number })?.c ?? 0;
      }
      if (cfg.pruneAudit) {
        try {
          const au = await query(
            `SELECT COUNT(*)::int AS c FROM admin_audit WHERE created_at < $1::timestamptz`,
            [cutoff]
          );
          result.audit_deleted = (au.rows[0] as { c: number })?.c ?? 0;
        } catch {
          result.audit_deleted = 0;
        }
      }
      return result;
    }

    const delEv = await query(`DELETE FROM events WHERE timestamp < $1::timestamptz`, [cutoff]);
    result.events_deleted = delEv.rowCount ?? 0;

    const delSess = await query(
      `DELETE FROM sessions s
       WHERE s.started_at < $1::timestamptz
         AND NOT EXISTS (SELECT 1 FROM events e WHERE e.session_id = s.id)`,
      [cutoff]
    );
    result.sessions_deleted = delSess.rowCount ?? 0;

    if (cfg.pruneApprovals) {
      const delAp = await query(
        `DELETE FROM approvals
         WHERE status <> 'pending' AND COALESCE(resolved_at, created_at) < $1::timestamptz`,
        [cutoff]
      );
      result.approvals_deleted = delAp.rowCount ?? 0;
    }

    if (cfg.pruneAudit) {
      try {
        const delAu = await query(`DELETE FROM admin_audit WHERE created_at < $1::timestamptz`, [
          cutoff,
        ]);
        result.audit_deleted = delAu.rowCount ?? 0;
      } catch {
        result.audit_deleted = 0;
      }
    }

    return result;
  } catch (err) {
    result.ok = false;
    result.error = err instanceof Error ? err.message : String(err);
    return result;
  }
}

/** Convenience wrapper for pg Pool */
export async function runRetentionWithPool(
  pool: { query: (sql: string, params?: unknown[]) => Promise<pg.QueryResult> },
  cfg: RetentionConfig
): Promise<RetentionResult> {
  return runRetentionCleanup(async (sql, params) => {
    const r = await pool.query(sql, params);
    return { rowCount: r.rowCount, rows: r.rows };
  }, cfg);
}
