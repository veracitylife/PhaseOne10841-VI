/**
 * Playbook effectiveness / learn loop — record confirm/deny outcomes,
 * compute hit rates, and suggest human-gated YAML tweaks.
 * DEFENSIVE ONLY — never auto-apply suggestions.
 */

import { getPool } from '../../recorder/src/db.js';

async function query<T extends object = Record<string, unknown>>(
  sql: string,
  params: unknown[] = []
): Promise<{ rows: T[] }> {
  return getPool().query(sql, params) as unknown as Promise<{ rows: T[] }>;
}

export type PlaybookOutcomeType = 'confirmed' | 'denied' | 'auto_resolved' | 'expired';

export interface PlaybookOutcomeRecord {
  id?: string;
  playbook_id: string;
  action_type?: string | null;
  outcome: PlaybookOutcomeType;
  confirmation_id?: string | null;
  admin_notes?: string | null;
  actor_email?: string | null;
  trigger_event?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  created_at?: string;
}

export interface PlaybookEffectiveness {
  playbook_id: string;
  total: number;
  confirmed: number;
  denied: number;
  auto_resolved: number;
  expired: number;
  deny_rate: number;
  confirm_rate: number;
  window_days: number;
}

export interface LearnSuggestion {
  playbook_id: string;
  kind: 'raise_threshold' | 'review_conditions' | 'reduce_noise';
  message: string;
  evidence: {
    deny_rate: number;
    total: number;
    window_days: number;
  };
  requires_human_approval: true;
}

/** In-memory fallback when DB is unavailable (tests / degraded mode). */
const memoryOutcomes: PlaybookOutcomeRecord[] = [];

export async function recordPlaybookOutcome(
  record: PlaybookOutcomeRecord
): Promise<{ ok: boolean; id?: string; error?: string }> {
  const row = {
    playbook_id: record.playbook_id,
    action_type: record.action_type ?? null,
    outcome: record.outcome,
    confirmation_id: record.confirmation_id ?? null,
    admin_notes: record.admin_notes ?? null,
    actor_email: record.actor_email ?? null,
    trigger_event: record.trigger_event ?? {},
    metadata: record.metadata ?? {},
  };

  try {
    const res = await query<{ id: string }>(
      `INSERT INTO playbook_outcomes
        (playbook_id, action_type, outcome, confirmation_id, admin_notes, actor_email, trigger_event, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb)
       RETURNING id`,
      [
        row.playbook_id,
        row.action_type,
        row.outcome,
        row.confirmation_id,
        row.admin_notes,
        row.actor_email,
        JSON.stringify(row.trigger_event),
        JSON.stringify(row.metadata),
      ]
    );
    return { ok: true, id: res.rows[0]?.id };
  } catch {
    const id = `mem-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    memoryOutcomes.push({ ...row, id, created_at: new Date().toISOString() });
    return { ok: true, id };
  }
}

export async function listPlaybookOutcomes(opts?: {
  playbook_id?: string;
  days?: number;
  limit?: number;
}): Promise<PlaybookOutcomeRecord[]> {
  const days = opts?.days ?? 7;
  const limit = Math.min(opts?.limit ?? 500, 2000);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  try {
    const params: unknown[] = [since, limit];
    let sql = `SELECT id, playbook_id, action_type, outcome, confirmation_id, admin_notes,
                      actor_email, trigger_event, metadata, created_at
               FROM playbook_outcomes
               WHERE created_at >= $1`;
    if (opts?.playbook_id) {
      params.push(opts.playbook_id);
      sql += ` AND playbook_id = $${params.length}`;
    }
    sql += ` ORDER BY created_at DESC LIMIT $2`;
    const res = await query<PlaybookOutcomeRecord>(sql, params);
    return res.rows;
  } catch {
    return memoryOutcomes
      .filter((o) => {
        if (opts?.playbook_id && o.playbook_id !== opts.playbook_id) return false;
        const t = o.created_at ? Date.parse(o.created_at) : Date.now();
        return t >= Date.parse(since);
      })
      .slice(0, limit);
  }
}

export function computeEffectiveness(
  outcomes: PlaybookOutcomeRecord[],
  windowDays = 7
): PlaybookEffectiveness[] {
  const byId = new Map<string, PlaybookEffectiveness>();
  for (const o of outcomes) {
    let row = byId.get(o.playbook_id);
    if (!row) {
      row = {
        playbook_id: o.playbook_id,
        total: 0,
        confirmed: 0,
        denied: 0,
        auto_resolved: 0,
        expired: 0,
        deny_rate: 0,
        confirm_rate: 0,
        window_days: windowDays,
      };
      byId.set(o.playbook_id, row);
    }
    row.total++;
    if (o.outcome === 'confirmed') row.confirmed++;
    else if (o.outcome === 'denied') row.denied++;
    else if (o.outcome === 'auto_resolved') row.auto_resolved++;
    else if (o.outcome === 'expired') row.expired++;
  }
  for (const row of byId.values()) {
    row.deny_rate = row.total ? row.denied / row.total : 0;
    row.confirm_rate = row.total ? row.confirmed / row.total : 0;
  }
  return [...byId.values()].sort((a, b) => b.total - a.total);
}

/**
 * Human-gated suggestion heuristics.
 * If deny rate > 50% over the window with at least 5 samples, suggest raising thresholds.
 */
export function suggestTweaks(
  metrics: PlaybookEffectiveness[],
  opts?: { minSamples?: number; denyRateThreshold?: number }
): LearnSuggestion[] {
  const minSamples = opts?.minSamples ?? 5;
  const denyRateThreshold = opts?.denyRateThreshold ?? 0.5;
  const out: LearnSuggestion[] = [];
  for (const m of metrics) {
    if (m.total < minSamples) continue;
    if (m.deny_rate > denyRateThreshold) {
      out.push({
        playbook_id: m.playbook_id,
        kind: 'raise_threshold',
        message: `Deny rate ${(m.deny_rate * 100).toFixed(0)}% over ${m.window_days}d (${m.denied}/${m.total}). Consider raising match thresholds or tightening conditions — human review required before applying.`,
        evidence: {
          deny_rate: m.deny_rate,
          total: m.total,
          window_days: m.window_days,
        },
        requires_human_approval: true,
      });
    } else if (m.total >= minSamples * 2 && m.confirm_rate < 0.2 && m.deny_rate < 0.2) {
      out.push({
        playbook_id: m.playbook_id,
        kind: 'reduce_noise',
        message: `Low engagement on ${m.playbook_id} (${m.total} outcomes, mostly auto/expired). Review whether the playbook is still needed.`,
        evidence: {
          deny_rate: m.deny_rate,
          total: m.total,
          window_days: m.window_days,
        },
        requires_human_approval: true,
      });
    }
  }
  return out;
}

export async function getEffectivenessReport(opts?: {
  days?: number;
  playbook_id?: string;
}): Promise<{
  window_days: number;
  metrics: PlaybookEffectiveness[];
  suggestions: LearnSuggestion[];
  outcomes_sample: PlaybookOutcomeRecord[];
}> {
  const days = opts?.days ?? 7;
  const outcomes = await listPlaybookOutcomes({
    days,
    playbook_id: opts?.playbook_id,
    limit: 1000,
  });
  const metrics = computeEffectiveness(outcomes, days);
  const suggestions = suggestTweaks(metrics);
  return {
    window_days: days,
    metrics,
    suggestions,
    outcomes_sample: outcomes.slice(0, 50),
  };
}

export function __testResetLearnLoop(): void {
  memoryOutcomes.length = 0;
}
