/**
 * Lightweight Sigma-ish detection rules engine — DEFENSIVE ONLY.
 * Matches event fields (tool name, domain, injection score, canary, a2a trust).
 * Supports aggregations and time-window based rules.
 * 
 * PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface AggregationConfig {
  type: 'count' | 'distinct_count' | 'sum' | 'avg';
  field?: string;
  group_by?: string[];
  threshold: number;
  comparison: 'gte' | 'gt' | 'lte' | 'lt' | 'eq';
}

export interface TimeWindowConfig {
  duration_ms: number;
  slide_ms?: number;
}

export interface DetectionRule {
  id: string;
  title: string;
  description?: string;
  status?: string;
  level: 'info' | 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  logsource?: { product?: string };
  detection: {
    selection?: Record<string, unknown>;
    selection_any?: Array<Record<string, unknown>>;
    condition?: string;
    aggregation?: AggregationConfig;
    timewindow?: TimeWindowConfig;
  };
  falsepositives?: string[];
  hit_count?: number;
}

export interface RuleMatchContext {
  event_type?: string;
  tool_name?: string;
  decision?: string;
  decision_reason?: string;
  destination?: string;
  domain?: string;
  injection_score?: number;
  canary?: boolean | string;
  a2a_trust?: string;
  severity?: string;
  agent_id?: string;
  session_id?: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RuleHit {
  rule_id: string;
  title: string;
  level: string;
  matched: Record<string, unknown>;
  aggregation_result?: {
    type: string;
    value: number;
    threshold: number;
    window_events?: number;
  };
}

interface WindowEvent {
  timestamp: number;
  ctx: RuleMatchContext;
}

interface AggregationState {
  events: WindowEvent[];
  lastCleanup: number;
}

const hitCounts = new Map<string, number>();
const aggregationStates = new Map<string, AggregationState>();
let cachedRules: DetectionRule[] | null = null;
let cachedDir: string | null = null;

export function defaultRulesDir(): string {
  return process.env.PHASEONE_RULES_DIR ?? join(__dirname, '..');
}

export function resetRulesCache(): void {
  cachedRules = null;
  cachedDir = null;
}

export function resetAggregationState(): void {
  aggregationStates.clear();
}

export function loadRules(dir?: string): DetectionRule[] {
  const rulesDir = dir ?? defaultRulesDir();
  if (cachedRules && cachedDir === rulesDir) return cachedRules;

  if (!existsSync(rulesDir)) {
    cachedRules = [];
    cachedDir = rulesDir;
    return cachedRules;
  }

  const files = readdirSync(rulesDir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  const rules: DetectionRule[] = [];
  for (const file of files) {
    try {
      const raw = readFileSync(join(rulesDir, file), 'utf8');
      const parsed = YAML.parse(raw) as DetectionRule;
      if (!parsed?.id || !parsed?.detection) continue;
      rules.push({
        ...parsed,
        enabled: parsed.enabled !== false,
        level: (parsed.level as DetectionRule['level']) ?? 'medium',
        hit_count: hitCounts.get(parsed.id) ?? 0,
      });
    } catch {
      // skip invalid rule files
    }
  }
  cachedRules = rules;
  cachedDir = rulesDir;
  return rules;
}

function fieldValue(ctx: RuleMatchContext, key: string): unknown {
  if (key in ctx && ctx[key] !== undefined) return ctx[key];
  if (ctx.metadata && key in ctx.metadata) return ctx.metadata[key];
  return undefined;
}

function matchSelection(sel: Record<string, unknown>, ctx: RuleMatchContext): boolean {
  for (const [key, expected] of Object.entries(sel)) {
    if (key === 'field_gte' && expected && typeof expected === 'object') {
      for (const [fk, threshold] of Object.entries(expected as Record<string, number>)) {
        const v = Number(fieldValue(ctx, fk) ?? NaN);
        if (!(v >= Number(threshold))) return false;
      }
      continue;
    }
    if (key === 'field_lte' && expected && typeof expected === 'object') {
      for (const [fk, threshold] of Object.entries(expected as Record<string, number>)) {
        const v = Number(fieldValue(ctx, fk) ?? NaN);
        if (!(v <= Number(threshold))) return false;
      }
      continue;
    }
    if (key === 'field_gt' && expected && typeof expected === 'object') {
      for (const [fk, threshold] of Object.entries(expected as Record<string, number>)) {
        const v = Number(fieldValue(ctx, fk) ?? NaN);
        if (!(v > Number(threshold))) return false;
      }
      continue;
    }
    if (key === 'field_lt' && expected && typeof expected === 'object') {
      for (const [fk, threshold] of Object.entries(expected as Record<string, number>)) {
        const v = Number(fieldValue(ctx, fk) ?? NaN);
        if (!(v < Number(threshold))) return false;
      }
      continue;
    }
    if (key === 'field_contains' && expected && typeof expected === 'object') {
      for (const [fk, substr] of Object.entries(expected as Record<string, string>)) {
        const v = String(fieldValue(ctx, fk) ?? '');
        if (!v.toLowerCase().includes(String(substr).toLowerCase())) return false;
      }
      continue;
    }
    if (key === 'field_regex' && expected && typeof expected === 'object') {
      for (const [fk, pattern] of Object.entries(expected as Record<string, string>)) {
        const v = String(fieldValue(ctx, fk) ?? '');
        try {
          const regex = new RegExp(pattern, 'i');
          if (!regex.test(v)) return false;
        } catch {
          return false;
        }
      }
      continue;
    }
    if (key === 'field_not' && expected && typeof expected === 'object') {
      for (const [fk, notVal] of Object.entries(expected as Record<string, unknown>)) {
        const v = fieldValue(ctx, fk);
        if (Array.isArray(notVal)) {
          if (notVal.map(String).includes(String(v))) return false;
        } else if (String(v) === String(notVal)) {
          return false;
        }
      }
      continue;
    }
    const actual = fieldValue(ctx, key);
    if (Array.isArray(expected)) {
      if (!expected.map(String).includes(String(actual))) return false;
    } else if (String(actual) !== String(expected)) {
      return false;
    }
  }
  return true;
}

function getGroupKey(ctx: RuleMatchContext, groupBy?: string[]): string {
  if (!groupBy || groupBy.length === 0) return '__all__';
  return groupBy.map((field) => String(fieldValue(ctx, field) ?? '')).join('|');
}

function cleanupOldEvents(state: AggregationState, windowMs: number, now: number): void {
  const cutoff = now - windowMs;
  state.events = state.events.filter((e) => e.timestamp >= cutoff);
  state.lastCleanup = now;
}

function evaluateAggregation(
  rule: DetectionRule,
  ctx: RuleMatchContext,
  now: number
): { matched: boolean; result?: RuleHit['aggregation_result'] } {
  const det = rule.detection;
  if (!det.aggregation || !det.timewindow) {
    return { matched: false };
  }

  const agg = det.aggregation;
  const windowMs = det.timewindow.duration_ms;
  const stateKey = `${rule.id}:${getGroupKey(ctx, agg.group_by)}`;

  let state = aggregationStates.get(stateKey);
  if (!state) {
    state = { events: [], lastCleanup: now };
    aggregationStates.set(stateKey, state);
  }

  if (now - state.lastCleanup > windowMs / 4) {
    cleanupOldEvents(state, windowMs, now);
  }

  state.events.push({ timestamp: now, ctx });

  const windowEvents = state.events.filter((e) => e.timestamp >= now - windowMs);
  let aggValue: number;

  switch (agg.type) {
    case 'count':
      aggValue = windowEvents.length;
      break;
    case 'distinct_count':
      if (!agg.field) {
        aggValue = windowEvents.length;
      } else {
        const distinct = new Set(windowEvents.map((e) => String(fieldValue(e.ctx, agg.field!) ?? '')));
        aggValue = distinct.size;
      }
      break;
    case 'sum':
      if (!agg.field) {
        aggValue = windowEvents.length;
      } else {
        aggValue = windowEvents.reduce((sum, e) => sum + Number(fieldValue(e.ctx, agg.field!) ?? 0), 0);
      }
      break;
    case 'avg':
      if (!agg.field || windowEvents.length === 0) {
        aggValue = 0;
      } else {
        const total = windowEvents.reduce((sum, e) => sum + Number(fieldValue(e.ctx, agg.field!) ?? 0), 0);
        aggValue = total / windowEvents.length;
      }
      break;
    default:
      aggValue = windowEvents.length;
  }

  let matched = false;
  switch (agg.comparison) {
    case 'gte':
      matched = aggValue >= agg.threshold;
      break;
    case 'gt':
      matched = aggValue > agg.threshold;
      break;
    case 'lte':
      matched = aggValue <= agg.threshold;
      break;
    case 'lt':
      matched = aggValue < agg.threshold;
      break;
    case 'eq':
      matched = aggValue === agg.threshold;
      break;
    default:
      matched = aggValue >= agg.threshold;
  }

  return {
    matched,
    result: {
      type: agg.type,
      value: aggValue,
      threshold: agg.threshold,
      window_events: windowEvents.length,
    },
  };
}

export function evaluateRules(ctx: RuleMatchContext, dir?: string): RuleHit[] {
  const rules = loadRules(dir).filter((r) => r.enabled);
  const hits: RuleHit[] = [];
  const now = ctx.timestamp ?? Date.now();

  for (const rule of rules) {
    const det = rule.detection;
    let matched = false;
    let matchedFields: Record<string, unknown> = {};
    let aggResult: RuleHit['aggregation_result'];

    if (det.selection_any && Array.isArray(det.selection_any)) {
      for (const sel of det.selection_any) {
        if (matchSelection(sel, ctx)) {
          matched = true;
          matchedFields = { ...sel };
          break;
        }
      }
    } else if (det.selection) {
      matched = matchSelection(det.selection, ctx);
      if (matched) matchedFields = { ...det.selection };
    }

    if (det.aggregation && det.timewindow) {
      const selectionMatched = matched || (!det.selection && !det.selection_any);
      if (selectionMatched) {
        const aggEval = evaluateAggregation(rule, ctx, now);
        matched = aggEval.matched;
        aggResult = aggEval.result;
        if (matched) {
          matchedFields = { ...matchedFields, aggregation: aggResult };
        }
      } else {
        matched = false;
      }
    }

    if (matched) {
      const count = (hitCounts.get(rule.id) ?? 0) + 1;
      hitCounts.set(rule.id, count);
      hits.push({
        rule_id: rule.id,
        title: rule.title,
        level: rule.level,
        matched: matchedFields,
        aggregation_result: aggResult,
      });
    }
  }
  return hits;
}

export function listRulesWithCounts(dir?: string): DetectionRule[] {
  return loadRules(dir).map((r) => ({
    ...r,
    hit_count: hitCounts.get(r.id) ?? r.hit_count ?? 0,
  }));
}

export function getRuleHitCounts(): Record<string, number> {
  return Object.fromEntries(hitCounts.entries());
}

export function getAggregationStats(): Record<string, { events: number; lastCleanup: number }> {
  const stats: Record<string, { events: number; lastCleanup: number }> = {};
  for (const [key, state] of aggregationStates.entries()) {
    stats[key] = {
      events: state.events.length,
      lastCleanup: state.lastCleanup,
    };
  }
  return stats;
}

export function __testResetHitCounts(): void {
  hitCounts.clear();
  resetRulesCache();
  resetAggregationState();
}
