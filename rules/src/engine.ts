/**
 * Lightweight Sigma-ish detection rules engine — DEFENSIVE ONLY.
 * Matches event fields (tool name, domain, injection score, canary, a2a trust).
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));

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
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RuleHit {
  rule_id: string;
  title: string;
  level: string;
  matched: Record<string, unknown>;
}

const hitCounts = new Map<string, number>();
let cachedRules: DetectionRule[] | null = null;
let cachedDir: string | null = null;

export function defaultRulesDir(): string {
  return process.env.PHASEONE_RULES_DIR ?? join(__dirname, '..');
}

export function resetRulesCache(): void {
  cachedRules = null;
  cachedDir = null;
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
    if (key === 'field_contains' && expected && typeof expected === 'object') {
      for (const [fk, substr] of Object.entries(expected as Record<string, string>)) {
        const v = String(fieldValue(ctx, fk) ?? '');
        if (!v.toLowerCase().includes(String(substr).toLowerCase())) return false;
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

export function evaluateRules(ctx: RuleMatchContext, dir?: string): RuleHit[] {
  const rules = loadRules(dir).filter((r) => r.enabled);
  const hits: RuleHit[] = [];

  for (const rule of rules) {
    const det = rule.detection;
    let matched = false;
    let matchedFields: Record<string, unknown> = {};

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

    if (matched) {
      const count = (hitCounts.get(rule.id) ?? 0) + 1;
      hitCounts.set(rule.id, count);
      hits.push({
        rule_id: rule.id,
        title: rule.title,
        level: rule.level,
        matched: matchedFields,
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

export function __testResetHitCounts(): void {
  hitCounts.clear();
  resetRulesCache();
}
