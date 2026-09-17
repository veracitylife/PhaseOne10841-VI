/**
 * PhaseOne10841 Gatekeeper Playbook Loader
 * Load and validate YAML playbooks for defense orchestration.
 * 
 * DEFENSIVE ONLY — no exploit tooling.
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import type {
  Playbook,
  PlaybookTier,
  PlaybookMatch,
  PlaybookAction,
  GatekeeperActionType,
} from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const ALLOWED_ACTION_TYPES: Set<GatekeeperActionType> = new Set([
  'emit_alert',
  'write_audit',
  'dashboard_notify',
  'tighten_rate_limit',
  'force_approval',
  'lower_a2a_trust',
  'deny_tool',
  'deny_domain',
  'rotate_canary',
  'reload_rules',
]);

const TIER_RANKS: Record<PlaybookTier, number> = {
  observe: 1,
  contain: 2,
  harden: 3,
};

const TIER_ALLOWED_ACTIONS: Record<PlaybookTier, Set<GatekeeperActionType>> = {
  observe: new Set(['emit_alert', 'write_audit', 'dashboard_notify']),
  contain: new Set([
    'emit_alert',
    'write_audit',
    'dashboard_notify',
    'tighten_rate_limit',
    'force_approval',
    'lower_a2a_trust',
    'deny_tool',
    'deny_domain',
  ]),
  harden: new Set([
    'emit_alert',
    'write_audit',
    'dashboard_notify',
    'tighten_rate_limit',
    'force_approval',
    'lower_a2a_trust',
    'deny_tool',
    'deny_domain',
    'rotate_canary',
    'reload_rules',
  ]),
};

export interface PlaybookValidation {
  ok: boolean;
  playbook?: Playbook;
  errors: string[];
  warnings: string[];
}

let cachedPlaybooks: Playbook[] | null = null;
let cachedDir: string | null = null;

export function defaultPlaybooksDir(): string {
  return process.env.PHASEONE_PLAYBOOKS_DIR ?? join(__dirname, '../../playbooks');
}

export function resetPlaybooksCache(): void {
  cachedPlaybooks = null;
  cachedDir = null;
}

function validateAction(action: PlaybookAction, tier: PlaybookTier): string[] {
  const errors: string[] = [];
  
  if (!action.type) {
    errors.push('action.type is required');
    return errors;
  }
  
  if (!ALLOWED_ACTION_TYPES.has(action.type)) {
    errors.push(`unknown action type: ${action.type}`);
    return errors;
  }
  
  const allowed = TIER_ALLOWED_ACTIONS[tier];
  if (!allowed.has(action.type)) {
    errors.push(`action ${action.type} not allowed in tier ${tier}`);
  }
  
  return errors;
}

function validateMatch(match: PlaybookMatch): string[] {
  const errors: string[] = [];
  
  if (!match) {
    errors.push('match block is required');
    return errors;
  }
  
  const hasCondition = match.rule_id || match.event_type || match.severity || match.decision;
  if (!hasCondition) {
    errors.push('match must specify at least one condition (rule_id, event_type, severity, or decision)');
  }
  
  if (match.count !== undefined && (typeof match.count !== 'number' || match.count < 1)) {
    errors.push('match.count must be a positive number');
  }
  
  if (match.window_ms !== undefined && (typeof match.window_ms !== 'number' || match.window_ms < 1000)) {
    errors.push('match.window_ms must be at least 1000ms');
  }
  
  return errors;
}

export function validatePlaybook(raw: unknown, filename?: string): PlaybookValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const prefix = filename ? `[${filename}] ` : '';
  
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, errors: [`${prefix}playbook must be a YAML mapping`], warnings };
  }
  
  const data = raw as Record<string, unknown>;
  
  if (!data.id || typeof data.id !== 'string') {
    errors.push(`${prefix}id is required and must be a string`);
  }
  
  if (!data.name || typeof data.name !== 'string') {
    errors.push(`${prefix}name is required and must be a string`);
  }
  
  const tier = data.tier as PlaybookTier;
  if (!tier || !['observe', 'contain', 'harden'].includes(tier)) {
    errors.push(`${prefix}tier must be one of: observe, contain, harden`);
  }
  
  const matchErrors = validateMatch(data.match as PlaybookMatch);
  errors.push(...matchErrors.map(e => `${prefix}${e}`));
  
  if (!data.actions || !Array.isArray(data.actions) || data.actions.length === 0) {
    errors.push(`${prefix}actions array is required and must not be empty`);
  } else {
    for (let i = 0; i < data.actions.length; i++) {
      const actionErrors = validateAction(data.actions[i] as PlaybookAction, tier);
      errors.push(...actionErrors.map(e => `${prefix}actions[${i}]: ${e}`));
    }
  }
  
  if (tier === 'harden') {
    const hasHardenAction = (data.actions as PlaybookAction[])?.some(
      a => a.type === 'rotate_canary' || a.type === 'reload_rules'
    );
    if (hasHardenAction) {
      warnings.push(`${prefix}harden tier actions (rotate_canary, reload_rules) require human confirmation by default`);
    }
  }
  
  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }
  
  const playbook: Playbook = {
    id: data.id as string,
    name: data.name as string,
    description: (data.description as string) ?? undefined,
    enabled: data.enabled !== false,
    tier: tier,
    match: data.match as PlaybookMatch,
    actions: (data.actions as PlaybookAction[]).map(a => ({
      type: a.type,
      params: a.params ?? undefined,
      requires_confirmation: a.requires_confirmation ?? (tier === 'harden' && (a.type === 'rotate_canary' || a.type === 'reload_rules')),
    })),
    cooldown_ms: (data.cooldown_ms as number) ?? 60000,
    max_executions_per_window: (data.max_executions_per_window as number) ?? 10,
  };
  
  return { ok: true, playbook, errors, warnings };
}

export function loadPlaybooks(dir?: string): Playbook[] {
  const playbooksDir = dir ?? defaultPlaybooksDir();
  
  if (cachedPlaybooks && cachedDir === playbooksDir) {
    return cachedPlaybooks;
  }
  
  if (!existsSync(playbooksDir)) {
    cachedPlaybooks = [];
    cachedDir = playbooksDir;
    return cachedPlaybooks;
  }
  
  const files = readdirSync(playbooksDir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
  const playbooks: Playbook[] = [];
  
  for (const file of files) {
    try {
      const raw = readFileSync(join(playbooksDir, file), 'utf8');
      const parsed = YAML.parse(raw);
      const validation = validatePlaybook(parsed, file);
      
      if (validation.ok && validation.playbook) {
        playbooks.push(validation.playbook);
      }
    } catch {
      // Skip invalid playbook files
    }
  }
  
  cachedPlaybooks = playbooks.sort((a, b) => {
    const tierDiff = TIER_RANKS[a.tier] - TIER_RANKS[b.tier];
    if (tierDiff !== 0) return tierDiff;
    return a.id.localeCompare(b.id);
  });
  
  cachedDir = playbooksDir;
  return cachedPlaybooks;
}

export function listPlaybooksDetailed(dir?: string): Array<Playbook & { file?: string }> {
  const playbooksDir = dir ?? defaultPlaybooksDir();
  
  if (!existsSync(playbooksDir)) {
    return [];
  }
  
  const files = readdirSync(playbooksDir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
  const result: Array<Playbook & { file?: string }> = [];
  
  for (const file of files) {
    try {
      const raw = readFileSync(join(playbooksDir, file), 'utf8');
      const parsed = YAML.parse(raw);
      const validation = validatePlaybook(parsed, file);
      
      if (validation.ok && validation.playbook) {
        result.push({ ...validation.playbook, file });
      }
    } catch {
      // Skip invalid
    }
  }
  
  return result.sort((a, b) => TIER_RANKS[a.tier] - TIER_RANKS[b.tier]);
}

export function getPlaybookById(id: string, dir?: string): Playbook | null {
  const playbooks = loadPlaybooks(dir);
  return playbooks.find(p => p.id === id) ?? null;
}
