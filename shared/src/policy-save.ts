/**
 * Validated policy YAML save path with backup of previous version.
 * Safe keys only — no code execution.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import YAML from 'yaml';
import type { PolicyConfig } from '../../policy/src/types.js';

export const ALLOWED_POLICY_KEYS = new Set([
  'version',
  'name',
  'domains',
  'tools',
  'shell',
  'filesystem',
  'http',
  'mcp',
  'destructive',
  'agent_spawn',
  'secret_egress',
  'canary',
  'approval',
  'siem',
  'prompt_injection',
  'a2a',
  'permission_analyzer',
  'alerting',
  'detection_rules',
]);

export interface PolicyValidateResult {
  ok: boolean;
  error?: string;
  parsed?: PolicyConfig;
}

export function validatePolicyYaml(yamlText: string): PolicyValidateResult {
  if (!yamlText || typeof yamlText !== 'string') {
    return { ok: false, error: 'yaml string required' };
  }
  if (yamlText.length > 200_000) {
    return { ok: false, error: 'yaml too large' };
  }
  let parsed: PolicyConfig;
  try {
    parsed = YAML.parse(yamlText) as PolicyConfig;
  } catch (err) {
    return { ok: false, error: `invalid YAML: ${err instanceof Error ? err.message : 'parse error'}` };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: 'policy must be a mapping' };
  }
  for (const key of Object.keys(parsed)) {
    if (!ALLOWED_POLICY_KEYS.has(key)) {
      return { ok: false, error: `disallowed policy key: ${key}` };
    }
  }
  if (!parsed.version || !parsed.name) {
    return { ok: false, error: 'version and name required' };
  }
  return { ok: true, parsed };
}

export function backupPolicyFile(policyPath: string, backupDir?: string): string | null {
  if (!existsSync(policyPath)) return null;
  const dir = backupDir ?? join(dirname(policyPath), 'backups');
  mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = join(dir, `${basename(policyPath)}.${stamp}.bak`);
  copyFileSync(policyPath, dest);
  return dest;
}

export function savePolicyYaml(
  policyPath: string,
  yamlText: string,
  opts?: { dry_run?: boolean; backupDir?: string; actor?: string }
): {
  ok: boolean;
  error?: string;
  dry_run?: boolean;
  parsed?: PolicyConfig;
  path?: string;
  backup?: string | null;
} {
  const v = validatePolicyYaml(yamlText);
  if (!v.ok) return { ok: false, error: v.error };
  if (opts?.dry_run) {
    return { ok: true, dry_run: true, parsed: v.parsed };
  }
  const backup = backupPolicyFile(policyPath, opts?.backupDir);
  const actor = opts?.actor ?? 'admin';
  const stamped =
    `# Updated by PhaseOne10841 admin — Veracity Integrity LLC\n` +
    `# ${new Date().toISOString()} · actor=${actor}\n` +
    yamlText.trim() +
    '\n';
  writeFileSync(policyPath, stamped, 'utf8');
  return { ok: true, path: policyPath, parsed: v.parsed, backup };
}

export function readPolicyRaw(policyPath: string): string {
  return readFileSync(policyPath, 'utf8');
}
