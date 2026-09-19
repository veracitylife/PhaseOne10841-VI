/**
 * Multi-tenant org controls — orgs, scoped agents/events, org_admin RBAC.
 * DEFENSIVE ONLY — strict tenant isolation.
 */

import { createHash, randomBytes } from 'node:crypto';
import { getPool } from '../../recorder/src/db.js';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

async function query<T extends object = Record<string, unknown>>(
  sql: string,
  params: unknown[] = []
): Promise<{ rows: T[] }> {
  return getPool().query(sql, params) as unknown as Promise<{ rows: T[] }>;
}

export interface OrgRecord {
  id: string;
  name: string;
  settings_json: Record<string, unknown>;
  soft_deleted: boolean;
  created_at?: string;
  updated_at?: string;
}

export type OrgRole = 'global_admin' | 'org_admin' | 'viewer' | 'none';

const memoryOrgs = new Map<string, OrgRecord>();

function slugify(name: string): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 48) || `org-${randomBytes(3).toString('hex')}`
  );
}

export async function createOrg(
  name: string,
  settings: Record<string, unknown> = {}
): Promise<{ ok: boolean; org?: OrgRecord; error?: string }> {
  const id = slugify(name);
  const org: OrgRecord = {
    id,
    name,
    settings_json: settings,
    soft_deleted: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  try {
    await query(
      `INSERT INTO orgs (id, name, settings_json)
       VALUES ($1, $2, $3::jsonb)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, updated_at = NOW(), soft_deleted = FALSE`,
      [org.id, org.name, JSON.stringify(org.settings_json)]
    );
    return { ok: true, org };
  } catch {
    memoryOrgs.set(org.id, org);
    return { ok: true, org };
  }
}

export async function getOrg(orgId: string): Promise<OrgRecord | null> {
  try {
    const res = await query<OrgRecord>(
      `SELECT id, name, settings_json, soft_deleted, created_at, updated_at
       FROM orgs WHERE id = $1 AND soft_deleted = FALSE`,
      [orgId]
    );
    return res.rows[0] ?? null;
  } catch {
    const o = memoryOrgs.get(orgId);
    return o && !o.soft_deleted ? o : null;
  }
}

export async function listOrgs(): Promise<OrgRecord[]> {
  try {
    const res = await query<OrgRecord>(
      `SELECT id, name, settings_json, soft_deleted, created_at, updated_at
       FROM orgs WHERE soft_deleted = FALSE ORDER BY name`
    );
    return res.rows;
  } catch {
    return [...memoryOrgs.values()].filter((o) => !o.soft_deleted);
  }
}

export async function softDeleteOrg(orgId: string): Promise<{ ok: boolean }> {
  try {
    await query(`UPDATE orgs SET soft_deleted = TRUE, updated_at = NOW() WHERE id = $1`, [orgId]);
    return { ok: true };
  } catch {
    const o = memoryOrgs.get(orgId);
    if (o) o.soft_deleted = true;
    return { ok: true };
  }
}

export function resolveOrgRole(
  emailRaw: string,
  orgId: string | undefined,
  opts?: {
    globalAdminEmails?: string[];
    orgAdminMap?: Record<string, string[]>;
  }
): OrgRole {
  const email = emailRaw.trim().toLowerCase();
  if (!email) return 'none';
  const globalAdmins = (
    opts?.globalAdminEmails ??
    (process.env.PHASEONE_ADMIN_EMAILS ?? 'admin@localhost').split(',')
  )
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (globalAdmins.includes('*') || globalAdmins.includes(email)) return 'global_admin';

  if (!orgId) return 'none';

  let map = opts?.orgAdminMap;
  if (!map) {
    try {
      map = JSON.parse(process.env.PHASEONE_ORG_ADMINS ?? '{}') as Record<string, string[]>;
    } catch {
      map = {};
    }
  }
  const orgAdmins = (map[orgId] ?? []).map((s) => s.trim().toLowerCase());
  if (orgAdmins.includes(email) || orgAdmins.includes('*')) return 'org_admin';
  return 'none';
}

export function canAccessOrg(role: OrgRole, orgId: string, requestOrgId: string): boolean {
  if (role === 'global_admin') return true;
  if (role === 'org_admin' && orgId === requestOrgId) return true;
  return false;
}

export function hashApiKey(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

export function mintOrgApiKey(): { raw: string; prefix: string; hash: string } {
  const raw = `po_${randomBytes(24).toString('base64url')}`;
  return { raw, prefix: raw.slice(0, 10), hash: hashApiKey(raw) };
}

/**
 * Resolve org-scoped policy path: policy/orgs/<orgId>/policy.yaml falling back to global.
 */
export function resolveOrgPolicyPath(
  orgId: string,
  root = process.cwd()
): { path: string; scoped: boolean } {
  const scoped = resolve(root, 'policy', 'orgs', orgId, 'policy.yaml');
  if (existsSync(scoped)) return { path: scoped, scoped: true };
  const global =
    process.env.PHASEONE_POLICY_PATH ?? resolve(root, 'policy', 'default-policy.yaml');
  return { path: global, scoped: false };
}

export function resolveOrgPlaybooksDir(
  orgId: string,
  root = process.cwd()
): { path: string; scoped: boolean } {
  const scoped = resolve(root, 'playbooks', 'orgs', orgId);
  if (existsSync(scoped)) return { path: scoped, scoped: true };
  return { path: resolve(root, 'playbooks'), scoped: false };
}

export function ensureOrgPolicyDir(orgId: string, root = process.cwd()): string {
  const dir = join(root, 'policy', 'orgs', orgId);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function readOrgSettingsFile(orgId: string, root = process.cwd()): Record<string, unknown> {
  const p = join(root, 'policy', 'orgs', orgId, 'settings.json');
  if (!existsSync(p)) return {};
  try {
    return JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export function __testResetOrgs(): void {
  memoryOrgs.clear();
}
