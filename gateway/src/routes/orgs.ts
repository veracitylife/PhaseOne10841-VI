/**
 * Org-scoped API routes — multi-tenant controls.
 * DEFENSIVE ONLY — strict isolation; global admin can see all.
 */

import type { Hono } from 'hono';
import {
  createOrg,
  getOrg,
  listOrgs,
  softDeleteOrg,
  resolveOrgRole,
  canAccessOrg,
  mintOrgApiKey,
  hashApiKey,
  resolveOrgPolicyPath,
  resolveOrgPlaybooksDir,
  ensureOrgPolicyDir,
} from '../../../shared/src/orgs.js';
import { recordAudit } from '../../../shared/src/audit.js';
import { getPool } from '../../../recorder/src/db.js';
import type { GatewayConfig } from '../config.js';

function actorEmail(c: { req: { header: (n: string) => string | undefined } }): string {
  return (
    c.req.header('x-phaseone-actor-email') ??
    c.req.header('x-actor-email') ??
    'operator@localhost'
  );
}

export function registerOrgRoutes(app: Hono, _cfg: GatewayConfig): void {
  app.get('/v1/orgs', async (c) => {
    const email = actorEmail(c);
    const role = resolveOrgRole(email, undefined);
    if (role !== 'global_admin') {
      return c.json({ error: 'global admin required', code: 'orgs.forbidden' }, 403);
    }
    const orgs = await listOrgs();
    return c.json({ orgs, count: orgs.length });
  });

  app.post('/v1/orgs', async (c) => {
    const email = actorEmail(c);
    const role = resolveOrgRole(email, undefined);
    if (role !== 'global_admin') {
      return c.json({ error: 'global admin required', code: 'orgs.forbidden' }, 403);
    }
    const body = (await c.req.json().catch(() => ({}))) as {
      name?: string;
      settings?: Record<string, unknown>;
    };
    if (!body.name?.trim()) {
      return c.json({ error: 'name required' }, 400);
    }
    const result = await createOrg(body.name.trim(), body.settings ?? {});
    if (result.org) {
      ensureOrgPolicyDir(result.org.id);
      await recordAudit({
        actor_email: email,
        action: 'org.create',
        resource: result.org.id,
        detail: { name: result.org.name },
      }).catch(() => undefined);
    }
    return c.json(result, result.ok ? 201 : 400);
  });

  app.get('/v1/orgs/:orgId', async (c) => {
    const orgId = c.req.param('orgId');
    const email = actorEmail(c);
    const role = resolveOrgRole(email, orgId);
    if (!canAccessOrg(role, orgId, orgId) && role !== 'global_admin') {
      return c.json({ error: 'forbidden', code: 'orgs.forbidden' }, 403);
    }
    const org = await getOrg(orgId);
    if (!org) return c.json({ error: 'org not found' }, 404);
    const policy = resolveOrgPolicyPath(orgId);
    const playbooks = resolveOrgPlaybooksDir(orgId);
    return c.json({ org, role, policy, playbooks });
  });

  app.delete('/v1/orgs/:orgId', async (c) => {
    const orgId = c.req.param('orgId');
    const email = actorEmail(c);
    const role = resolveOrgRole(email, orgId);
    if (role !== 'global_admin') {
      return c.json({ error: 'global admin required for soft-delete' }, 403);
    }
    await softDeleteOrg(orgId);
    await recordAudit({
      actor_email: email,
      action: 'org.soft_delete',
      resource: orgId,
    }).catch(() => undefined);
    return c.json({ ok: true, org_id: orgId, soft_deleted: true });
  });

  app.get('/v1/orgs/:orgId/events', async (c) => {
    const orgId = c.req.param('orgId');
    const email = actorEmail(c);
    const role = resolveOrgRole(email, orgId);
    if (!canAccessOrg(role, orgId, orgId) && role !== 'global_admin') {
      return c.json({ error: 'forbidden' }, 403);
    }
    const limit = Math.min(Number(c.req.query('limit') ?? 50), 200);
    try {
      const res = await getPool().query(
        `SELECT id, session_id, agent_id, event_type, severity, timestamp, decision, org_id
         FROM events WHERE org_id = $1 ORDER BY timestamp DESC LIMIT $2`,
        [orgId, limit]
      );
      return c.json({ org_id: orgId, events: res.rows, count: res.rows.length });
    } catch {
      return c.json({ org_id: orgId, events: [], count: 0, degraded: true });
    }
  });

  app.get('/v1/orgs/:orgId/policy', async (c) => {
    const orgId = c.req.param('orgId');
    const email = actorEmail(c);
    const role = resolveOrgRole(email, orgId);
    if (!canAccessOrg(role, orgId, orgId) && role !== 'global_admin') {
      return c.json({ error: 'forbidden' }, 403);
    }
    return c.json({
      org_id: orgId,
      ...resolveOrgPolicyPath(orgId),
      playbooks: resolveOrgPlaybooksDir(orgId),
    });
  });

  app.post('/v1/orgs/:orgId/api-keys', async (c) => {
    const orgId = c.req.param('orgId');
    const email = actorEmail(c);
    const role = resolveOrgRole(email, orgId);
    if (role !== 'global_admin' && role !== 'org_admin') {
      return c.json({ error: 'org_admin or global_admin required' }, 403);
    }
    const org = await getOrg(orgId);
    if (!org) return c.json({ error: 'org not found' }, 404);
    const body = (await c.req.json().catch(() => ({}))) as { label?: string };
    const minted = mintOrgApiKey();
    try {
      await getPool().query(
        `INSERT INTO org_api_keys (org_id, key_prefix, key_hash, label, created_by)
         VALUES ($1, $2, $3, $4, $5)`,
        [orgId, minted.prefix, minted.hash, body.label ?? null, email]
      );
    } catch {
      /* memory-only mint still returned once */
    }
    await recordAudit({
      actor_email: email,
      action: 'org.api_key.create',
      resource: orgId,
      detail: { prefix: minted.prefix, label: body.label },
    }).catch(() => undefined);
    return c.json({
      ok: true,
      org_id: orgId,
      key_prefix: minted.prefix,
      api_key: minted.raw,
      note: 'Store this key now — it will not be shown again. Hash only is retained.',
    });
  });

  app.post('/v1/orgs/:orgId/api-keys/verify', async (c) => {
    const orgId = c.req.param('orgId');
    const body = (await c.req.json().catch(() => ({}))) as { api_key?: string };
    if (!body.api_key) return c.json({ ok: false, error: 'api_key required' }, 400);
    const hash = hashApiKey(body.api_key);
    try {
      const res = await getPool().query(
        `SELECT id FROM org_api_keys
         WHERE org_id = $1 AND key_hash = $2 AND revoked = FALSE LIMIT 1`,
        [orgId, hash]
      );
      return c.json({ ok: res.rows.length > 0, org_id: orgId });
    } catch {
      return c.json({ ok: false, org_id: orgId, degraded: true });
    }
  });
}
