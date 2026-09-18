/**
 * Phase 4 API routes — healthz/readyz, metrics, audit, rules, canaries, alerts, A2A list.
 * DEFENSIVE ONLY.
 */
import type { Hono } from 'hono';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { healthCheck } from '../../../recorder/src/db.js';
import { renderPrometheus, Metrics, getCounter } from '../../../shared/src/metrics.js';
import { listAudit, recordAudit } from '../../../shared/src/audit.js';
import { loadAlertConfig, sendAlert } from '../../../shared/src/alerting.js';
import {
  listRulesWithCounts,
  evaluateRules,
  loadRules,
  resetRulesCache,
} from '../../../rules/src/engine.js';
import {
  listCanariesDetailed,
  rotateCanary,
  noteCanaryTrigger,
  matchCanariesRuntime,
  signAllCanaries,
  verifyAllCanaries,
} from '../../../canaries/src/manager.js';
import { getPublicKeyInfo, ensureCanaryKeys } from '../../../shared/src/canary-sign.js';
import {
  validatePolicyYaml,
  savePolicyYaml,
  ALLOWED_POLICY_KEYS,
} from '../../../shared/src/policy-save.js';
import { loadPolicy, getPolicy } from '../../../policy/src/engine.js';
import type { GatewayConfig } from '../config.js';
import { listCanaryFiles } from '../../../canaries/src/detector.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function policyPath(cfg: GatewayConfig): string {
  return (
    cfg.policyPath ??
    process.env.PHASEONE_POLICY_PATH ??
    join(__dirname, '../../../policy/default-policy.yaml')
  );
}

function rulesDir(cfg: GatewayConfig): string {
  return cfg.rulesDir ?? process.env.PHASEONE_RULES_DIR ?? join(__dirname, '../../../rules');
}

export function registerPhase4Routes(app: Hono, cfg: GatewayConfig): void {
  /** Liveness — process up */
  app.get('/healthz', (c) => {
    return c.json({
      status: 'ok',
      service: 'phaseone-gateway',
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
      site: 'https://VeracityIntegrity.com',
      version: cfg.productVersion,
    });
  });

  /** Readiness — DB reachable */
  app.get('/readyz', async (c) => {
    const dbOk = await healthCheck();
    const body = {
      status: dbOk ? 'ready' : 'not_ready',
      db: dbOk,
      service: 'phaseone-gateway',
      version: cfg.productVersion,
    };
    return c.json(body, dbOk ? 200 : 503);
  });

  app.get('/metrics', (c) => {
    c.header('content-type', 'text/plain; version=0.0.4; charset=utf-8');
    return c.body(renderPrometheus());
  });

  app.get('/v1/phaseone/metrics', (c) => {
    return c.json({
      blocks: getCounter('phaseone_blocks_total'),
      canaries: getCounter('phaseone_canaries_total'),
      prometheus_text: renderPrometheus(),
    });
  });

  /** Detection rules */
  app.get('/v1/phaseone/rules', (c) => {
    resetRulesCache();
    const rules = listRulesWithCounts(rulesDir(cfg));
    return c.json({
      data: rules,
      dir: rulesDir(cfg),
      count: rules.length,
      product: 'PhaseOne10841',
    });
  });

  app.post('/v1/phaseone/rules/evaluate', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    const hits = evaluateRules(body as never, rulesDir(cfg));
    for (const h of hits) Metrics.ruleHit(h.rule_id);
    return c.json({ hits, count: hits.length });
  });

  /** Canary management */
  app.get('/v1/phaseone/canaries/manage', (c) => {
    return c.json({
      data: listCanariesDetailed(),
      files: listCanaryFiles(),
      note: 'Markers are harmless fakes. Rotate replaces runtime marker values safely.',
    });
  });

  app.post('/v1/phaseone/canaries/rotate', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      canary_id?: string;
      name?: string;
      actor_email?: string;
    };
    if (!body.canary_id) return c.json({ ok: false, error: 'canary_id required' }, 400);
    const result = rotateCanary(body.canary_id, body.name);
    if (result.ok && body.actor_email) {
      await recordAudit({
        actor_email: body.actor_email,
        action: 'canary.rotate',
        resource: body.canary_id,
        detail: { name: body.name, previous_preview: result.previous_preview },
      });
    }
    return c.json(result, result.ok ? 200 : 404);
  });

  app.post('/v1/phaseone/canaries/match', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      text?: string;
      session_id?: string;
      agent_id?: string;
    };
    const hits = matchCanariesRuntime(body.text ?? '');
    for (const h of hits) {
      noteCanaryTrigger(h.canaryId, {
        session_id: body.session_id,
        agent_id: body.agent_id,
        name: h.name,
      });
      Metrics.canary();
    }
    return c.json({ hits, count: hits.length });
  });

  /** Signed canary verify / sign (Wave B #7) */
  app.get('/v1/phaseone/canaries/verify', (c) => {
    const results = verifyAllCanaries();
    const invalid = results.filter((r) => r.valid === false);
    const unsigned = results.filter((r) => r.valid === null);
    return c.json({
      ok: invalid.length === 0,
      results,
      invalid_count: invalid.length,
      unsigned_count: unsigned.length,
      public_key: getPublicKeyInfo(),
      note: 'Tamper detection is warn-oriented on first run; never blocks gateway startup.',
    });
  });

  app.post('/v1/phaseone/canaries/sign', async (c) => {
    ensureCanaryKeys();
    const result = signAllCanaries();
    const body = (await c.req.json().catch(() => ({}))) as { actor_email?: string };
    if (body.actor_email) {
      await recordAudit({
        actor_email: body.actor_email,
        action: 'canary.sign',
        resource: result.key_id,
        detail: { signed: result.signed },
      });
    }
    return c.json({ ok: true, ...result });
  });

  /** Admin audit log */
  app.get('/v1/phaseone/audit', async (c) => {
    const data = await listAudit({
      limit: Number(c.req.query('limit') ?? 100),
      actor: c.req.query('actor') || undefined,
      action: c.req.query('action') || undefined,
    });
    return c.json({ data });
  });

  app.post('/v1/phaseone/audit', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      actor_email?: string;
      action?: string;
      resource?: string;
      detail?: Record<string, unknown>;
      ip?: string;
    };
    if (!body.actor_email || !body.action) {
      return c.json({ ok: false, error: 'actor_email and action required' }, 400);
    }
    const entry = await recordAudit({
      actor_email: body.actor_email,
      action: body.action,
      resource: body.resource,
      detail: body.detail,
      ip: body.ip,
    });
    return c.json(entry, 201);
  });

  /** A2A trust list (read) */
  app.get('/v1/phaseone/a2a/trust', (c) => {
    const a2a = getPolicy().a2a ?? {};
    return c.json({
      a2a,
      levels: [
        'LOCAL-TRUSTED',
        'LOCAL-UNTRUSTED',
        'REMOTE-VERIFIED',
        'REMOTE-UNKNOWN',
        'QUARANTINED',
      ],
    });
  });

  /** Alerting */
  app.get('/v1/phaseone/alerts/config', (c) => {
    const ac = loadAlertConfig();
    return c.json({
      enabled: ac.enabled,
      webhook_configured: Boolean(ac.webhookUrl),
      max_retries: ac.maxRetries,
      base_delay_ms: ac.baseDelayMs,
    });
  });

  app.post('/v1/phaseone/alerts/test', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      url?: string;
      actor_email?: string;
    };
    const cfgAlert = loadAlertConfig();
    const result = await sendAlert(
      {
        event: 'alert.test',
        severity: 'high',
        message: 'PhaseOne10841 alert test from admin console',
        detail: { actor: body.actor_email },
      },
      {
        ...cfgAlert,
        webhookUrl: body.url ?? cfgAlert.webhookUrl,
        enabled: true,
      }
    );
    if (body.actor_email) {
      await recordAudit({
        actor_email: body.actor_email,
        action: 'alert.test',
        detail: { ok: result.ok, attempts: result.attempts },
      });
    }
    return c.json(result, result.ok ? 200 : 502);
  });

  /** Enhanced policy PUT with backup (also kept on phase3; this is the Phase 4 path) */
  app.put('/v1/phaseone/policy/v2', async (c) => {
    const body = (await c.req.json()) as {
      yaml?: string;
      dry_run?: boolean;
      actor_email?: string;
    };
    if (!body.yaml) return c.json({ ok: false, error: 'yaml string required' }, 400);
    const path = policyPath(cfg);
    const result = savePolicyYaml(path, body.yaml, {
      dry_run: body.dry_run,
      actor: body.actor_email,
    });
    if (!result.ok) return c.json(result, 400);
    if (!body.dry_run) {
      loadPolicy(path);
      if (body.actor_email) {
        await recordAudit({
          actor_email: body.actor_email,
          action: 'policy.save',
          resource: path,
          detail: { backup: result.backup },
        });
      }
      return c.json({ ...result, parsed: getPolicy() });
    }
    if (body.actor_email) {
      await recordAudit({
        actor_email: body.actor_email,
        action: 'policy.dry_run',
        resource: path,
      });
    }
    return c.json(result);
  });

  app.get('/v1/phaseone/policy/allowed-keys', (c) => {
    return c.json({ keys: [...ALLOWED_POLICY_KEYS].sort() });
  });

  app.post('/v1/phaseone/policy/validate', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { yaml?: string };
    const v = validatePolicyYaml(body.yaml ?? '');
    return c.json(v, v.ok ? 200 : 400);
  });
}

/** Hook used by enforce/recorder paths to evaluate detection rules on events */
export function evaluateEventRules(ctx: {
  event_type?: string;
  tool_name?: string;
  decision?: string;
  decision_reason?: string;
  destination?: string;
  injection_score?: number;
  a2a_trust?: string;
  canary?: boolean;
  metadata?: Record<string, unknown>;
}): ReturnType<typeof evaluateRules> {
  const dir = process.env.PHASEONE_RULES_DIR ?? join(__dirname, '../../../rules');
  const hits = evaluateRules(ctx, dir);
  for (const h of hits) Metrics.ruleHit(h.rule_id);
  return hits;
}

export { loadRules, validatePolicyYaml };
