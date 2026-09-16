/**
 * Phase 3 API routes — SIEM export, rich timeline, policy write, agents, health detail.
 * Mounted from gateway index.
 */
import type { Hono } from 'hono';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import {
  listEvents,
  listAgents,
  listSessions,
  getRichSessionTimeline,
  recordEvent,
} from '../../../recorder/src/recorder.js';
import { eventsToJsonl, sendWebhookSink, toEcsLike } from '../../../recorder/src/export.js';
import { loadPolicy, getPolicy } from '../../../policy/src/engine.js';
import type { PolicyConfig } from '../../../policy/src/types.js';
import { listCanaryFiles } from '../../../canaries/src/detector.js';
import { listSecretPatternTypes } from '../../../shared/src/secrets.js';
import type { GatewayConfig } from '../config.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function policyPath(cfg: GatewayConfig): string {
  return (
    cfg.policyPath ??
    process.env.PHASEONE_POLICY_PATH ??
    join(__dirname, '../../../policy/default-policy.yaml')
  );
}

/** Safe YAML merge: only allow known top-level keys; reject shell/code injection via parse. */
const ALLOWED_POLICY_KEYS = new Set([
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
]);

export function registerPhase3Routes(app: Hono, cfg: GatewayConfig): void {
  app.get('/v1/phaseone/sessions/:id/replay', async (c) => {
    const agentId = c.req.query('agent_id') || undefined;
    const rich = await getRichSessionTimeline(c.req.param('id'), { agentId });
    return c.json(rich);
  });


  app.get('/v1/phaseone/sessions/:id/export.jsonl', async (c) => {
    const rich = await getRichSessionTimeline(c.req.param('id'));
    const body = eventsToJsonl(rich.events, { version: cfg.productVersion });
    return c.body(body, 200, {
      'content-type': 'application/x-ndjson; charset=utf-8',
      'content-disposition': `attachment; filename="phaseone-session-${c.req.param('id')}.jsonl"`,
    });
  });

  app.get('/v1/phaseone/export/events.jsonl', async (c) => {
    const sessionId = c.req.query('session_id') || undefined;
    const agentId = c.req.query('agent_id') || undefined;
    const eventType = c.req.query('event_type') || undefined;
    const limit = Number(c.req.query('limit') ?? 500);
    const events = await listEvents({ sessionId, agentId, eventType, limit });
    const body = eventsToJsonl(events, { version: cfg.productVersion });
    await recordEvent({
      session_id: sessionId ?? '00000000-0000-4000-8000-000000000001',
      agent_id: agentId ?? 'siem-export',
      event_type: 'siem.export',
      severity: 'info',
      decision: 'allow',
      decision_reason: `exported ${events.length} events as JSONL`,
      metadata: { count: events.length, format: 'ecs-ish' },
    }).catch(() => undefined);
    return c.body(body, 200, {
      'content-type': 'application/x-ndjson; charset=utf-8',
      'content-disposition': 'attachment; filename="phaseone-events.jsonl"',
    });
  });

  app.post('/v1/phaseone/export/webhook', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      url?: string;
      session_id?: string;
      agent_id?: string;
      limit?: number;
    };
    const url = body.url ?? cfg.siemWebhookUrl ?? getPolicy().siem?.webhook_url;
    if (!url) {
      return c.json({ ok: false, error: 'webhook URL not configured (body.url or PHASEONE_SIEM_WEBHOOK_URL)' }, 400);
    }
    const events = await listEvents({
      sessionId: body.session_id,
      agentId: body.agent_id,
      limit: body.limit ?? 100,
    });
    const result = await sendWebhookSink(url, events, { version: cfg.productVersion });
    await recordEvent({
      session_id: body.session_id ?? '00000000-0000-4000-8000-000000000001',
      agent_id: body.agent_id ?? 'siem-webhook',
      event_type: 'siem.webhook',
      severity: result.ok ? 'info' : 'medium',
      decision: result.ok ? 'allow' : 'deny',
      decision_reason: result.ok ? `webhook sent ${result.sent}` : result.error,
      metadata: { status: result.status, sent: result.sent },
    }).catch(() => undefined);
    return c.json(result, result.ok ? 200 : 502);
  });

  app.get('/v1/phaseone/export/preview', async (c) => {
    const events = await listEvents({ limit: Number(c.req.query('limit') ?? 5) });
    return c.json({
      format: 'ecs-ish',
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
      site: 'https://VeracityIntegrity.com',
      sample: events.map((e) => toEcsLike(e, { version: cfg.productVersion })),
    });
  });

  app.get('/v1/phaseone/agents', async (c) => {
    const agents = await listAgents();
    return c.json({ data: agents });
  });

  app.get('/v1/phaseone/sessions', async (c) => {
    const sessions = await listSessions(Number(c.req.query('limit') ?? 50));
    return c.json({ data: sessions });
  });


  app.get('/v1/phaseone/secrets/patterns', (c) => {
    return c.json({ patterns: listSecretPatternTypes() });
  });

  app.get('/v1/phaseone/policy/raw', (c) => {
    const raw = readFileSync(policyPath(cfg), 'utf8');
    return c.json({ path: policyPath(cfg), yaml: raw, parsed: getPolicy() });
  });

  app.put('/v1/phaseone/policy', async (c) => {
    const body = (await c.req.json()) as { yaml?: string; dry_run?: boolean };
    if (!body.yaml || typeof body.yaml !== 'string') {
      return c.json({ ok: false, error: 'yaml string required' }, 400);
    }
    if (body.yaml.length > 200_000) {
      return c.json({ ok: false, error: 'yaml too large' }, 400);
    }
    let parsed: PolicyConfig;
    try {
      parsed = YAML.parse(body.yaml) as PolicyConfig;
    } catch (err) {
      return c.json({ ok: false, error: `invalid YAML: ${err instanceof Error ? err.message : 'parse error'}` }, 400);
    }
    if (!parsed || typeof parsed !== 'object') {
      return c.json({ ok: false, error: 'policy must be a mapping' }, 400);
    }
    for (const key of Object.keys(parsed)) {
      if (!ALLOWED_POLICY_KEYS.has(key)) {
        return c.json({ ok: false, error: `disallowed policy key: ${key}` }, 400);
      }
    }
    if (!parsed.version || !parsed.name) {
      return c.json({ ok: false, error: 'version and name required' }, 400);
    }
    if (body.dry_run) {
      return c.json({ ok: true, dry_run: true, parsed });
    }
    const path = policyPath(cfg);
    const stamped = `# Updated by PhaseOne10841 admin UI — Veracity Integrity LLC\n# ${new Date().toISOString()}\n` + body.yaml.trim() + '\n';
    writeFileSync(path, stamped, 'utf8');
    loadPolicy(path);
    return c.json({ ok: true, path, parsed: getPolicy() });
  });

  /** A2A trust admin — update in-memory/policy a2a lists via safe YAML merge */
  app.post('/v1/phaseone/a2a/trust', async (c) => {
    const body = (await c.req.json()) as {
      agent_id: string;
      trust: 'LOCAL-TRUSTED' | 'LOCAL-UNTRUSTED' | 'REMOTE-VERIFIED' | 'QUARANTINED' | 'clear';
      persist?: boolean;
    };
    if (!body.agent_id || !body.trust) {
      return c.json({ ok: false, error: 'agent_id and trust required' }, 400);
    }
    const policy = { ...getPolicy() };
    const a2a = {
      ...(policy.a2a ?? {
        enabled: true,
        default_remote: 'REMOTE-UNKNOWN' as const,
        local_trusted_agents: [],
        local_untrusted_agents: [],
        verified_remote_agents: [],
        quarantined_agents: [],
        block_quarantined: true,
        block_unknown_remote: false,
        scan_injection: true,
        block_on_injection: true,
        allow_from_to_same: true,
      }),
    };
    const strip = (arr: string[]) => arr.filter((a) => a !== body.agent_id);
    a2a.local_trusted_agents = strip(a2a.local_trusted_agents ?? []);
    a2a.local_untrusted_agents = strip(a2a.local_untrusted_agents ?? []);
    a2a.verified_remote_agents = strip(a2a.verified_remote_agents ?? []);
    a2a.quarantined_agents = strip(a2a.quarantined_agents ?? []);
    if (body.trust === 'LOCAL-TRUSTED') a2a.local_trusted_agents.push(body.agent_id);
    if (body.trust === 'LOCAL-UNTRUSTED') a2a.local_untrusted_agents.push(body.agent_id);
    if (body.trust === 'REMOTE-VERIFIED') a2a.verified_remote_agents.push(body.agent_id);
    if (body.trust === 'QUARANTINED') a2a.quarantined_agents.push(body.agent_id);
    policy.a2a = a2a;

    if (body.persist) {
      const path = policyPath(cfg);
      writeFileSync(path, YAML.stringify(policy), 'utf8');
      loadPolicy(path);
    } else {
      // Reload from file then overlay isn't available — persist to temp by rewriting
      writeFileSync(policyPath(cfg), YAML.stringify(policy), 'utf8');
      loadPolicy(policyPath(cfg));
    }
    return c.json({ ok: true, a2a: getPolicy().a2a });
  });



  app.get('/v1/phaseone/health/detail', async (c) => {
    const { healthCheck } = await import('../../../recorder/src/db.js');
    const dbOk = await healthCheck();
    return c.json({
      status: dbOk ? 'ok' : 'degraded',
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
      site: 'https://VeracityIntegrity.com',
      version: cfg.productVersion,
      db: dbOk,
      siem_webhook_configured: Boolean(cfg.siemWebhookUrl),
      approval: getPolicy().approval,
      secret_patterns: listSecretPatternTypes().length,
      canaries: listCanaryFiles().length,
    });
  });

}
