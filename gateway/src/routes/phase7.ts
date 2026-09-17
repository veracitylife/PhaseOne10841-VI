/**
 * Phase 7 API routes — Gatekeeper automated defense orchestration.
 * DEFENSIVE ONLY.
 * 
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */
import type { Hono } from 'hono';
import type { GatewayConfig } from '../config.js';
import {
  getGatekeeperStatus,
  setGatekeeperEnabled,
  setGatekeeperDryRun,
  processEvent,
  runGatekeeperCycle,
  confirmPendingAction,
  denyPendingAction,
  queueEvent,
  convertRuleHitToEvent,
  loadGatekeeperConfig,
} from '../../../gatekeeper/src/worker.js';
import {
  loadPlaybooks,
  listPlaybooksDetailed,
  validatePlaybook,
  resetPlaybooksCache,
} from '../../../gatekeeper/src/playbooks.js';
import {
  listRuntimeOverrides,
  getDashboardNotifications,
  clearExpiredOverrides,
} from '../../../gatekeeper/src/actions.js';
import { recordAudit } from '../../../shared/src/audit.js';
import { evaluateRules } from '../../../rules/src/engine.js';
import type { GatekeeperEvent } from '../../../gatekeeper/src/types.js';

export function registerPhase7Routes(app: Hono, _cfg: GatewayConfig): void {
  app.get('/v1/phaseone/gatekeeper/status', (c) => {
    const status = getGatekeeperStatus();
    return c.json({
      ...status,
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
    });
  });

  app.get('/v1/phaseone/gatekeeper/config', (c) => {
    const config = loadGatekeeperConfig();
    return c.json({
      ...config,
      product: 'PhaseOne10841',
    });
  });

  app.post('/v1/phaseone/gatekeeper/config', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      enabled?: boolean;
      dry_run?: boolean;
      actor_email?: string;
    };

    if (typeof body.enabled === 'boolean') {
      setGatekeeperEnabled(body.enabled);
    }
    if (typeof body.dry_run === 'boolean') {
      setGatekeeperDryRun(body.dry_run);
    }

    if (body.actor_email) {
      await recordAudit({
        actor_email: body.actor_email,
        action: 'gatekeeper.config',
        detail: { enabled: body.enabled, dry_run: body.dry_run },
      });
    }

    return c.json({
      ok: true,
      state: getGatekeeperStatus().state,
    });
  });

  app.get('/v1/phaseone/gatekeeper/playbooks', (c) => {
    resetPlaybooksCache();
    const playbooks = listPlaybooksDetailed();
    return c.json({
      data: playbooks,
      count: playbooks.length,
      tiers: {
        observe: playbooks.filter(p => p.tier === 'observe').length,
        contain: playbooks.filter(p => p.tier === 'contain').length,
        harden: playbooks.filter(p => p.tier === 'harden').length,
      },
      product: 'PhaseOne10841',
    });
  });

  app.post('/v1/phaseone/gatekeeper/playbooks/validate', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { playbook?: unknown };
    if (!body.playbook) {
      return c.json({ ok: false, error: 'playbook object required' }, 400);
    }
    const result = validatePlaybook(body.playbook);
    return c.json(result, result.ok ? 200 : 400);
  });

  app.post('/v1/phaseone/gatekeeper/queue', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      event?: GatekeeperEvent;
      events?: GatekeeperEvent[];
    };

    const events = body.events ?? (body.event ? [body.event] : []);
    if (events.length === 0) {
      return c.json({ ok: false, error: 'event or events array required' }, 400);
    }

    for (const event of events) {
      event.id = event.id ?? `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      event.timestamp = event.timestamp ?? Date.now();
      queueEvent(event);
    }

    return c.json({
      ok: true,
      queued: events.length,
      queue_size: getGatekeeperStatus().queue_size,
    });
  });

  app.post('/v1/phaseone/gatekeeper/process', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      event: GatekeeperEvent;
      dry_run?: boolean;
    };

    if (!body.event || !body.event.event_type) {
      return c.json({ ok: false, error: 'event with event_type required' }, 400);
    }

    body.event.id = body.event.id ?? `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    body.event.timestamp = body.event.timestamp ?? Date.now();

    const executions = await processEvent(body.event, {
      dryRunOverride: body.dry_run,
    });

    return c.json({
      ok: true,
      event: body.event,
      executions,
      dry_run: body.dry_run ?? getGatekeeperStatus().state.dry_run,
    });
  });

  app.post('/v1/phaseone/gatekeeper/run', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      dry_run?: boolean;
      actor_email?: string;
    };

    const result = await runGatekeeperCycle({
      dryRunOverride: body.dry_run,
    });

    if (body.actor_email && result.executions.length > 0) {
      await recordAudit({
        actor_email: body.actor_email,
        action: 'gatekeeper.run',
        detail: {
          processed: result.processed,
          executions: result.executions.length,
          dry_run: body.dry_run,
        },
      });
    }

    return c.json({
      ok: true,
      ...result,
      dry_run: body.dry_run ?? getGatekeeperStatus().state.dry_run,
    });
  });

  app.get('/v1/phaseone/gatekeeper/pending', (c) => {
    const status = getGatekeeperStatus();
    return c.json({
      data: status.state.pending_confirmations,
      count: status.state.pending_confirmations.length,
    });
  });

  app.post('/v1/phaseone/gatekeeper/confirm/:id', async (c) => {
    const id = c.req.param('id');
    const body = (await c.req.json().catch(() => ({}))) as {
      actor_email?: string;
    };

    const approvedBy = body.actor_email ?? 'api';
    const result = await confirmPendingAction(id, approvedBy);

    return c.json(result, result.ok ? 200 : 400);
  });

  app.post('/v1/phaseone/gatekeeper/deny/:id', async (c) => {
    const id = c.req.param('id');
    const body = (await c.req.json().catch(() => ({}))) as {
      actor_email?: string;
    };

    const deniedBy = body.actor_email ?? 'api';
    const result = await denyPendingAction(id, deniedBy);

    return c.json(result, result.ok ? 200 : 400);
  });

  app.get('/v1/phaseone/gatekeeper/recent', (c) => {
    const limit = Number(c.req.query('limit') ?? 50);
    const status = getGatekeeperStatus();
    const recent = status.state.recent_actions.slice(0, limit);
    return c.json({
      data: recent,
      count: recent.length,
      total: status.state.executions_count,
    });
  });

  app.get('/v1/phaseone/gatekeeper/overrides', (c) => {
    const overrides = listRuntimeOverrides();
    return c.json({
      data: overrides,
      count: Object.keys(overrides).length,
    });
  });

  app.post('/v1/phaseone/gatekeeper/overrides/cleanup', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      actor_email?: string;
    };

    const cleared = clearExpiredOverrides();

    if (body.actor_email) {
      await recordAudit({
        actor_email: body.actor_email,
        action: 'gatekeeper.cleanup',
        detail: { cleared },
      });
    }

    return c.json({ ok: true, cleared });
  });

  app.get('/v1/phaseone/gatekeeper/notifications', (c) => {
    const limit = Number(c.req.query('limit') ?? 50);
    const notifications = getDashboardNotifications(limit);
    return c.json({
      data: notifications,
      count: notifications.length,
    });
  });

  app.post('/v1/phaseone/gatekeeper/rules-event', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      event: {
        event_type?: string;
        tool_name?: string;
        decision?: string;
        decision_reason?: string;
        destination?: string;
        injection_score?: number;
        a2a_trust?: string;
        canary?: boolean;
        agent_id?: string;
        session_id?: string;
        metadata?: Record<string, unknown>;
      };
      dry_run?: boolean;
    };

    if (!body.event) {
      return c.json({ ok: false, error: 'event object required' }, 400);
    }

    const ruleHits = evaluateRules(body.event);

    const executions = [];
    for (const hit of ruleHits) {
      const gatekeeperEvent = convertRuleHitToEvent(hit, {
        event_type: body.event.event_type,
        agent_id: body.event.agent_id,
        session_id: body.event.session_id,
        decision: body.event.decision,
      });

      const playbookExecutions = await processEvent(gatekeeperEvent, {
        dryRunOverride: body.dry_run,
      });
      executions.push(...playbookExecutions);
    }

    return c.json({
      ok: true,
      rule_hits: ruleHits,
      executions,
      dry_run: body.dry_run ?? getGatekeeperStatus().state.dry_run,
    });
  });
}

export function hookGatekeeperToRuleHits(ruleHit: {
  rule_id: string;
  title: string;
  level: string;
  matched: Record<string, unknown>;
}, context: {
  event_type?: string;
  agent_id?: string;
  session_id?: string;
  decision?: string;
}): void {
  const config = loadGatekeeperConfig();
  if (!config.enabled) return;

  const event = convertRuleHitToEvent(ruleHit, context);
  queueEvent(event);
}
