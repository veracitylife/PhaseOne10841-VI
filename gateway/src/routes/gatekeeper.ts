/**
 * Gatekeeper API routes — simulation, blast-radius, rate-caps.
 * DEFENSIVE ONLY.
 */
import type { Hono } from 'hono';
import { listEvents } from '../../../recorder/src/recorder.js';
import {
  simulateEvents,
  loadRateCapConfig,
  getRateCapStatus,
  checkRateCap,
  type SimulationConfig,
  type SimulationEvent,
} from '../../../shared/src/gatekeeper.js';
import type { GatewayConfig } from '../config.js';

export function registerGatekeeperRoutes(app: Hono, cfg: GatewayConfig): void {
  /**
   * POST /v1/phaseone/gatekeeper/simulate
   * Dry-run historical replay: evaluate events against current (or override) policy
   * without mutating anything.
   */
  app.post('/v1/phaseone/gatekeeper/simulate', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      events?: SimulationEvent[];
      use_historical?: boolean;
      config?: SimulationConfig;
      playbook_id?: string;
      from_time?: string | number;
      to_time?: string | number;
      max_events?: number;
      event_types?: string[];
      agent_ids?: string[];
      tool_names?: string[];
      policy_override?: Record<string, unknown>;
    };

    const config: SimulationConfig = {
      playbook_id: body.playbook_id ?? body.config?.playbook_id,
      from_time: body.from_time ?? body.config?.from_time,
      to_time: body.to_time ?? body.config?.to_time,
      max_events: body.max_events ?? body.config?.max_events ?? 1000,
      event_types: body.event_types ?? body.config?.event_types,
      agent_ids: body.agent_ids ?? body.config?.agent_ids,
      tool_names: body.tool_names ?? body.config?.tool_names,
      policy_override: body.policy_override ?? body.config?.policy_override,
    };

    let events: SimulationEvent[] = [];

    if (body.events && body.events.length > 0) {
      // Use provided events
      events = body.events;
    } else if (body.use_historical !== false) {
      // Fetch historical events from database
      const limit = config.max_events ?? 1000;
      const dbEvents = await listEvents({
        limit,
        eventType: config.event_types?.join(','),
        severity: undefined,
        sessionId: undefined,
      });
      
      // Convert DB events to simulation events
      events = dbEvents.map(e => ({
        id: e.id,
        session_id: e.session_id,
        agent_id: e.agent_id,
        event_type: e.event_type,
        tool_name: e.tool_name ?? undefined,
        tool_args: e.tool_args ?? undefined,
        destination: e.destination ?? undefined,
        timestamp: e.timestamp,
        ...(e.metadata as Record<string, unknown> ?? {}),
      }));
    }

    if (events.length === 0) {
      return c.json({
        ok: true,
        config,
        results: [],
        blast_radius: {
          total_events: 0,
          blocked_count: 0,
          approval_required_count: 0,
          allowed_count: 0,
          affected_agents: [],
          affected_tools: [],
          affected_domains: [],
          rule_hits: {},
          canary_matches: 0,
          secret_matches: 0,
        },
        simulation_time_ms: 0,
        dry_run: true,
        message: 'No events to simulate',
      });
    }

    const result = simulateEvents(events, config);
    return c.json(result);
  });

  /**
   * GET /v1/phaseone/gatekeeper/simulate
   * Quick simulation with query params for simple use cases
   */
  app.get('/v1/phaseone/gatekeeper/simulate', async (c) => {
    const limit = Number(c.req.query('limit') ?? 100);
    const eventType = c.req.query('event_type');
    const agentId = c.req.query('agent_id');

    const dbEvents = await listEvents({
      limit,
      eventType: eventType ?? undefined,
      severity: undefined,
      sessionId: undefined,
    });

    const events: SimulationEvent[] = dbEvents.map(e => ({
      id: e.id,
      session_id: e.session_id,
      agent_id: e.agent_id,
      event_type: e.event_type,
      tool_name: e.tool_name ?? undefined,
      tool_args: e.tool_args ?? undefined,
      destination: e.destination ?? undefined,
      timestamp: e.timestamp,
    }));

    const config: SimulationConfig = {
      max_events: limit,
      event_types: eventType ? [eventType] : undefined,
      agent_ids: agentId ? [agentId] : undefined,
    };

    const result = simulateEvents(events, config);
    return c.json(result);
  });

  /**
   * GET /v1/phaseone/gatekeeper/blast-radius
   * Get blast-radius summary for recent events
   */
  app.get('/v1/phaseone/gatekeeper/blast-radius', async (c) => {
    const limit = Number(c.req.query('limit') ?? 500);
    const dbEvents = await listEvents({ limit });

    const events: SimulationEvent[] = dbEvents.map(e => ({
      id: e.id,
      session_id: e.session_id,
      agent_id: e.agent_id,
      event_type: e.event_type,
      tool_name: e.tool_name ?? undefined,
      tool_args: e.tool_args ?? undefined,
      destination: e.destination ?? undefined,
      timestamp: e.timestamp,
    }));

    const result = simulateEvents(events, { max_events: limit });
    
    return c.json({
      ok: true,
      blast_radius: result.blast_radius,
      simulation_time_ms: result.simulation_time_ms,
      events_analyzed: events.length,
    });
  });

  /**
   * GET /v1/phaseone/gatekeeper/rate-caps
   * Get current rate-cap configuration and state
   */
  app.get('/v1/phaseone/gatekeeper/rate-caps', (c) => {
    const status = getRateCapStatus();
    return c.json({
      ok: true,
      ...status,
      env_vars: {
        PHASEONE_GATEKEEPER_MAX_ACTIONS: 'Max actions per window',
        PHASEONE_GATEKEEPER_WINDOW_MS: 'Rate limit window in ms',
        PHASEONE_GATEKEEPER_COOLDOWN_MS: 'Cooldown between same actions',
        PHASEONE_GATEKEEPER_MAX_PENDING: 'Max pending approvals',
        PHASEONE_GATEKEEPER_CB_THRESHOLD: 'Circuit breaker threshold',
        PHASEONE_GATEKEEPER_CB_COOLDOWN_MS: 'Circuit breaker cooldown',
      },
    });
  });

  /**
   * POST /v1/phaseone/gatekeeper/rate-cap-check
   * Test if an action would be rate-limited
   */
  app.post('/v1/phaseone/gatekeeper/rate-cap-check', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      action: string;
      agent_id?: string;
    };

    if (!body.action) {
      return c.json({ error: 'action required' }, 400);
    }

    const result = checkRateCap(body.action, body.agent_id);
    return c.json({
      ...result,
      action: body.action,
      agent_id: body.agent_id,
      dry_run: true,
    });
  });

  /**
   * GET /v1/phaseone/gatekeeper/status
   * Overall gatekeeper status
   */
  app.get('/v1/phaseone/gatekeeper/status', (c) => {
    const rateCapStatus = getRateCapStatus();
    const rateCapConfig = loadRateCapConfig();

    return c.json({
      ok: true,
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
      component: 'gatekeeper',
      version: cfg.productVersion,
      rate_caps: {
        enabled: true,
        config: rateCapConfig,
        state: rateCapStatus.state,
      },
      simulation: {
        enabled: true,
        endpoint: '/v1/phaseone/gatekeeper/simulate',
        methods: ['GET', 'POST'],
      },
      blast_radius: {
        enabled: true,
        endpoint: '/v1/phaseone/gatekeeper/blast-radius',
      },
      learn_loop: {
        enabled: true,
        endpoint: '/v1/phaseone/gatekeeper/effectiveness',
      },
    });
  });

  /**
   * GET /v1/phaseone/gatekeeper/effectiveness
   * Playbook learn-loop metrics + human-gated suggestions.
   */
  app.get('/v1/phaseone/gatekeeper/effectiveness', async (c) => {
    const { getEffectivenessReport } = await import('../../../shared/src/playbook-learn.js');
    const days = Number(c.req.query('days') ?? 7);
    const playbookId = c.req.query('playbook_id') ?? undefined;
    const report = await getEffectivenessReport({ days, playbook_id: playbookId });
    return c.json({
      ok: true,
      product: 'PhaseOne10841',
      ...report,
      note: 'Suggestions require human review before applying — never auto-applied.',
    });
  });

  /**
   * GET /v1/phaseone/gatekeeper/effectiveness/export
   * Export effectiveness data for offline analysis.
   */
  app.get('/v1/phaseone/gatekeeper/effectiveness/export', async (c) => {
    const { getEffectivenessReport } = await import('../../../shared/src/playbook-learn.js');
    const days = Number(c.req.query('days') ?? 30);
    const report = await getEffectivenessReport({ days });
    const body = JSON.stringify(report, null, 2);
    return c.body(body, 200, {
      'content-type': 'application/json',
      'content-disposition': 'attachment; filename="phaseone-playbook-effectiveness.json"',
    });
  });
}
