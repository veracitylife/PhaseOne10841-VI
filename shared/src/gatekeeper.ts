/**
 * Gatekeeper simulation and rate-cap module.
 * Provides dry-run policy replay and blast-radius analysis.
 * DEFENSIVE ONLY.
 */

import { evaluateToolCall, evaluatePolicy, getPolicy } from '../../policy/src/engine.js';
import type { PolicyDecision, PolicyCheckContext } from './types.js';

export interface SimulationEvent {
  id?: string;
  session_id?: string;
  agent_id?: string;
  event_type?: string;
  tool_name?: string;
  tool_args?: unknown;
  destination?: string;
  url?: string;
  method?: string;
  path?: string;
  shell_command?: string;
  mcp_server?: string;
  mcp_tool?: string;
  timestamp?: string | number;
  [key: string]: unknown;
}

export interface SimulationResult {
  event: SimulationEvent;
  decision: PolicyDecision;
  would_block: boolean;
  would_require_approval: boolean;
  matched_rules: string[];
}

export interface BlastRadiusSummary {
  total_events: number;
  blocked_count: number;
  approval_required_count: number;
  allowed_count: number;
  affected_agents: string[];
  affected_tools: string[];
  affected_domains: string[];
  rule_hits: Record<string, number>;
  canary_matches: number;
  secret_matches: number;
}

export interface SimulationConfig {
  /** Playbook ID or policy override (optional) */
  playbook_id?: string;
  /** Time window start (ISO or epoch ms) */
  from_time?: string | number;
  /** Time window end (ISO or epoch ms) */
  to_time?: string | number;
  /** Maximum events to process */
  max_events?: number;
  /** Include events matching these types only */
  event_types?: string[];
  /** Filter by agent ID */
  agent_ids?: string[];
  /** Filter by tool name */
  tool_names?: string[];
  /** Custom policy YAML override for simulation */
  policy_override?: Record<string, unknown>;
}

export interface SimulationOutput {
  ok: boolean;
  config: SimulationConfig;
  results: SimulationResult[];
  blast_radius: BlastRadiusSummary;
  simulation_time_ms: number;
  dry_run: true;
}

export interface RateCapConfig {
  /** Max contain/harden actions per window */
  max_actions_per_window: number;
  /** Window duration in ms */
  window_ms: number;
  /** Cooldown between similar actions in ms */
  cooldown_ms: number;
  /** Max concurrent pending approvals */
  max_pending_approvals: number;
  /** Global circuit breaker threshold */
  circuit_breaker_threshold: number;
  /** Circuit breaker cooldown ms */
  circuit_breaker_cooldown_ms: number;
}

export interface RateCapState {
  actions: Array<{ timestamp: number; action: string; agent_id?: string }>;
  circuit_breaker_tripped: boolean;
  circuit_breaker_until?: number;
  pending_approvals: number;
}

const DEFAULT_RATE_CAP: RateCapConfig = {
  max_actions_per_window: 100,
  window_ms: 60000,
  cooldown_ms: 1000,
  max_pending_approvals: 50,
  circuit_breaker_threshold: 500,
  circuit_breaker_cooldown_ms: 300000,
};

let rateCapState: RateCapState = {
  actions: [],
  circuit_breaker_tripped: false,
  pending_approvals: 0,
};

export function loadRateCapConfig(): RateCapConfig {
  return {
    max_actions_per_window: Number(process.env.PHASEONE_GATEKEEPER_MAX_ACTIONS ?? DEFAULT_RATE_CAP.max_actions_per_window),
    window_ms: Number(process.env.PHASEONE_GATEKEEPER_WINDOW_MS ?? DEFAULT_RATE_CAP.window_ms),
    cooldown_ms: Number(process.env.PHASEONE_GATEKEEPER_COOLDOWN_MS ?? DEFAULT_RATE_CAP.cooldown_ms),
    max_pending_approvals: Number(process.env.PHASEONE_GATEKEEPER_MAX_PENDING ?? DEFAULT_RATE_CAP.max_pending_approvals),
    circuit_breaker_threshold: Number(process.env.PHASEONE_GATEKEEPER_CB_THRESHOLD ?? DEFAULT_RATE_CAP.circuit_breaker_threshold),
    circuit_breaker_cooldown_ms: Number(process.env.PHASEONE_GATEKEEPER_CB_COOLDOWN_MS ?? DEFAULT_RATE_CAP.circuit_breaker_cooldown_ms),
  };
}

export function checkRateCap(
  action: string,
  agentId?: string,
  cfg = loadRateCapConfig()
): { allowed: boolean; reason?: string; retry_after_ms?: number } {
  const now = Date.now();

  // Circuit breaker check
  if (rateCapState.circuit_breaker_tripped) {
    if (rateCapState.circuit_breaker_until && now < rateCapState.circuit_breaker_until) {
      return {
        allowed: false,
        reason: 'Circuit breaker tripped - too many actions',
        retry_after_ms: rateCapState.circuit_breaker_until - now,
      };
    }
    rateCapState.circuit_breaker_tripped = false;
    rateCapState.circuit_breaker_until = undefined;
  }

  // Cleanup old actions outside window
  const windowStart = now - cfg.window_ms;
  rateCapState.actions = rateCapState.actions.filter(a => a.timestamp > windowStart);

  // Check window rate limit
  if (rateCapState.actions.length >= cfg.max_actions_per_window) {
    return {
      allowed: false,
      reason: `Rate limit exceeded: ${cfg.max_actions_per_window} actions per ${cfg.window_ms}ms window`,
      retry_after_ms: rateCapState.actions[0].timestamp + cfg.window_ms - now,
    };
  }

  // Check cooldown for same action
  const lastSame = rateCapState.actions
    .filter(a => a.action === action && (!agentId || a.agent_id === agentId))
    .sort((a, b) => b.timestamp - a.timestamp)[0];
  
  if (lastSame && now - lastSame.timestamp < cfg.cooldown_ms) {
    return {
      allowed: false,
      reason: `Cooldown active for action: ${action}`,
      retry_after_ms: lastSame.timestamp + cfg.cooldown_ms - now,
    };
  }

  // Check pending approvals
  if (action === 'require_approval' && rateCapState.pending_approvals >= cfg.max_pending_approvals) {
    return {
      allowed: false,
      reason: `Too many pending approvals: ${rateCapState.pending_approvals}/${cfg.max_pending_approvals}`,
    };
  }

  // Check circuit breaker threshold
  if (rateCapState.actions.length >= cfg.circuit_breaker_threshold) {
    rateCapState.circuit_breaker_tripped = true;
    rateCapState.circuit_breaker_until = now + cfg.circuit_breaker_cooldown_ms;
    return {
      allowed: false,
      reason: 'Circuit breaker triggered',
      retry_after_ms: cfg.circuit_breaker_cooldown_ms,
    };
  }

  return { allowed: true };
}

export function recordAction(action: string, agentId?: string): void {
  rateCapState.actions.push({
    timestamp: Date.now(),
    action,
    agent_id: agentId,
  });
  
  if (action === 'require_approval') {
    rateCapState.pending_approvals++;
  }
}

export function releaseApproval(): void {
  if (rateCapState.pending_approvals > 0) {
    rateCapState.pending_approvals--;
  }
}

export function getRateCapStatus(cfg = loadRateCapConfig()): {
  config: RateCapConfig;
  state: {
    actions_in_window: number;
    circuit_breaker_tripped: boolean;
    pending_approvals: number;
    circuit_breaker_resets_in_ms?: number;
  };
} {
  const now = Date.now();
  const windowStart = now - cfg.window_ms;
  const actionsInWindow = rateCapState.actions.filter(a => a.timestamp > windowStart).length;

  return {
    config: cfg,
    state: {
      actions_in_window: actionsInWindow,
      circuit_breaker_tripped: rateCapState.circuit_breaker_tripped,
      pending_approvals: rateCapState.pending_approvals,
      circuit_breaker_resets_in_ms: rateCapState.circuit_breaker_until
        ? Math.max(0, rateCapState.circuit_breaker_until - now)
        : undefined,
    },
  };
}

export function resetRateCapState(): void {
  rateCapState = {
    actions: [],
    circuit_breaker_tripped: false,
    pending_approvals: 0,
  };
}

function eventToContext(event: SimulationEvent): PolicyCheckContext {
  const args = event.tool_args ?? {};
  const argsObj = typeof args === 'object' && args !== null ? args as Record<string, unknown> : {};
  
  return {
    agentId: event.agent_id ?? 'simulation-agent',
    sessionId: event.session_id ?? 'simulation-session',
    toolName: event.tool_name,
    toolArgs: args,
    domain: event.destination ?? (typeof argsObj.url === 'string' ? argsObj.url : undefined),
    url: event.url ?? (typeof argsObj.url === 'string' ? argsObj.url : undefined),
    method: event.method ?? (typeof argsObj.method === 'string' ? argsObj.method : undefined),
    path: event.path ?? (typeof argsObj.path === 'string' ? argsObj.path : undefined),
    shellCommand: event.shell_command ?? (typeof argsObj.command === 'string' ? argsObj.command : undefined),
    mcpServer: event.mcp_server ?? (typeof argsObj.server === 'string' ? argsObj.server : undefined),
    mcpTool: event.mcp_tool ?? (typeof argsObj.tool === 'string' ? argsObj.tool : undefined),
    actionHint: event.event_type,
  };
}

function extractDomain(event: SimulationEvent): string | null {
  const url = event.destination ?? event.url;
  if (!url) return null;
  try {
    if (url.includes('://')) {
      return new URL(url).hostname;
    }
    return url.split('/')[0].split(':')[0];
  } catch {
    return null;
  }
}

export function simulateEvents(
  events: SimulationEvent[],
  config: SimulationConfig = {}
): SimulationOutput {
  const startTime = Date.now();
  const results: SimulationResult[] = [];
  const policy = config.policy_override ? { ...getPolicy(), ...config.policy_override } : getPolicy();

  let processedEvents = events;

  // Apply filters
  if (config.event_types?.length) {
    processedEvents = processedEvents.filter(e => 
      e.event_type && config.event_types!.includes(e.event_type)
    );
  }
  if (config.agent_ids?.length) {
    processedEvents = processedEvents.filter(e => 
      e.agent_id && config.agent_ids!.includes(e.agent_id)
    );
  }
  if (config.tool_names?.length) {
    processedEvents = processedEvents.filter(e => 
      e.tool_name && config.tool_names!.includes(e.tool_name)
    );
  }
  if (config.from_time) {
    const from = typeof config.from_time === 'number' 
      ? config.from_time 
      : new Date(config.from_time).getTime();
    processedEvents = processedEvents.filter(e => {
      if (!e.timestamp) return true;
      const ts = typeof e.timestamp === 'number' ? e.timestamp : new Date(e.timestamp).getTime();
      return ts >= from;
    });
  }
  if (config.to_time) {
    const to = typeof config.to_time === 'number' 
      ? config.to_time 
      : new Date(config.to_time).getTime();
    processedEvents = processedEvents.filter(e => {
      if (!e.timestamp) return true;
      const ts = typeof e.timestamp === 'number' ? e.timestamp : new Date(e.timestamp).getTime();
      return ts <= to;
    });
  }
  if (config.max_events && processedEvents.length > config.max_events) {
    processedEvents = processedEvents.slice(0, config.max_events);
  }

  // Simulate each event
  for (const event of processedEvents) {
    let decision: PolicyDecision;
    
    if (event.tool_name) {
      decision = evaluateToolCall(
        event.agent_id ?? 'simulation-agent',
        event.session_id ?? 'simulation-session',
        event.tool_name,
        event.tool_args
      );
    } else {
      const ctx = eventToContext(event);
      decision = evaluatePolicy(ctx, policy as never);
    }

    results.push({
      event,
      decision,
      would_block: decision.action === 'deny',
      would_require_approval: decision.action === 'require_approval',
      matched_rules: [decision.ruleId ?? 'unknown'].filter(Boolean),
    });
  }

  // Calculate blast radius
  const blastRadius = calculateBlastRadius(results);
  
  return {
    ok: true,
    config,
    results,
    blast_radius: blastRadius,
    simulation_time_ms: Date.now() - startTime,
    dry_run: true,
  };
}

export function calculateBlastRadius(results: SimulationResult[]): BlastRadiusSummary {
  const agents = new Set<string>();
  const tools = new Set<string>();
  const domains = new Set<string>();
  const ruleHits: Record<string, number> = {};
  let blockedCount = 0;
  let approvalCount = 0;
  let allowedCount = 0;
  let canaryMatches = 0;
  let secretMatches = 0;

  for (const result of results) {
    const event = result.event;
    const decision = result.decision;

    if (event.agent_id) agents.add(event.agent_id);
    if (event.tool_name) tools.add(event.tool_name);
    
    const domain = extractDomain(event);
    if (domain) domains.add(domain);

    if (decision.action === 'deny') blockedCount++;
    else if (decision.action === 'require_approval') approvalCount++;
    else allowedCount++;

    if (decision.ruleId) {
      ruleHits[decision.ruleId] = (ruleHits[decision.ruleId] ?? 0) + 1;
    }

    if (decision.matchedCanaries?.length) {
      canaryMatches += decision.matchedCanaries.length;
    }
    if (decision.matchedSecrets?.length) {
      secretMatches += decision.matchedSecrets.length;
    }
  }

  return {
    total_events: results.length,
    blocked_count: blockedCount,
    approval_required_count: approvalCount,
    allowed_count: allowedCount,
    affected_agents: Array.from(agents),
    affected_tools: Array.from(tools),
    affected_domains: Array.from(domains),
    rule_hits: ruleHits,
    canary_matches: canaryMatches,
    secret_matches: secretMatches,
  };
}

export function simulateWithHistoricalEvents(
  fetchEvents: () => Promise<SimulationEvent[]>,
  config: SimulationConfig = {}
): Promise<SimulationOutput> {
  return fetchEvents().then(events => simulateEvents(events, config));
}

export function __testResetGatekeeperState(): void {
  resetRateCapState();
}
