/**
 * Gatekeeper simulation and rate-cap tests.
 * DEFENSIVE ONLY.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  simulateEvents,
  calculateBlastRadius,
  loadRateCapConfig,
  checkRateCap,
  recordAction,
  releaseApproval,
  getRateCapStatus,
  resetRateCapState,
  type SimulationEvent,
  type SimulationResult,
} from '../shared/src/gatekeeper.js';

describe('Gatekeeper Simulation', () => {
  it('simulates empty event list', () => {
    const result = simulateEvents([]);
    expect(result.ok).toBe(true);
    expect(result.results).toHaveLength(0);
    expect(result.blast_radius.total_events).toBe(0);
    expect(result.dry_run).toBe(true);
  });

  it('simulates tool call events', () => {
    const events: SimulationEvent[] = [
      {
        id: '1',
        session_id: 'sess-1',
        agent_id: 'agent-1',
        event_type: 'tool.call',
        tool_name: 'http_request',
        tool_args: { url: 'https://api.example.com/data' },
      },
      {
        id: '2',
        session_id: 'sess-1',
        agent_id: 'agent-1',
        event_type: 'tool.call',
        tool_name: 'run_shell',
        tool_args: { command: 'echo hello' },
      },
    ];

    const result = simulateEvents(events);
    expect(result.ok).toBe(true);
    expect(result.results).toHaveLength(2);
    expect(result.blast_radius.total_events).toBe(2);
    expect(result.blast_radius.affected_agents).toContain('agent-1');
    expect(result.blast_radius.affected_tools).toContain('http_request');
    expect(result.blast_radius.affected_tools).toContain('run_shell');
  });

  it('identifies blocked events', () => {
    const events: SimulationEvent[] = [
      {
        id: '1',
        agent_id: 'agent-1',
        tool_name: 'run_shell',
        tool_args: { command: 'rm -rf /' }, // Dangerous command
      },
    ];

    const result = simulateEvents(events);
    expect(result.results[0].would_block).toBe(true);
    expect(result.blast_radius.blocked_count).toBeGreaterThanOrEqual(1);
  });

  it('applies event type filter', () => {
    const events: SimulationEvent[] = [
      { id: '1', event_type: 'tool.call', tool_name: 'read_file' },
      { id: '2', event_type: 'shell.exec', shell_command: 'ls' },
      { id: '3', event_type: 'tool.call', tool_name: 'write_file' },
    ];

    const result = simulateEvents(events, { event_types: ['tool.call'] });
    expect(result.results).toHaveLength(2);
  });

  it('applies agent ID filter', () => {
    const events: SimulationEvent[] = [
      { id: '1', agent_id: 'agent-1', tool_name: 'read_file' },
      { id: '2', agent_id: 'agent-2', tool_name: 'read_file' },
      { id: '3', agent_id: 'agent-1', tool_name: 'write_file' },
    ];

    const result = simulateEvents(events, { agent_ids: ['agent-1'] });
    expect(result.results).toHaveLength(2);
    expect(result.blast_radius.affected_agents).toEqual(['agent-1']);
  });

  it('applies max events limit', () => {
    const events: SimulationEvent[] = Array.from({ length: 100 }, (_, i) => ({
      id: String(i),
      tool_name: 'read_file',
    }));

    const result = simulateEvents(events, { max_events: 10 });
    expect(result.results).toHaveLength(10);
  });

  it('calculates simulation time', () => {
    const events: SimulationEvent[] = [
      { id: '1', tool_name: 'read_file' },
      { id: '2', tool_name: 'write_file' },
    ];

    const result = simulateEvents(events);
    expect(result.simulation_time_ms).toBeGreaterThanOrEqual(0);
  });
});

describe('Blast Radius Calculation', () => {
  it('calculates empty results', () => {
    const br = calculateBlastRadius([]);
    expect(br.total_events).toBe(0);
    expect(br.blocked_count).toBe(0);
    expect(br.affected_agents).toHaveLength(0);
  });

  it('counts blocked and allowed events', () => {
    const results: SimulationResult[] = [
      {
        event: { id: '1' },
        decision: { action: 'deny', reason: 'test', ruleId: 'test.rule' },
        would_block: true,
        would_require_approval: false,
        matched_rules: ['test.rule'],
      },
      {
        event: { id: '2' },
        decision: { action: 'allow', reason: 'ok', ruleId: 'default.allow' },
        would_block: false,
        would_require_approval: false,
        matched_rules: ['default.allow'],
      },
      {
        event: { id: '3' },
        decision: { action: 'require_approval', reason: 'destructive', ruleId: 'destructive.approval' },
        would_block: false,
        would_require_approval: true,
        matched_rules: ['destructive.approval'],
      },
    ];

    const br = calculateBlastRadius(results);
    expect(br.total_events).toBe(3);
    expect(br.blocked_count).toBe(1);
    expect(br.approval_required_count).toBe(1);
    expect(br.allowed_count).toBe(1);
  });

  it('tracks rule hit counts', () => {
    const results: SimulationResult[] = [
      {
        event: {},
        decision: { action: 'deny', reason: 'test', ruleId: 'rule.a' },
        would_block: true,
        would_require_approval: false,
        matched_rules: ['rule.a'],
      },
      {
        event: {},
        decision: { action: 'deny', reason: 'test', ruleId: 'rule.a' },
        would_block: true,
        would_require_approval: false,
        matched_rules: ['rule.a'],
      },
      {
        event: {},
        decision: { action: 'deny', reason: 'test', ruleId: 'rule.b' },
        would_block: true,
        would_require_approval: false,
        matched_rules: ['rule.b'],
      },
    ];

    const br = calculateBlastRadius(results);
    expect(br.rule_hits['rule.a']).toBe(2);
    expect(br.rule_hits['rule.b']).toBe(1);
  });

  it('counts canary and secret matches', () => {
    const results: SimulationResult[] = [
      {
        event: {},
        decision: {
          action: 'deny',
          reason: 'canary',
          ruleId: 'canary.block',
          matchedCanaries: ['canary1', 'canary2'],
        },
        would_block: true,
        would_require_approval: false,
        matched_rules: ['canary.block'],
      },
      {
        event: {},
        decision: {
          action: 'deny',
          reason: 'secret',
          ruleId: 'secret.egress',
          matchedSecrets: ['aws_key'],
        },
        would_block: true,
        would_require_approval: false,
        matched_rules: ['secret.egress'],
      },
    ];

    const br = calculateBlastRadius(results);
    expect(br.canary_matches).toBe(2);
    expect(br.secret_matches).toBe(1);
  });

  it('extracts unique domains', () => {
    const results: SimulationResult[] = [
      {
        event: { destination: 'https://api.example.com/v1' },
        decision: { action: 'allow', reason: 'ok' },
        would_block: false,
        would_require_approval: false,
        matched_rules: [],
      },
      {
        event: { url: 'https://api.example.com/v2' },
        decision: { action: 'allow', reason: 'ok' },
        would_block: false,
        would_require_approval: false,
        matched_rules: [],
      },
      {
        event: { destination: 'https://other.com/api' },
        decision: { action: 'allow', reason: 'ok' },
        would_block: false,
        would_require_approval: false,
        matched_rules: [],
      },
    ];

    const br = calculateBlastRadius(results);
    expect(br.affected_domains).toContain('api.example.com');
    expect(br.affected_domains).toContain('other.com');
    expect(br.affected_domains).toHaveLength(2);
  });
});

describe('Rate Cap', () => {
  beforeEach(() => {
    resetRateCapState();
  });

  afterEach(() => {
    resetRateCapState();
  });

  it('loads rate cap config from environment', () => {
    const cfg = loadRateCapConfig();
    expect(cfg.max_actions_per_window).toBeGreaterThan(0);
    expect(cfg.window_ms).toBeGreaterThan(0);
    expect(cfg.cooldown_ms).toBeGreaterThan(0);
  });

  it('allows actions within limits', () => {
    const result = checkRateCap('test_action', 'agent-1');
    expect(result.allowed).toBe(true);
  });

  it('enforces cooldown between same actions', () => {
    const cfg = loadRateCapConfig();
    
    // Record first action
    recordAction('test_action', 'agent-1');
    
    // Immediate second action should be rate limited
    const result = checkRateCap('test_action', 'agent-1', { ...cfg, cooldown_ms: 10000 });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Cooldown');
    expect(result.retry_after_ms).toBeGreaterThan(0);
  });

  it('allows different actions during cooldown', () => {
    recordAction('action_a', 'agent-1');
    
    const result = checkRateCap('action_b', 'agent-1');
    expect(result.allowed).toBe(true);
  });

  it('enforces window rate limit', () => {
    const cfg = { ...loadRateCapConfig(), max_actions_per_window: 3, window_ms: 60000 };
    
    recordAction('action_1');
    recordAction('action_2');
    recordAction('action_3');
    
    const result = checkRateCap('action_4', undefined, cfg);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Rate limit');
  });

  it('tracks pending approvals', () => {
    recordAction('require_approval');
    recordAction('require_approval');
    
    const status = getRateCapStatus();
    expect(status.state.pending_approvals).toBe(2);
    
    releaseApproval();
    const status2 = getRateCapStatus();
    expect(status2.state.pending_approvals).toBe(1);
  });

  it('enforces max pending approvals', () => {
    const cfg = { ...loadRateCapConfig(), max_pending_approvals: 2, cooldown_ms: 0 };
    
    recordAction('require_approval');
    recordAction('require_approval');
    
    const result = checkRateCap('require_approval', undefined, cfg);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('pending approvals');
  });

  it('triggers circuit breaker at threshold', () => {
    const cfg = {
      ...loadRateCapConfig(),
      circuit_breaker_threshold: 5,
      circuit_breaker_cooldown_ms: 10000,
    };
    
    // Fill up to threshold
    for (let i = 0; i < 5; i++) {
      recordAction(`action_${i}`);
    }
    
    const result = checkRateCap('action_next', undefined, cfg);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Circuit breaker');
    
    const status = getRateCapStatus();
    expect(status.state.circuit_breaker_tripped).toBe(true);
  });

  it('resets state correctly', () => {
    recordAction('test');
    recordAction('require_approval');
    
    resetRateCapState();
    
    const status = getRateCapStatus();
    expect(status.state.actions_in_window).toBe(0);
    expect(status.state.pending_approvals).toBe(0);
    expect(status.state.circuit_breaker_tripped).toBe(false);
  });

  it('returns status with config and state', () => {
    const status = getRateCapStatus();
    
    expect(status).toHaveProperty('config');
    expect(status).toHaveProperty('state');
    expect(status.config).toHaveProperty('max_actions_per_window');
    expect(status.state).toHaveProperty('actions_in_window');
    expect(status.state).toHaveProperty('circuit_breaker_tripped');
    expect(status.state).toHaveProperty('pending_approvals');
  });
});
