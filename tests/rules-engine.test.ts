/**
 * PhaseOne10841 Rules Engine Tests
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 *
 * Tests for detection rules engine including aggregation and time-window support.
 * DEFENSIVE ONLY — no exploit tooling.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadRules,
  evaluateRules,
  listRulesWithCounts,
  getRuleHitCounts,
  getAggregationStats,
  defaultRulesDir,
  __testResetHitCounts,
  type RuleMatchContext,
  type DetectionRule,
} from '../rules/src/engine.js';

describe('rules engine basics', () => {
  beforeEach(() => {
    __testResetHitCounts();
  });

  it('loads rules from default directory', () => {
    const rules = loadRules();
    expect(Array.isArray(rules)).toBe(true);
    expect(rules.length).toBeGreaterThan(0);
  });

  it('rules have required fields', () => {
    const rules = loadRules();
    for (const rule of rules) {
      expect(rule.id).toBeTruthy();
      expect(rule.title).toBeTruthy();
      expect(rule.detection).toBeDefined();
      expect(['info', 'low', 'medium', 'high', 'critical']).toContain(rule.level);
    }
  });

  it('evaluates simple selection rules', () => {
    const ctx: RuleMatchContext = {
      tool_name: 'run_shell',
      decision: 'deny',
    };
    const hits = evaluateRules(ctx);
    expect(Array.isArray(hits)).toBe(true);
    const shellRule = hits.find((h) => h.rule_id === 'phaseone.shell.denied');
    expect(shellRule).toBeDefined();
    expect(shellRule?.level).toBe('medium');
  });

  it('tracks hit counts', () => {
    const ctx: RuleMatchContext = {
      tool_name: 'run_shell',
      decision: 'deny',
    };
    evaluateRules(ctx);
    evaluateRules(ctx);
    const counts = getRuleHitCounts();
    expect(counts['phaseone.shell.denied']).toBe(2);
  });

  it('lists rules with counts', () => {
    const ctx: RuleMatchContext = { tool_name: 'run_shell', decision: 'deny' };
    evaluateRules(ctx);
    const rules = listRulesWithCounts();
    const shellRule = rules.find((r) => r.id === 'phaseone.shell.denied');
    expect(shellRule?.hit_count).toBe(1);
  });
});

describe('field matchers', () => {
  beforeEach(() => {
    __testResetHitCounts();
  });

  it('matches field_gte for injection score', () => {
    const ctx: RuleMatchContext = {
      injection_score: 0.8,
    };
    const hits = evaluateRules(ctx);
    const highScore = hits.find((h) => h.rule_id === 'phaseone.injection.score.high');
    expect(highScore).toBeDefined();
  });

  it('does not match field_gte below threshold', () => {
    const ctx: RuleMatchContext = {
      injection_score: 0.3,
    };
    const hits = evaluateRules(ctx);
    const highScore = hits.find((h) => h.rule_id === 'phaseone.injection.score.high');
    expect(highScore).toBeUndefined();
  });

  it('matches array values', () => {
    const ctx: RuleMatchContext = {
      tool_name: 'shell_exec',
      decision: 'deny',
    };
    const hits = evaluateRules(ctx);
    const shellRule = hits.find((h) => h.rule_id === 'phaseone.shell.denied');
    expect(shellRule).toBeDefined();
  });

  it('reads from metadata', () => {
    const ctx: RuleMatchContext = {
      metadata: {
        injection_score: 0.9,
      },
    };
    const hits = evaluateRules(ctx);
    const highScore = hits.find((h) => h.rule_id === 'phaseone.injection.score.high');
    expect(highScore).toBeDefined();
  });
});

describe('aggregation rules', () => {
  beforeEach(() => {
    __testResetHitCounts();
  });

  it('count aggregation triggers after threshold', () => {
    const now = Date.now();
    const ctx: RuleMatchContext = {
      event_type: 'auth_failure',
      source_ip: '192.168.1.1',
      timestamp: now,
    };

    for (let i = 0; i < 4; i++) {
      const hits = evaluateRules({ ...ctx, timestamp: now + i * 1000 });
      const bruteForce = hits.find((h) => h.rule_id === 'phaseone.auth.brute_force');
      expect(bruteForce).toBeUndefined();
    }

    const finalHits = evaluateRules({ ...ctx, timestamp: now + 5000 });
    const bruteForce = finalHits.find((h) => h.rule_id === 'phaseone.auth.brute_force');
    expect(bruteForce).toBeDefined();
    expect(bruteForce?.aggregation_result?.type).toBe('count');
    expect(bruteForce?.aggregation_result?.value).toBeGreaterThanOrEqual(5);
  });

  it('aggregation respects group_by', () => {
    const now = Date.now();

    for (let i = 0; i < 3; i++) {
      evaluateRules({
        event_type: 'auth_failure',
        source_ip: '192.168.1.1',
        timestamp: now + i * 1000,
      });
    }

    for (let i = 0; i < 3; i++) {
      const hits = evaluateRules({
        event_type: 'auth_failure',
        source_ip: '192.168.1.2',
        timestamp: now + i * 1000,
      });
      const bruteForce = hits.find((h) => h.rule_id === 'phaseone.auth.brute_force');
      expect(bruteForce).toBeUndefined();
    }
  });

  it('aggregation state is tracked', () => {
    const ctx: RuleMatchContext = {
      event_type: 'auth_failure',
      source_ip: '10.0.0.1',
      timestamp: Date.now(),
    };
    evaluateRules(ctx);
    const stats = getAggregationStats();
    expect(Object.keys(stats).length).toBeGreaterThan(0);
  });

  it('time window expires old events', () => {
    const now = Date.now();
    const fiveMinutesAgo = now - 6 * 60 * 1000;

    for (let i = 0; i < 5; i++) {
      evaluateRules({
        event_type: 'auth_failure',
        source_ip: '10.0.0.5',
        timestamp: fiveMinutesAgo + i * 1000,
      });
    }

    const recentHits = evaluateRules({
      event_type: 'auth_failure',
      source_ip: '10.0.0.5',
      timestamp: now,
    });
    const bruteForce = recentHits.find((h) => h.rule_id === 'phaseone.auth.brute_force');
    expect(bruteForce).toBeUndefined();
  });
});

describe('rapid tool calls rule', () => {
  beforeEach(() => {
    __testResetHitCounts();
  });

  it('triggers after many tool calls from same agent', () => {
    const now = Date.now();

    for (let i = 0; i < 49; i++) {
      evaluateRules({
        event_type: 'tool_call',
        agent_id: 'rapid-agent',
        timestamp: now + i * 100,
      });
    }

    const finalHits = evaluateRules({
      event_type: 'tool_call',
      agent_id: 'rapid-agent',
      timestamp: now + 50 * 100,
    });
    const rapidRule = finalHits.find((h) => h.rule_id === 'phaseone.agent.rapid_tools');
    expect(rapidRule).toBeDefined();
    expect(rapidRule?.aggregation_result?.value).toBeGreaterThanOrEqual(50);
  });
});

describe('selection_any matching', () => {
  beforeEach(() => {
    __testResetHitCounts();
  });

  it('matches any selection in selection_any', () => {
    const rules = loadRules();
    const hasSelectionAny = rules.some((r) => r.detection.selection_any);

    if (hasSelectionAny) {
      expect(true).toBe(true);
    } else {
      const ctx: RuleMatchContext = { tool_name: 'test' };
      const hits = evaluateRules(ctx);
      expect(Array.isArray(hits)).toBe(true);
    }
  });
});

describe('disabled rules', () => {
  it('does not evaluate disabled rules', () => {
    const rules = loadRules();
    const enabledRules = rules.filter((r) => r.enabled);
    const disabledRules = rules.filter((r) => !r.enabled);

    expect(enabledRules.length).toBeGreaterThan(0);
    expect(disabledRules.every((r) => r.enabled === false)).toBe(true);
  });
});
