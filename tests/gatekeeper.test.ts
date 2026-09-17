/**
 * PhaseOne10841 Gatekeeper Tests — Phase 7
 * DEFENSIVE ONLY — no exploit tooling.
 * 
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  loadPlaybooks,
  validatePlaybook,
  resetPlaybooksCache,
  listPlaybooksDetailed,
} from '../gatekeeper/src/playbooks.js';
import {
  matchPlaybook,
  matchAllPlaybooks,
  recordPlaybookExecution,
  __testResetMatcher,
} from '../gatekeeper/src/matcher.js';
import {
  executeAction,
  getRuntimeOverride,
  listRuntimeOverrides,
  getDashboardNotifications,
  __testResetActions,
} from '../gatekeeper/src/actions.js';
import {
  getGatekeeperStatus,
  processEvent,
  runGatekeeperCycle,
  queueEvent,
  setGatekeeperEnabled,
  setGatekeeperDryRun,
  __testResetWorker,
} from '../gatekeeper/src/worker.js';
import type { Playbook, GatekeeperEvent, PlaybookAction } from '../gatekeeper/src/types.js';
import { __testResetAudit, __testPeekAudit } from '../shared/src/audit.js';

describe('Gatekeeper Playbook Validation', () => {
  it('validates a correct observe playbook', () => {
    const playbook = {
      id: 'test-observe',
      name: 'Test Observe',
      tier: 'observe',
      match: { event_type: 'canary.trigger' },
      actions: [{ type: 'emit_alert' }],
    };
    
    const result = validatePlaybook(playbook);
    expect(result.ok).toBe(true);
    expect(result.playbook?.id).toBe('test-observe');
    expect(result.playbook?.tier).toBe('observe');
  });

  it('validates a correct contain playbook', () => {
    const playbook = {
      id: 'test-contain',
      name: 'Test Contain',
      tier: 'contain',
      match: { rule_id: 'brute-force' },
      actions: [
        { type: 'emit_alert' },
        { type: 'tighten_rate_limit', params: { factor: 0.5 } },
      ],
    };
    
    const result = validatePlaybook(playbook);
    expect(result.ok).toBe(true);
    expect(result.playbook?.actions).toHaveLength(2);
  });

  it('validates a harden playbook with confirmation warning', () => {
    const playbook = {
      id: 'test-harden',
      name: 'Test Harden',
      tier: 'harden',
      match: { severity: 'critical' },
      actions: [{ type: 'rotate_canary' }],
    };
    
    const result = validatePlaybook(playbook);
    expect(result.ok).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain('confirmation');
  });

  it('rejects playbook missing id', () => {
    const playbook = {
      name: 'No ID',
      tier: 'observe',
      match: { event_type: 'test' },
      actions: [{ type: 'emit_alert' }],
    };
    
    const result = validatePlaybook(playbook);
    expect(result.ok).toBe(false);
    expect(result.errors.some(e => e.includes('id'))).toBe(true);
  });

  it('rejects observe playbook with contain action', () => {
    const playbook = {
      id: 'bad-observe',
      name: 'Bad Observe',
      tier: 'observe',
      match: { event_type: 'test' },
      actions: [{ type: 'tighten_rate_limit' }],
    };
    
    const result = validatePlaybook(playbook);
    expect(result.ok).toBe(false);
    expect(result.errors.some(e => e.includes('not allowed in tier'))).toBe(true);
  });

  it('rejects unknown action type', () => {
    const playbook = {
      id: 'bad-action',
      name: 'Bad Action',
      tier: 'observe',
      match: { event_type: 'test' },
      actions: [{ type: 'shell_exec' }],
    };
    
    const result = validatePlaybook(playbook);
    expect(result.ok).toBe(false);
    expect(result.errors.some(e => e.includes('unknown action type'))).toBe(true);
  });

  it('rejects playbook without match conditions', () => {
    const playbook = {
      id: 'no-match',
      name: 'No Match',
      tier: 'observe',
      match: {},
      actions: [{ type: 'emit_alert' }],
    };
    
    const result = validatePlaybook(playbook);
    expect(result.ok).toBe(false);
    expect(result.errors.some(e => e.includes('at least one condition'))).toBe(true);
  });
});

describe('Gatekeeper Playbook Matching', () => {
  let testPlaybook: Playbook;

  beforeEach(() => {
    __testResetMatcher();
    testPlaybook = {
      id: 'test-playbook',
      name: 'Test Playbook',
      enabled: true,
      tier: 'observe',
      match: {
        event_type: 'canary.trigger',
        severity: 'high',
      },
      actions: [{ type: 'emit_alert' }],
      cooldown_ms: 1000,
      max_executions_per_window: 5,
    };
  });

  afterEach(() => {
    __testResetMatcher();
  });

  it('matches event that meets all conditions', () => {
    const event: GatekeeperEvent = {
      id: 'evt-1',
      event_type: 'canary.trigger',
      severity: 'high',
      timestamp: Date.now(),
    };
    
    const result = matchPlaybook(testPlaybook, event);
    expect(result.matched).toBe(true);
  });

  it('does not match disabled playbook', () => {
    testPlaybook.enabled = false;
    const event: GatekeeperEvent = {
      id: 'evt-2',
      event_type: 'canary.trigger',
      severity: 'high',
      timestamp: Date.now(),
    };
    
    const result = matchPlaybook(testPlaybook, event);
    expect(result.matched).toBe(false);
    expect(result.reason).toContain('disabled');
  });

  it('does not match wrong event type', () => {
    const event: GatekeeperEvent = {
      id: 'evt-3',
      event_type: 'a2a.blocked',
      severity: 'high',
      timestamp: Date.now(),
    };
    
    const result = matchPlaybook(testPlaybook, event);
    expect(result.matched).toBe(false);
  });

  it('matches severity >= threshold', () => {
    const playbookWithThreshold: Playbook = {
      ...testPlaybook,
      match: {
        event_type: 'test',
        severity: '>=medium',
      },
    };
    
    const highEvent: GatekeeperEvent = {
      id: 'evt-4',
      event_type: 'test',
      severity: 'high',
      timestamp: Date.now(),
    };
    
    const lowEvent: GatekeeperEvent = {
      id: 'evt-5',
      event_type: 'test',
      severity: 'low',
      timestamp: Date.now(),
    };
    
    expect(matchPlaybook(playbookWithThreshold, highEvent).matched).toBe(true);
    expect(matchPlaybook(playbookWithThreshold, lowEvent).matched).toBe(false);
  });

  it('respects cooldown period', () => {
    const event: GatekeeperEvent = {
      id: 'evt-6',
      event_type: 'canary.trigger',
      severity: 'high',
      timestamp: Date.now(),
    };
    
    const result1 = matchPlaybook(testPlaybook, event);
    expect(result1.matched).toBe(true);
    recordPlaybookExecution(testPlaybook.id);
    
    const result2 = matchPlaybook(testPlaybook, event);
    expect(result2.matched).toBe(false);
    expect(result2.reason).toContain('cooldown');
  });

  it('matches with count threshold', () => {
    const countPlaybook: Playbook = {
      ...testPlaybook,
      match: {
        event_type: 'test',
        count: 3,
        window_ms: 60000,
      },
    };
    
    const now = Date.now();
    
    for (let i = 0; i < 2; i++) {
      const event: GatekeeperEvent = {
        id: `evt-count-${i}`,
        event_type: 'test',
        timestamp: now + i * 100,
      };
      const result = matchPlaybook(countPlaybook, event, now + i * 100);
      expect(result.matched).toBe(false);
      expect(result.eventsInWindow).toBe(i + 1);
    }
    
    const finalEvent: GatekeeperEvent = {
      id: 'evt-count-final',
      event_type: 'test',
      timestamp: now + 300,
    };
    const finalResult = matchPlaybook(countPlaybook, finalEvent, now + 300);
    expect(finalResult.matched).toBe(true);
    expect(finalResult.eventsInWindow).toBe(3);
  });

  it('matches multiple playbooks', () => {
    const playbook2: Playbook = {
      id: 'test-playbook-2',
      name: 'Test Playbook 2',
      enabled: true,
      tier: 'observe',
      match: { severity: 'high' },
      actions: [{ type: 'write_audit' }],
    };
    
    const event: GatekeeperEvent = {
      id: 'evt-multi',
      event_type: 'canary.trigger',
      severity: 'high',
      timestamp: Date.now(),
    };
    
    const matches = matchAllPlaybooks([testPlaybook, playbook2], event);
    expect(matches).toHaveLength(2);
  });
});

describe('Gatekeeper Action Execution', () => {
  beforeEach(() => {
    __testResetActions();
    __testResetAudit();
  });

  afterEach(() => {
    __testResetActions();
    __testResetAudit();
  });

  it('executes emit_alert in dry-run mode', async () => {
    const action: PlaybookAction = { type: 'emit_alert', params: { message: 'Test alert' } };
    const event: GatekeeperEvent = {
      id: 'evt-alert',
      event_type: 'test',
      timestamp: Date.now(),
    };
    
    const result = await executeAction(action, event, true);
    expect(result.ok).toBe(true);
    expect(result.dry_run).toBe(true);
    expect(result.detail).toContain('Would send alert');
  });

  it('executes write_audit and records audit entry', async () => {
    const action: PlaybookAction = { type: 'write_audit', params: { action: 'test.action' } };
    const event: GatekeeperEvent = {
      id: 'evt-audit',
      event_type: 'test',
      timestamp: Date.now(),
    };
    
    const result = await executeAction(action, event, false);
    expect(result.ok).toBe(true);
    expect(result.dry_run).toBe(false);
    
    const auditEntries = __testPeekAudit();
    expect(auditEntries.some(e => e.actor_email === 'gatekeeper')).toBe(true);
  });

  it('executes dashboard_notify', async () => {
    const action: PlaybookAction = { type: 'dashboard_notify', params: { message: 'Test notify' } };
    const event: GatekeeperEvent = {
      id: 'evt-notify',
      event_type: 'test',
      timestamp: Date.now(),
    };
    
    const result = await executeAction(action, event, false);
    expect(result.ok).toBe(true);
    
    const notifications = getDashboardNotifications();
    expect(notifications.some(n => n.message === 'Test notify')).toBe(true);
  });

  it('executes tighten_rate_limit and creates override', async () => {
    const action: PlaybookAction = {
      type: 'tighten_rate_limit',
      params: { factor: 0.5, duration_ms: 300000 },
    };
    const event: GatekeeperEvent = {
      id: 'evt-rate',
      event_type: 'test',
      agent_id: 'test-agent',
      timestamp: Date.now(),
    };
    
    const result = await executeAction(action, event, false);
    expect(result.ok).toBe(true);
    
    const override = getRuntimeOverride('rate_limit:test-agent');
    expect(override).toBeTruthy();
    expect((override as { factor: number }).factor).toBe(0.5);
  });

  it('executes deny_tool and creates override', async () => {
    const action: PlaybookAction = {
      type: 'deny_tool',
      params: { tool: 'dangerous_tool', duration_ms: 600000 },
    };
    const event: GatekeeperEvent = {
      id: 'evt-deny-tool',
      event_type: 'test',
      timestamp: Date.now(),
    };
    
    const result = await executeAction(action, event, false);
    expect(result.ok).toBe(true);
    
    const override = getRuntimeOverride('deny_tool:dangerous_tool');
    expect(override).toBeTruthy();
    expect((override as { denied: boolean }).denied).toBe(true);
  });

  it('rotate_canary requires confirmation', async () => {
    const action: PlaybookAction = {
      type: 'rotate_canary',
      requires_confirmation: true,
      params: { canary_id: 'api-key' },
    };
    const event: GatekeeperEvent = {
      id: 'evt-canary',
      event_type: 'test',
      timestamp: Date.now(),
    };
    
    const result = await executeAction(action, event, false);
    expect(result.ok).toBe(false);
    expect(result.requires_confirmation).toBe(true);
  });

  it('lists runtime overrides', async () => {
    const action: PlaybookAction = {
      type: 'deny_domain',
      params: { domain: 'evil.com', duration_ms: 300000 },
    };
    const event: GatekeeperEvent = {
      id: 'evt-domain',
      event_type: 'test',
      timestamp: Date.now(),
    };
    
    await executeAction(action, event, false);
    
    const overrides = listRuntimeOverrides();
    expect(Object.keys(overrides)).toContain('deny_domain:evil.com');
  });
});

describe('Gatekeeper Worker', () => {
  let testDir: string;

  beforeEach(() => {
    __testResetWorker();
    __testResetAudit();
    
    testDir = join(tmpdir(), `phaseone-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
    
    const playbook = `
id: test-worker-playbook
name: Test Worker Playbook
tier: observe
match:
  event_type: test.event
actions:
  - type: dashboard_notify
    params:
      message: Worker test notification
`;
    writeFileSync(join(testDir, 'test-playbook.yaml'), playbook);
    resetPlaybooksCache();
  });

  afterEach(() => {
    __testResetWorker();
    __testResetAudit();
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('processes event through playbook', async () => {
    const event: GatekeeperEvent = {
      id: 'evt-worker',
      event_type: 'test.event',
      timestamp: Date.now(),
    };
    
    const executions = await processEvent(event, {
      dryRunOverride: false,
      playbooksDir: testDir,
    });
    
    expect(executions).toHaveLength(1);
    expect(executions[0].playbook_id).toBe('test-worker-playbook');
    expect(executions[0].actions).toHaveLength(1);
    expect(executions[0].actions[0].ok).toBe(true);
  });

  it('processes queued events in cycle', async () => {
    const event1: GatekeeperEvent = {
      id: 'evt-cycle-1',
      event_type: 'test.event',
      timestamp: Date.now(),
    };
    const event2: GatekeeperEvent = {
      id: 'evt-cycle-2',
      event_type: 'test.event',
      timestamp: Date.now() + 100,
    };
    
    queueEvent(event1);
    queueEvent(event2);
    
    const result = await runGatekeeperCycle({
      dryRunOverride: false,
      playbooksDir: testDir,
    });
    
    expect(result.processed).toBe(2);
    expect(result.executions.length).toBeGreaterThan(0);
  });

  it('tracks gatekeeper state', async () => {
    setGatekeeperEnabled(true);
    setGatekeeperDryRun(false);
    
    const event: GatekeeperEvent = {
      id: 'evt-state',
      event_type: 'test.event',
      timestamp: Date.now(),
    };
    
    await processEvent(event, { playbooksDir: testDir });
    
    const status = getGatekeeperStatus();
    expect(status.state.enabled).toBe(true);
    expect(status.state.dry_run).toBe(false);
    expect(status.state.executions_count).toBeGreaterThan(0);
    expect(status.state.recent_actions.length).toBeGreaterThan(0);
  });

  it('dry-run mode does not mutate', async () => {
    const containPlaybook = `
id: test-contain-dry
name: Test Contain Dry
tier: contain
match:
  event_type: contain.test
actions:
  - type: deny_tool
    params:
      tool: test_tool
      duration_ms: 60000
`;
    writeFileSync(join(testDir, 'contain-playbook.yaml'), containPlaybook);
    resetPlaybooksCache();
    
    const event: GatekeeperEvent = {
      id: 'evt-dry',
      event_type: 'contain.test',
      timestamp: Date.now(),
    };
    
    const executions = await processEvent(event, {
      dryRunOverride: true,
      playbooksDir: testDir,
    });
    
    expect(executions[0].dry_run).toBe(true);
    expect(executions[0].actions[0].dry_run).toBe(true);
    
    const override = getRuntimeOverride('deny_tool:test_tool');
    expect(override).toBeNull();
  });
});

describe('Gatekeeper Playbook Loading', () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `phaseone-playbooks-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
    resetPlaybooksCache();
  });

  afterEach(() => {
    resetPlaybooksCache();
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('loads playbooks from directory', () => {
    const playbook1 = `
id: load-test-1
name: Load Test 1
tier: observe
match:
  event_type: test
actions:
  - type: emit_alert
`;
    const playbook2 = `
id: load-test-2
name: Load Test 2
tier: contain
match:
  rule_id: test-rule
actions:
  - type: tighten_rate_limit
`;
    writeFileSync(join(testDir, 'playbook1.yaml'), playbook1);
    writeFileSync(join(testDir, 'playbook2.yaml'), playbook2);
    
    const playbooks = loadPlaybooks(testDir);
    expect(playbooks).toHaveLength(2);
    expect(playbooks.find(p => p.id === 'load-test-1')).toBeTruthy();
    expect(playbooks.find(p => p.id === 'load-test-2')).toBeTruthy();
  });

  it('sorts playbooks by tier', () => {
    const harden = `
id: tier-harden
name: Harden
tier: harden
match:
  severity: critical
actions:
  - type: emit_alert
`;
    const observe = `
id: tier-observe
name: Observe
tier: observe
match:
  event_type: test
actions:
  - type: emit_alert
`;
    const contain = `
id: tier-contain
name: Contain
tier: contain
match:
  rule_id: test
actions:
  - type: emit_alert
`;
    writeFileSync(join(testDir, 'harden.yaml'), harden);
    writeFileSync(join(testDir, 'observe.yaml'), observe);
    writeFileSync(join(testDir, 'contain.yaml'), contain);
    
    const playbooks = loadPlaybooks(testDir);
    expect(playbooks[0].tier).toBe('observe');
    expect(playbooks[1].tier).toBe('contain');
    expect(playbooks[2].tier).toBe('harden');
  });

  it('skips invalid playbook files', () => {
    const valid = `
id: valid-playbook
name: Valid
tier: observe
match:
  event_type: test
actions:
  - type: emit_alert
`;
    const invalid = 'this is not valid yaml: [[';
    writeFileSync(join(testDir, 'valid.yaml'), valid);
    writeFileSync(join(testDir, 'invalid.yaml'), invalid);
    
    const playbooks = loadPlaybooks(testDir);
    expect(playbooks).toHaveLength(1);
    expect(playbooks[0].id).toBe('valid-playbook');
  });

  it('lists playbooks with details', () => {
    const playbook = `
id: detail-test
name: Detail Test
description: A test playbook with details
tier: observe
enabled: false
match:
  event_type: test
actions:
  - type: emit_alert
  - type: write_audit
`;
    writeFileSync(join(testDir, 'detail.yaml'), playbook);
    
    const detailed = listPlaybooksDetailed(testDir);
    expect(detailed).toHaveLength(1);
    expect(detailed[0].file).toBe('detail.yaml');
    expect(detailed[0].description).toBe('A test playbook with details');
    expect(detailed[0].enabled).toBe(false);
    expect(detailed[0].actions).toHaveLength(2);
  });

  it('returns empty array for missing directory', () => {
    const playbooks = loadPlaybooks('/nonexistent/path');
    expect(playbooks).toEqual([]);
  });
});

describe('Gatekeeper LLM Advisor', () => {
  function createMockFetch(responses: Array<{ ok: boolean; status?: number; body?: unknown; error?: Error }>): typeof fetch {
    let callIndex = 0;
    return async (_url: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
      const response = responses[callIndex++] ?? { ok: false, status: 500 };
      
      if (response.error) {
        throw response.error;
      }
      
      return {
        ok: response.ok,
        status: response.status ?? (response.ok ? 200 : 500),
        json: async () => response.body,
        text: async () => JSON.stringify(response.body),
      } as Response;
    };
  }

  it('loads LLM config from environment', async () => {
    const { loadGatekeeperLLMConfig } = await import('../shared/src/gatekeeper-llm.js');
    const originalKey = process.env.OPENROUTER_API_KEY;
    const originalPrimary = process.env.PHASEONE_GATEKEEPER_LLM_PRIMARY;

    try {
      process.env.OPENROUTER_API_KEY = 'test-key-123';
      process.env.PHASEONE_GATEKEEPER_LLM_PRIMARY = 'openrouter';
      
      const config = loadGatekeeperLLMConfig();
      
      expect(config.enabled).toBe(true);
      expect(config.primary).toBe('openrouter');
      expect(config.fallback).toBe('ollama');
      expect(config.openrouter.apiKey).toBe('test-key-123');
      expect(config.openrouter.model).toBe('openrouter/auto');
      expect(config.ollama.model).toBe('unrestricted:latest');
    } finally {
      if (originalKey === undefined) delete process.env.OPENROUTER_API_KEY;
      else process.env.OPENROUTER_API_KEY = originalKey;
      if (originalPrimary === undefined) delete process.env.PHASEONE_GATEKEEPER_LLM_PRIMARY;
      else process.env.PHASEONE_GATEKEEPER_LLM_PRIMARY = originalPrimary;
    }
  });

  it('returns disabled when no API key configured', async () => {
    const { loadGatekeeperLLMConfig } = await import('../shared/src/gatekeeper-llm.js');
    const originalKey = process.env.OPENROUTER_API_KEY;
    const originalEnabled = process.env.PHASEONE_GATEKEEPER_LLM_ENABLED;

    try {
      delete process.env.OPENROUTER_API_KEY;
      delete process.env.PHASEONE_GATEKEEPER_LLM_ENABLED;
      
      const config = loadGatekeeperLLMConfig();
      expect(config.enabled).toBe(false);
    } finally {
      if (originalKey !== undefined) process.env.OPENROUTER_API_KEY = originalKey;
      if (originalEnabled !== undefined) process.env.PHASEONE_GATEKEEPER_LLM_ENABLED = originalEnabled;
    }
  });

  it('describes config without exposing API key', async () => {
    const { describeConfig } = await import('../shared/src/gatekeeper-llm.js');
    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'secret-key-123', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 30000,
      maxTokens: 512,
    };

    const described = describeConfig(config);

    expect(described.enabled).toBe(true);
    expect((described.openrouter as { configured: boolean }).configured).toBe(true);
    expect(JSON.stringify(described)).not.toContain('secret-key-123');
  });

  it('completes advisor prompt via primary (OpenRouter)', async () => {
    const { completeAdvisorPrompt } = await import('../shared/src/gatekeeper-llm.js');
    const mockFetch = createMockFetch([{
      ok: true,
      body: {
        choices: [{ message: { content: 'Recommend enabling rate limiting for this agent.' } }],
      },
    }]);

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'test-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 30000,
      maxTokens: 512,
    };

    const response = await completeAdvisorPrompt(
      { context: 'test', event_summary: 'Canary trigger' },
      config,
      mockFetch
    );

    expect(response.ok).toBe(true);
    expect(response.provider).toBe('openrouter');
    expect(response.fallback_used).toBe(false);
    expect(response.suggestion).toContain('rate limiting');
  });

  it('falls back to Ollama when OpenRouter fails', async () => {
    const { completeAdvisorPrompt } = await import('../shared/src/gatekeeper-llm.js');
    const mockFetch = createMockFetch([
      { ok: false, status: 401, body: { error: { message: 'Invalid API key' } } },
      { ok: true, body: { choices: [{ message: { content: 'Fallback suggestion: quarantine agent.' } }] } },
    ]);

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'bad-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 30000,
      maxTokens: 512,
    };

    const response = await completeAdvisorPrompt(
      { context: 'test', event_summary: 'A2A blocked' },
      config,
      mockFetch
    );

    expect(response.ok).toBe(true);
    expect(response.provider).toBe('ollama');
    expect(response.fallback_used).toBe(true);
    expect(response.suggestion).toContain('quarantine');
  });

  it('gracefully degrades when both providers fail', async () => {
    const { completeAdvisorPrompt } = await import('../shared/src/gatekeeper-llm.js');
    const mockFetch = createMockFetch([
      { ok: false, status: 500, body: { error: { message: 'Server error' } } },
      { ok: false, status: 503, body: { error: { message: 'Service unavailable' } } },
    ]);

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'test-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 30000,
      maxTokens: 512,
    };

    const response = await completeAdvisorPrompt(
      { context: 'test', event_summary: 'Injection blocked' },
      config,
      mockFetch
    );

    expect(response.ok).toBe(false);
    expect(response.provider).toBe('none');
    expect(response.fallback_used).toBe(true);
    expect(response.error).toContain('primary');
    expect(response.error).toContain('fallback');
  });

  it('returns disabled error when advisor is not enabled', async () => {
    const { completeAdvisorPrompt } = await import('../shared/src/gatekeeper-llm.js');
    const config = {
      enabled: false,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: '', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 30000,
      maxTokens: 512,
    };

    const response = await completeAdvisorPrompt(
      { context: 'test', event_summary: 'Test event' },
      config,
      createMockFetch([])
    );

    expect(response.ok).toBe(false);
    expect(response.error).toContain('not enabled');
  });

  it('handles timeout gracefully', async () => {
    const { completeAdvisorPrompt } = await import('../shared/src/gatekeeper-llm.js');

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'none' as const,
      openrouter: { apiKey: 'test-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 50,
      maxTokens: 512,
    };

    const mockFetch = createMockFetch([{
      ok: false,
      error: Object.assign(new Error('timeout after 50ms'), { name: 'AbortError' }),
    }]);

    const response = await completeAdvisorPrompt(
      { context: 'test', event_summary: 'Timeout test' },
      config,
      mockFetch
    );

    expect(response.ok).toBe(false);
  });

  it('handles empty response from model', async () => {
    const { completeAdvisorPrompt } = await import('../shared/src/gatekeeper-llm.js');
    const mockFetch = createMockFetch([
      { ok: true, body: { choices: [{ message: { content: '' } }] } },
      { ok: true, body: { choices: [{ message: { content: 'Fallback response with content.' } }] } },
    ]);

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'test-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 30000,
      maxTokens: 512,
    };

    const response = await completeAdvisorPrompt(
      { context: 'test', event_summary: 'Empty response test' },
      config,
      mockFetch
    );

    expect(response.ok).toBe(true);
    expect(response.provider).toBe('ollama');
    expect(response.fallback_used).toBe(true);
  });

  it('checks health of both providers', async () => {
    const { checkLLMHealth } = await import('../shared/src/gatekeeper-llm.js');
    const mockFetch = createMockFetch([
      { ok: true, body: { choices: [{ message: { content: 'OK' } }] } },
      { ok: true, body: { choices: [{ message: { content: 'OK' } }] } },
    ]);

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'test-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 15000,
      maxTokens: 64,
    };

    const health = await checkLLMHealth(config, mockFetch);

    expect(health.openrouter.ok).toBe(true);
    expect(health.ollama.ok).toBe(true);
    expect(health.recommended_provider).toBe('openrouter');
  });

  it('recommends ollama when openrouter fails health check', async () => {
    const { checkLLMHealth } = await import('../shared/src/gatekeeper-llm.js');
    const mockFetch = createMockFetch([
      { ok: false, status: 401, body: { error: { message: 'Unauthorized' } } },
      { ok: true, body: { choices: [{ message: { content: 'OK' } }] } },
    ]);

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'bad-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 15000,
      maxTokens: 64,
    };

    const health = await checkLLMHealth(config, mockFetch);

    expect(health.openrouter.ok).toBe(false);
    expect(health.ollama.ok).toBe(true);
    expect(health.recommended_provider).toBe('ollama');
  });

  it('recommends none when both providers fail health check', async () => {
    const { checkLLMHealth } = await import('../shared/src/gatekeeper-llm.js');
    const mockFetch = createMockFetch([
      { ok: false, status: 500, body: { error: { message: 'Server error' } } },
      { ok: false, status: 503, body: { error: { message: 'Service unavailable' } } },
    ]);

    const config = {
      enabled: true,
      primary: 'openrouter' as const,
      fallback: 'ollama' as const,
      openrouter: { apiKey: 'test-key', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto' },
      ollama: { baseUrl: 'http://localhost:11434/v1', model: 'unrestricted:latest' },
      timeoutMs: 15000,
      maxTokens: 64,
    };

    const health = await checkLLMHealth(config, mockFetch);

    expect(health.openrouter.ok).toBe(false);
    expect(health.ollama.ok).toBe(false);
    expect(health.recommended_provider).toBe('none');
  });
});
