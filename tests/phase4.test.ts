/**
 * Phase 4 unit coverage: rules engine, metrics, alerting, audit, RBAC,
 * policy save/backup, canary rotate, adapters.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadRules,
  evaluateRules,
  listRulesWithCounts,
  __testResetHitCounts,
  resetRulesCache,
} from '../rules/src/engine.js';
import { Metrics, renderPrometheus, resetMetrics, getCounter, incCounter } from '../shared/src/metrics.js';
import { sendAlert, loadAlertConfig } from '../shared/src/alerting.js';
import { recordAudit, listAudit, __testResetAudit, __testPeekAudit } from '../shared/src/audit.js';
import { resolveRole, canMutate, canRead, loadRbacConfig } from '../shared/src/rbac.js';
import { validatePolicyYaml, savePolicyYaml, backupPolicyFile } from '../shared/src/policy-save.js';
import {
  listCanariesDetailed,
  rotateCanary,
  matchCanariesRuntime,
  noteCanaryTrigger,
  __testResetCanaryManager,
} from '../canaries/src/manager.js';
import { phaseOneOpenAIConfig, describeOpenAIIntegration } from '../adapters/openai-compatible.js';
import { langchainPhaseOneHint } from '../adapters/langchain-stub.js';
import { crewaiPhaseOneHint } from '../adapters/crewai-stub.js';
import { claudeToolProxyHint } from '../adapters/claude-tool-proxy-stub.js';
import { defaultAnswers, renderEnv } from '../scripts/onboard.js';
import { loadConfig } from '../gateway/src/config.js';

describe('detection rules engine', () => {
  beforeEach(() => {
    __testResetHitCounts();
    resetRulesCache();
  });

  it('loads shipped YAML rules', () => {
    const rules = loadRules(join(process.cwd(), 'rules'));
    expect(rules.length).toBeGreaterThanOrEqual(4);
    expect(rules.some((r) => r.id === 'phaseone.canary.trigger')).toBe(true);
  });

  it('matches canary.trigger events', () => {
    const hits = evaluateRules({ event_type: 'canary.trigger' }, join(process.cwd(), 'rules'));
    expect(hits.some((h) => h.rule_id === 'phaseone.canary.trigger')).toBe(true);
  });

  it('matches injection score threshold', () => {
    const hits = evaluateRules(
      { injection_score: 0.9, metadata: { injection_score: 0.9 } },
      join(process.cwd(), 'rules')
    );
    expect(hits.some((h) => h.rule_id === 'phaseone.injection.score.high')).toBe(true);
  });

  it('tracks hit counts', () => {
    evaluateRules({ event_type: 'prompt_injection.blocked' }, join(process.cwd(), 'rules'));
    evaluateRules({ event_type: 'prompt_injection.blocked' }, join(process.cwd(), 'rules'));
    const listed = listRulesWithCounts(join(process.cwd(), 'rules'));
    const rule = listed.find((r) => r.id === 'phaseone.injection.blocked');
    expect(rule?.hit_count).toBeGreaterThanOrEqual(2);
  });

  it('matches a2a selection_any', () => {
    const hits = evaluateRules({ event_type: 'a2a.quarantined' }, join(process.cwd(), 'rules'));
    expect(hits.some((h) => h.rule_id === 'phaseone.a2a.untrusted')).toBe(true);
  });
});

describe('prometheus metrics', () => {
  beforeEach(() => resetMetrics());

  it('increments named counters and renders text', () => {
    Metrics.block('policy');
    Metrics.canary();
    Metrics.injection('blocked');
    Metrics.approval('requested');
    Metrics.a2a('deny');
    const text = renderPrometheus();
    expect(text).toContain('phaseone_blocks_total');
    expect(text).toContain('phaseone_canaries_total');
    expect(getCounter('phaseone_canaries_total')).toBe(1);
    expect(text).toContain('Veracity Integrity');
  });

  it('incCounter with labels', () => {
    incCounter('phaseone_approvals_total', { status: 'approved' }, 2);
    expect(renderPrometheus()).toContain('phaseone_approvals_total{status="approved"} 2');
  });
});

describe('alerting retry/backoff', () => {
  it('returns not configured when URL missing', async () => {
    const prev = process.env.PHASEONE_ALERT_WEBHOOK_URL;
    delete process.env.PHASEONE_ALERT_WEBHOOK_URL;
    delete process.env.ALERT_WEBHOOK_URL;
    const r = await sendAlert(
      { event: 'canary', severity: 'critical', message: 'test' },
      { enabled: true, webhookUrl: undefined, maxRetries: 2, baseDelayMs: 1 }
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not configured/i);
    if (prev !== undefined) process.env.PHASEONE_ALERT_WEBHOOK_URL = prev;
  });

  it('retries on failure then succeeds', async () => {
    let n = 0;
    const fetchImpl = vi.fn(async () => {
      n += 1;
      if (n < 3) return new Response('nope', { status: 500 });
      return new Response('ok', { status: 200 });
    });
    const r = await sendAlert(
      { event: 'injection_blocked', severity: 'high', message: 'blocked' },
      { enabled: true, webhookUrl: 'https://hooks.example/alert', maxRetries: 4, baseDelayMs: 1 },
      fetchImpl as unknown as typeof fetch
    );
    expect(r.ok).toBe(true);
    expect(r.attempts).toBe(3);
  });

  it('loadAlertConfig reads env', () => {
    process.env.PHASEONE_ALERT_WEBHOOK_URL = 'https://hooks.example/x';
    const cfg = loadAlertConfig();
    expect(cfg.webhookUrl).toContain('hooks.example');
    delete process.env.PHASEONE_ALERT_WEBHOOK_URL;
  });
});

describe('admin audit log (memory)', () => {
  beforeEach(() => __testResetAudit());

  it('records actor + action + timestamp', async () => {
    const e = await recordAudit({
      actor_email: 'admin@veracityintegrity.com',
      action: 'login',
      detail: { role: 'admin' },
    });
    expect(e.actor_email).toBe('admin@veracityintegrity.com');
    expect(e.action).toBe('login');
    expect(e.created_at).toBeTruthy();
    expect(__testPeekAudit()).toHaveLength(1);
    const listed = await listAudit({ limit: 10 });
    expect(listed[0].action).toBe('login');
  });

  it('filters by action', async () => {
    await recordAudit({ actor_email: 'a@x.com', action: 'approve', resource: '1' });
    await recordAudit({ actor_email: 'a@x.com', action: 'export' });
    const only = await listAudit({ action: 'export' });
    expect(only.every((x) => x.action === 'export')).toBe(true);
  });
});

describe('RBAC lite', () => {
  const prevAdmin = process.env.PHASEONE_ADMIN_EMAILS;
  const prevViewer = process.env.PHASEONE_VIEWER_EMAILS;

  afterEach(() => {
    if (prevAdmin === undefined) delete process.env.PHASEONE_ADMIN_EMAILS;
    else process.env.PHASEONE_ADMIN_EMAILS = prevAdmin;
    if (prevViewer === undefined) delete process.env.PHASEONE_VIEWER_EMAILS;
    else process.env.PHASEONE_VIEWER_EMAILS = prevViewer;
  });

  it('resolves admin vs viewer vs none', () => {
    process.env.PHASEONE_ADMIN_EMAILS = 'admin@vi.com';
    process.env.PHASEONE_VIEWER_EMAILS = 'viewer@vi.com';
    const cfg = loadRbacConfig();
    expect(resolveRole('admin@vi.com', cfg)).toBe('admin');
    expect(resolveRole('viewer@vi.com', cfg)).toBe('viewer');
    expect(resolveRole('other@vi.com', cfg)).toBe('none');
    expect(canMutate('admin')).toBe(true);
    expect(canMutate('viewer')).toBe(false);
    expect(canRead('viewer')).toBe(true);
  });
});

describe('policy save path + reject invalid', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'phaseone-policy-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('rejects invalid YAML', () => {
    const v = validatePolicyYaml('version: [unclosed');
    expect(v.ok).toBe(false);
    expect(v.error).toMatch(/invalid YAML/i);
  });

  it('rejects disallowed keys', () => {
    const v = validatePolicyYaml('version: "0.4"\nname: x\nevil_exec: true\n');
    expect(v.ok).toBe(false);
    expect(v.error).toMatch(/disallowed/i);
  });

  it('rejects missing version/name', () => {
    const v = validatePolicyYaml('domains: {}\n');
    expect(v.ok).toBe(false);
  });

  it('dry_run validates without writing', () => {
    const path = join(dir, 'policy.yaml');
    writeFileSync(path, 'version: "0.4"\nname: base\n');
    const r = savePolicyYaml(path, 'version: "0.4"\nname: test\n', { dry_run: true });
    expect(r.ok).toBe(true);
    expect(r.dry_run).toBe(true);
    expect(readFileSync(path, 'utf8')).toContain('base');
  });

  it('saves and backs up previous version', () => {
    const path = join(dir, 'policy.yaml');
    writeFileSync(path, 'version: "0.3"\nname: old\n');
    const backupDir = join(dir, 'backups');
    const r = savePolicyYaml(path, 'version: "0.4"\nname: new\n', {
      actor: 'admin@vi.com',
      backupDir,
    });
    expect(r.ok).toBe(true);
    expect(r.backup).toBeTruthy();
    expect(existsSync(r.backup!)).toBe(true);
    expect(readFileSync(path, 'utf8')).toContain('name: new');
    expect(readFileSync(path, 'utf8')).toContain('Veracity Integrity');
  });

  it('backupPolicyFile returns null when missing', () => {
    expect(backupPolicyFile(join(dir, 'nope.yaml'))).toBeNull();
  });
});

describe('canary management', () => {
  beforeEach(() => __testResetCanaryManager());

  it('lists canaries with previews', () => {
    const list = listCanariesDetailed();
    expect(list.length).toBeGreaterThan(3);
    expect(list[0].marker_preview).toContain('…');
  });

  it('rotates marker values safely', () => {
    const list = listCanariesDetailed();
    const target = list[0];
    const before = target.marker;
    const r = rotateCanary(target.canary_id, target.name);
    expect(r.ok).toBe(true);
    expect(r.record?.marker).toMatch(/^PHASEONE_CANARY_ROTATED_/);
    expect(r.record?.marker).not.toBe(before);
  });

  it('tracks last trigger', () => {
    const list = listCanariesDetailed();
    noteCanaryTrigger(list[0].canary_id, { session_id: 's1', agent_id: 'a1', name: list[0].name });
    const again = listCanariesDetailed().find((c) => c.canary_id === list[0].canary_id);
    expect(again?.last_trigger_at).toBeTruthy();
  });

  it('matchCanariesRuntime finds markers', () => {
    const list = listCanariesDetailed();
    const hits = matchCanariesRuntime(`leak ${list[0].marker} here`);
    expect(hits.length).toBeGreaterThan(0);
  });
});

describe('framework adapters', () => {
  it('openai-compatible helper', () => {
    const cfg = phaseOneOpenAIConfig({ gatewayUrl: 'http://localhost:8080', agentId: 't' });
    expect(cfg.baseURL).toBe('http://localhost:8080/v1');
    expect(cfg.defaultHeaders['X-PhaseOne-Agent-Id']).toBe('t');
    expect(describeOpenAIIntegration()).toContain('Veracity Integrity');
  });

  it('langchain / crewai / claude stubs', () => {
    expect(langchainPhaseOneHint().baseURL).toContain('/v1');
    expect(crewaiPhaseOneHint().a2a_endpoint).toContain('/a2a/message');
    expect(claudeToolProxyHint().enforceUrl).toContain('/tools/enforce');
  });
});

describe('onboard Phase 4 env', () => {
  it('renderEnv includes Phase 4 keys', () => {
    const env = renderEnv(
      defaultAnswers({
        alertWebhookUrl: 'https://hooks.example/a',
        rulesDir: './rules',
        viewerEmails: 'v@localhost',
      })
    );
    expect(env).toContain('PHASEONE_ALERT_WEBHOOK_URL=https://hooks.example/a');
    expect(env).toContain('PHASEONE_RULES_DIR=./rules');
    expect(env).toContain('PHASEONE_VIEWER_EMAILS=v@localhost');
    expect(env).toMatch(/v0\.1\.2/);
  });
});

describe('gateway config version', () => {
  it('matches current app version 0.1.2', () => {
    expect(loadConfig().productVersion).toMatch(/^0\.1\.2$/);
  });
});
