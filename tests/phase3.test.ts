/**
 * Phase 3 unit coverage: SIEM export, timeline replay, approval helpers,
 * secret deep-redact, MCP allowlist E2E (policy).
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { loadPolicy, evaluateToolCall } from '../policy/src/engine.js';
import { eventsToJsonl, toEcsLike, sendWebhookSink } from '../recorder/src/export.js';
import { buildTimelineSteps } from '../recorder/src/recorder.js';
import {
  getApprovalTimeoutMs,
  approvalExpiresAt,
  riskForTool,
} from '../gateway/src/approval.js';
import {
  detectSecrets,
  redactSecretsDeep,
  detectSecretsInValue,
  listSecretPatternTypes,
  OUTBOUND_TOOL_NAMES,
} from '../shared/src/secrets.js';
import type { AgentEvent } from '../shared/src/types.js';

beforeAll(() => {
  loadPolicy();
});

describe('MCP allowlist E2E (policy)', () => {
  it('allows listed MCP server + tool', () => {
    const d = evaluateToolCall('a1', 's1', 'mcp_call', {
      server: 'filesystem',
      tool: 'read_file',
    });
    expect(d.action).toBe('allow');
  });

  it('denies unlisted MCP server', () => {
    const d = evaluateToolCall('a1', 's1', 'mcp_call', {
      server: 'evil-remote-mcp',
      tool: 'exec',
    });
    expect(d.action).toBe('deny');
    expect(d.ruleId).toBe('mcp.allowlist');
  });

  it('denies MCP deny_tools', () => {
    const d = evaluateToolCall('a1', 's1', 'mcp_call', {
      server: 'filesystem',
      tool: 'raw_shell',
    });
    expect(d.action).toBe('deny');
    expect(d.ruleId).toBe('mcp.tool.deny');
  });

  it('allows lab-fake-mcp stub server', () => {
    const d = evaluateToolCall('lab', 's1', 'mcp_call', {
      server: 'lab-fake-mcp',
      tool: 'echo',
    });
    expect(d.action).toBe('allow');
  });
});

describe('SIEM JSONL + webhook export', () => {
  const sample: AgentEvent = {
    id: 'e1',
    session_id: '00000000-0000-4000-8000-000000000099',
    agent_id: 'agent-test',
    event_type: 'tool.call',
    severity: 'info',
    timestamp: '2026-01-15T12:00:00.000Z',
    tool_name: 'http_request',
    tool_args: { url: 'https://api.openai.com', authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz' },
    destination: 'https://api.openai.com',
    decision: 'allow',
    decision_reason: 'ok',
  };

  it('toEcsLike brands Veracity and redacts secrets', () => {
    const doc = toEcsLike(sample, { version: '0.3.0' });
    expect(doc.labels.product).toBe('PhaseOne10841');
    expect(doc.labels.vendor).toBe('Veracity Integrity LLC');
    expect(doc.labels.version).toBe('0.3.0');
    expect(JSON.stringify(doc)).toContain('[REDACTED]');
    expect(JSON.stringify(doc)).not.toMatch(/sk-abcdefghijklmnop/);
  });

  it('eventsToJsonl emits NDJSON lines', () => {
    const body = eventsToJsonl([sample, { ...sample, id: 'e2' }]);
    const lines = body.trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0])['@timestamp']).toBeTruthy();
  });

  it('sendWebhookSink posts ECS-ish payload', async () => {
    const fetchImpl = vi.fn(async () => new Response('ok', { status: 200 }));
    const result = await sendWebhookSink('https://siem.example/hook', [sample], {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      version: '0.3.0',
    });
    expect(result.ok).toBe(true);
    expect(result.sent).toBe(1);
    expect(fetchImpl).toHaveBeenCalledOnce();
    const call = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    const init = call[1];
    const body = JSON.parse(String(init.body));
    expect(body.vendor).toBe('Veracity Integrity LLC');
    expect(body.format).toBe('ecs-ish');
  });
});

describe('deep session replay timeline', () => {
  it('buildTimelineSteps chains agent→tool→args→dest→result→next', () => {
    const events: AgentEvent[] = [
      {
        id: '1',
        session_id: 's',
        agent_id: 'a',
        event_type: 'tool.call',
        severity: 'info',
        timestamp: '2026-01-01T00:00:00.000Z',
        tool_name: 'http_request',
        tool_args: { token: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
        destination: 'https://api.github.com',
        decision: 'deny',
      },
      {
        id: '2',
        session_id: 's',
        agent_id: 'a',
        event_type: 'policy.decision',
        severity: 'high',
        timestamp: '2026-01-01T00:00:01.000Z',
        decision: 'deny',
        decision_reason: 'blocked',
      },
    ];
    const steps = buildTimelineSteps(events);
    expect(steps).toHaveLength(2);
    expect(steps[0].chain.agent).toBe('a');
    expect(steps[0].chain.tool).toBe('http_request');
    expect(steps[0].chain.dest).toBe('https://api.github.com');
    expect(steps[0].chain.next).toBe('2');
    expect(JSON.stringify(steps[0].chain.args)).toContain('[REDACTED]');
    expect(steps[1].index).toBe(1);
  });
});

describe('approval helpers', () => {
  it('riskForTool classifies destructive tools', () => {
    expect(riskForTool('delete_file')).toBe('high');
    expect(riskForTool('read_file')).toBe('low');
  });

  it('approvalExpiresAt is in the future', () => {
    const iso = approvalExpiresAt(new Date('2026-01-01T00:00:00Z'), 60_000);
    expect(Date.parse(iso)).toBe(Date.parse('2026-01-01T00:01:00.000Z'));
  });

  it('getApprovalTimeoutMs reads env', () => {
    const prev = process.env.PHASEONE_APPROVAL_TIMEOUT_MS;
    process.env.PHASEONE_APPROVAL_TIMEOUT_MS = '5000';
    expect(getApprovalTimeoutMs()).toBe(5000);
    if (prev === undefined) delete process.env.PHASEONE_APPROVAL_TIMEOUT_MS;
    else process.env.PHASEONE_APPROVAL_TIMEOUT_MS = prev;
  });
});

describe('secret-egress hardening', () => {
  it('lists expanded pattern types', () => {
    expect(listSecretPatternTypes().length).toBeGreaterThan(10);
    expect(listSecretPatternTypes()).toContain('jwt_token');
    expect(listSecretPatternTypes()).toContain('npm_token');
  });

  it('detects nested secrets in objects', () => {
    const hits = detectSecretsInValue({
      headers: { Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwxyz123456' },
      body: { nested: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
    });
    expect(hits.length).toBeGreaterThan(0);
  });

  it('redactSecretsDeep redacts sensitive keys', () => {
    const out = redactSecretsDeep({
      password: 'supersecretvalue',
      nested: { api_key: 'abcdefghijklmnop' },
      safe: 'hello',
    }) as Record<string, unknown>;
    expect(out.password).toBe('[REDACTED]');
    expect((out.nested as Record<string, unknown>).api_key).toBe('[REDACTED]');
    expect(out.safe).toBe('hello');
  });

  it('outbound tool set includes mcp and email', () => {
    expect(OUTBOUND_TOOL_NAMES.has('mcp_call')).toBe(true);
    expect(OUTBOUND_TOOL_NAMES.has('send_email')).toBe(true);
  });

  it('detects stripe + jwt shapes', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepartxx';
    expect(detectSecrets(`key sk_live_${'a'.repeat(24)}`).some((h) => h.type === 'stripe_key')).toBe(
      true
    );
    expect(detectSecrets(jwt).some((h) => h.type === 'jwt_token')).toBe(true);
  });
});
