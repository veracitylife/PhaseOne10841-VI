/**
 * Phase 8 Wave B + C unit tests — learn loop, MCP proxy helpers, signed canaries, orgs.
 * DEFENSIVE ONLY.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  recordPlaybookOutcome,
  computeEffectiveness,
  suggestTweaks,
  getEffectivenessReport,
  __testResetLearnLoop,
} from '../shared/src/playbook-learn.js';
import {
  generateCanaryKeyPair,
  signCanaryPayload,
  verifyCanarySignature,
  ensureCanaryKeys,
} from '../shared/src/canary-sign.js';
import {
  __testResetCanaryManager,
  rotateCanary,
  signAllCanaries,
  verifyAllCanaries,
  listCanariesDetailed,
} from '../canaries/src/manager.js';
import {
  createOrg,
  resolveOrgRole,
  canAccessOrg,
  resolveOrgPolicyPath,
  mintOrgApiKey,
  hashApiKey,
  __testResetOrgs,
} from '../shared/src/orgs.js';
import { toEcsLike } from '../recorder/src/export.js';
import type { AgentEvent } from '../shared/src/types.js';

describe('Wave B #2 playbook learn loop', () => {
  beforeEach(() => {
    __testResetLearnLoop();
  });

  it('records outcomes in memory when DB unavailable and computes deny rate', async () => {
    for (let i = 0; i < 6; i++) {
      await recordPlaybookOutcome({
        playbook_id: 'canary-response',
        outcome: i < 4 ? 'denied' : 'confirmed',
        actor_email: 'admin@localhost',
      });
    }
    const report = await getEffectivenessReport({ days: 7, playbook_id: 'canary-response' });
    expect(report.metrics.length).toBe(1);
    expect(report.metrics[0].total).toBe(6);
    expect(report.metrics[0].denied).toBe(4);
    expect(report.metrics[0].deny_rate).toBeCloseTo(4 / 6, 2);
    expect(report.suggestions.some((s) => s.requires_human_approval)).toBe(true);
  });

  it('suggests raise_threshold when deny rate > 50% with enough samples', () => {
    const metrics = computeEffectiveness(
      Array.from({ length: 10 }, (_, i) => ({
        playbook_id: 'noisy',
        outcome: (i < 7 ? 'denied' : 'confirmed') as 'denied' | 'confirmed',
      }))
    );
    const suggestions = suggestTweaks(metrics);
    expect(suggestions[0]?.kind).toBe('raise_threshold');
    expect(suggestions[0]?.requires_human_approval).toBe(true);
  });
});

describe('Wave B #7 signed canaries', () => {
  let keyDir: string;
  const prev = process.env.PHASEONE_CANARY_KEY_DIR;

  beforeEach(() => {
    __testResetCanaryManager();
    keyDir = mkdtempSync(join(tmpdir(), 'phaseone-canary-'));
    process.env.PHASEONE_CANARY_KEY_DIR = keyDir;
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.PHASEONE_CANARY_KEY_DIR;
    else process.env.PHASEONE_CANARY_KEY_DIR = prev;
    rmSync(keyDir, { recursive: true, force: true });
    __testResetCanaryManager();
  });

  it('signs and verifies Ed25519 canary payloads', () => {
    const keys = generateCanaryKeyPair();
    const payload = {
      canary_id: 'c1',
      name: 'test',
      marker: 'PHASEONE_CANARY_TEST_abc',
      rotated_at: null,
      previous_signature: null,
    };
    const bundle = signCanaryPayload(payload, keys);
    expect(bundle.algorithm).toBe('ed25519');
    expect(bundle.signature.length).toBeGreaterThan(20);
    const ok = verifyCanarySignature(payload, bundle.signature, keys.publicKeyPem);
    expect(ok.ok).toBe(true);
    const bad = verifyCanarySignature(
      { ...payload, marker: 'tampered' },
      bundle.signature,
      keys.publicKeyPem
    );
    expect(bad.ok).toBe(false);
  });

  it('rotate preserves signature chain and verify passes', () => {
    ensureCanaryKeys(keyDir);
    signAllCanaries();
    const before = listCanariesDetailed()[0];
    expect(before).toBeTruthy();
    const rotated = rotateCanary(before.canary_id, before.name);
    expect(rotated.ok).toBe(true);
    expect(rotated.record?.signature).toBeTruthy();
    expect(rotated.record?.signature_prev).toBe(before.signature ?? null);
    const results = verifyAllCanaries();
    expect(results.every((r) => r.valid === true)).toBe(true);
  });

  it('SIEM export includes canary_signature field', () => {
    const event: AgentEvent = {
      id: 'e1',
      session_id: 's1',
      agent_id: 'a1',
      event_type: 'canary.trigger',
      severity: 'high',
      timestamp: new Date().toISOString(),
      metadata: { canary_signature: 'sig-abc' },
    };
    const doc = toEcsLike(event, { version: '0.1.1' });
    expect(doc.phaseone.canary_signature).toBe('sig-abc');
    expect(doc.labels.version).toBe('0.1.1');
  });
});

describe('Wave C #6 multi-tenant orgs', () => {
  beforeEach(() => {
    __testResetOrgs();
  });

  it('creates org and resolves roles with isolation', async () => {
    const created = await createOrg('Acme Labs', { tier: 'lab' });
    expect(created.ok).toBe(true);
    expect(created.org?.id).toContain('acme');

    process.env.PHASEONE_ADMIN_EMAILS = 'global@example.com';
    process.env.PHASEONE_ORG_ADMINS = JSON.stringify({
      [created.org!.id]: ['orgadmin@example.com'],
    });

    expect(resolveOrgRole('global@example.com', created.org!.id)).toBe('global_admin');
    expect(resolveOrgRole('orgadmin@example.com', created.org!.id)).toBe('org_admin');
    expect(resolveOrgRole('stranger@example.com', created.org!.id)).toBe('none');
    expect(canAccessOrg('org_admin', created.org!.id, created.org!.id)).toBe(true);
    expect(canAccessOrg('org_admin', created.org!.id, 'other-org')).toBe(false);
  });

  it('mints org API keys with hash-only retention semantics', () => {
    const minted = mintOrgApiKey();
    expect(minted.raw.startsWith('po_')).toBe(true);
    expect(hashApiKey(minted.raw)).toBe(minted.hash);
    expect(minted.prefix.length).toBeGreaterThan(5);
  });

  it('falls back to global policy path when org policy missing', () => {
    const resolved = resolveOrgPolicyPath('no-such-org-xyz');
    expect(resolved.scoped).toBe(false);
    expect(resolved.path).toContain('policy');
  });
});

describe('Wave B #3 MCP allowlist policy surface', () => {
  it('default policy lists allowlisted MCP servers including lab stub', async () => {
    const { loadPolicy, getPolicy } = await import('../policy/src/engine.js');
    loadPolicy();
    const p = getPolicy();
    expect(p.mcp.mode).toBe('allowlist');
    expect(p.mcp.allow_servers).toContain('lab-fake-mcp');
    expect(p.mcp.deny_tools).toContain('unrestricted_exec');
  });
});
