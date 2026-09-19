/**
 * Operator MCP unit tests — tool list, auth, rate limit, gateway errors.
 * DEFENSIVE ONLY.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  TOOL_DEFINITIONS,
  handleToolCall,
  verifyAdminToken,
  ManagementRateLimiter,
  managementRateLimiter,
  isWriteTool,
} from '../mcp-server/src/tools.js';

const originalFetch = globalThis.fetch;

describe('Operator MCP tools', () => {
  beforeEach(() => {
    vi.stubEnv('PHASEONE_OPERATOR_MCP_TOKEN', 'test-admin-token');
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllEnvs();
  });

  it('lists all expected tools', () => {
    const names = TOOL_DEFINITIONS.map((t) => t.name);
    expect(names).toEqual([
      'phaseone_health',
      'phaseone_gatekeeper_status',
      'phaseone_pending',
      'phaseone_metrics',
      'phaseone_recent_events',
      'phaseone_confirm',
      'phaseone_deny',
      'phaseone_override',
    ]);
    expect(TOOL_DEFINITIONS.every((t) => t.description && t.inputSchema)).toBe(true);
  });

  it('classifies read vs write tools', () => {
    expect(isWriteTool('phaseone_health')).toBe(false);
    expect(isWriteTool('phaseone_confirm')).toBe(true);
    expect(isWriteTool('phaseone_deny')).toBe(true);
    expect(isWriteTool('phaseone_override')).toBe(true);
  });

  it('allows read tools without admin token', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ status: 'ok', service: 'phaseone-gateway' }),
    });

    const result = await handleToolCall('phaseone_health', {}, {
      gatewayUrl: 'http://127.0.0.1:8080',
    });

    expect(result.ok).toBe(true);
    expect(result.isError).toBeFalsy();
    const payload = JSON.parse(result.content[0].text);
    expect(payload.status).toBe('ok');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://127.0.0.1:8080/health',
      expect.objectContaining({ signal: expect.any(AbortSignal) })
    );
  });

  it('rejects write tools without admin token', async () => {
    const result = await handleToolCall(
      'phaseone_confirm',
      { id: 'pending-1' },
      { gatewayUrl: 'http://127.0.0.1:8080' }
    );

    expect(result.ok).toBe(false);
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.code).toBe('unauthorized');
  });

  it('accepts write tools with matching admin token', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ ok: true, action_id: 'pending-1' }),
    });

    const result = await handleToolCall(
      'phaseone_confirm',
      { id: 'pending-1', actor_email: 'ops@example.com' },
      {
        gatewayUrl: 'http://127.0.0.1:8080',
        adminToken: 'test-admin-token',
        adminTokenHeader: 'test-admin-token',
        actor: 'ops@example.com',
      }
    );

    expect(result.ok).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://127.0.0.1:8080/v1/phaseone/gatekeeper/confirm/pending-1',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ actor_email: 'ops@example.com' }),
      })
    );
  });

  it('verifyAdminToken matches header to env token', () => {
    expect(
      verifyAdminToken({
        gatewayUrl: 'http://127.0.0.1:8080',
        adminToken: 'test-admin-token',
        adminTokenHeader: 'test-admin-token',
      })
    ).toBe(true);
    expect(
      verifyAdminToken({
        gatewayUrl: 'http://127.0.0.1:8080',
        adminToken: 'test-admin-token',
        adminTokenHeader: 'wrong',
      })
    ).toBe(false);
  });

  it('returns structured error when gateway is unreachable', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await handleToolCall('phaseone_metrics', {}, {
      gatewayUrl: 'http://127.0.0.1:8080',
    });

    expect(result.ok).toBe(false);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.code).toBe('gateway_unreachable');
    expect(payload.error).toContain('ECONNREFUSED');
  });

  it('rate limits management calls', async () => {
    const limiter = new ManagementRateLimiter(2, 60_000);
    expect(limiter.check('test').allowed).toBe(true);
    expect(limiter.check('test').allowed).toBe(true);
    const blocked = limiter.check('test');
    expect(blocked.allowed).toBe(false);
    expect(blocked.retry_after_ms).toBeGreaterThan(0);
  });

  it('enforces rate limit on write tools', async () => {
    managementRateLimiter.reset();

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ ok: true }),
    });

    const ctx = {
      gatewayUrl: 'http://127.0.0.1:8080',
      adminToken: 'test-admin-token',
      adminTokenHeader: 'test-admin-token',
      actor: 'rate-test-write',
    };

    // Exhaust default limiter (30/min) for this actor by pre-filling bucket
    for (let i = 0; i < 30; i++) {
      managementRateLimiter.check('rate-test-write');
    }

    const result = await handleToolCall('phaseone_deny', { id: 'x' }, ctx);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.code).toBe('rate_limited');

    managementRateLimiter.reset();
  });
});
