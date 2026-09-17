/**
 * Phase 5 unit coverage: rate limit, retention, security headers,
 * smoke helpers, onboard Phase 5 env, OpenAPI presence.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  checkRateLimit,
  recordRateLimitHit,
  loadApiRateLimitConfig,
  loadOtpRateLimitConfig,
  __testResetRateLimits,
} from '../shared/src/rate-limit.js';
import {
  loadRetentionConfig,
  runRetentionCleanup,
} from '../shared/src/retention.js';
import {
  SECURITY_HEADERS,
  dashboardContentSecurityPolicy,
  describeCookieDefaults,
} from '../shared/src/security-headers.js';
import { defaultAnswers, renderEnv, parseArgs } from '../scripts/onboard.js';
import { parseRetentionArgs } from '../scripts/retention-cleanup.js';
import { loadConfig } from '../gateway/src/config.js';

describe('rate limiter', () => {
  beforeEach(() => __testResetRateLimits());

  it('allows under max then blocks', () => {
    const opts = { windowMs: 60_000, max: 3, prefix: 't' };
    expect(recordRateLimitHit('a', opts).ok).toBe(true);
    expect(recordRateLimitHit('a', opts).ok).toBe(true);
    expect(recordRateLimitHit('a', opts).ok).toBe(true);
    const blocked = recordRateLimitHit('a', opts);
    expect(blocked.ok).toBe(false);
    expect(blocked.retryAfterMs).toBeGreaterThan(0);
  });

  it('isolates keys', () => {
    const opts = { windowMs: 60_000, max: 1, prefix: 't' };
    expect(recordRateLimitHit('x', opts).ok).toBe(true);
    expect(recordRateLimitHit('y', opts).ok).toBe(true);
    expect(recordRateLimitHit('x', opts).ok).toBe(false);
  });

  it('loads api + otp configs from env', () => {
    const prev = process.env.PHASEONE_API_RATE_LIMIT;
    process.env.PHASEONE_API_RATE_LIMIT = '42';
    expect(loadApiRateLimitConfig().max).toBe(42);
    expect(loadOtpRateLimitConfig().max).toBeGreaterThan(0);
    if (prev === undefined) delete process.env.PHASEONE_API_RATE_LIMIT;
    else process.env.PHASEONE_API_RATE_LIMIT = prev;
  });

  it('checkRateLimit does not consume without record', () => {
    const opts = { windowMs: 60_000, max: 1, prefix: 'chk' };
    expect(checkRateLimit('z', opts).ok).toBe(true);
    expect(checkRateLimit('z', opts).ok).toBe(true);
  });
});

describe('retention cleanup', () => {
  it('loadRetentionConfig defaults', () => {
    const cfg = loadRetentionConfig({ retentionDays: 7, dryRun: true });
    expect(cfg.retentionDays).toBe(7);
    expect(cfg.dryRun).toBe(true);
  });

  it('dry-run counts via query stub', async () => {
    const calls: string[] = [];
    const result = await runRetentionCleanup(async (sql) => {
      calls.push(sql);
      return { rowCount: 0, rows: [{ c: 3 }] };
    }, loadRetentionConfig({ retentionDays: 14, dryRun: true }));
    expect(result.ok).toBe(true);
    expect(result.dry_run).toBe(true);
    expect(result.events_deleted).toBe(3);
    expect(calls.some((s) => s.includes('SELECT COUNT'))).toBe(true);
  });

  it('execute issues DELETE', async () => {
    const calls: string[] = [];
    const result = await runRetentionCleanup(async (sql) => {
      calls.push(sql);
      return { rowCount: 2, rows: [] };
    }, loadRetentionConfig({ retentionDays: 30, dryRun: false, pruneApprovals: false, pruneAudit: false }));
    expect(result.ok).toBe(true);
    expect(result.events_deleted).toBe(2);
    expect(calls.some((s) => s.startsWith('DELETE FROM events'))).toBe(true);
  });

  it('parseRetentionArgs defaults to dry-run', () => {
    expect(parseRetentionArgs([]).dryRun).toBe(true);
    expect(parseRetentionArgs(['--execute']).dryRun).toBe(false);
    expect(parseRetentionArgs(['--days', '10']).days).toBe(10);
  });
});

describe('security headers & cookies', () => {
  it('exports required headers', () => {
    expect(SECURITY_HEADERS['X-Content-Type-Options']).toBe('nosniff');
    expect(SECURITY_HEADERS['X-Frame-Options']).toBe('DENY');
    expect(SECURITY_HEADERS['Referrer-Policy']).toBe('no-referrer');
  });

  it('dashboard CSP denies framing', () => {
    const csp = dashboardContentSecurityPolicy();
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("default-src 'self'");
  });

  it('cookie notes document Secure flag tradeoff', () => {
    const insecure = describeCookieDefaults(false);
    expect(insecure.secure).toBe(false);
    expect(insecure.httpOnly).toBe(true);
    expect(insecure.notes.some((n) => n.includes('PHASEONE_SECURE_COOKIES'))).toBe(true);
    expect(describeCookieDefaults(true).secure).toBe(true);
  });
});

describe('onboard Phase 5 env', () => {
  it('renderEnv includes retention and rate limits', () => {
    const env = renderEnv(defaultAnswers());
    expect(env).toContain('PHASEONE_RETENTION_DAYS=');
    expect(env).toContain('PHASEONE_API_RATE_LIMIT=');
    expect(env).toContain('PHASEONE_OTP_RATE_LIMIT=');
    expect(env).toContain('PHASEONE_BACKUP_DIR=');
    expect(env).toContain('v0.7');
  });
});

describe('version & docs artifacts', () => {
  it('config productVersion is 0.7.0', () => {
    expect(loadConfig().productVersion).toBe('0.7.0');
  });

  it('package.json is 0.7.0', () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'));
    expect(pkg.version).toBe('0.7.0');
    expect(pkg.scripts.smoke).toBeTruthy();
    expect(pkg.scripts.retention).toBeTruthy();
    expect(pkg.scripts.backup).toBeTruthy();
  });

  it('OpenAPI exists and covers healthz + chat + ops', () => {
    const path = join(process.cwd(), 'docs/openapi.yaml');
    expect(existsSync(path)).toBe(true);
    const body = readFileSync(path, 'utf8');
    expect(body).toContain('/healthz');
    expect(body).toContain('/v1/chat/completions');
    expect(body).toContain('/v1/phaseone/ops');
    expect(body).toContain('0.6.0');
    expect(body).toContain('Veracity Integrity');
  });

  it('operations.md and adapters README exist', () => {
    expect(existsSync(join(process.cwd(), 'docs/operations.md'))).toBe(true);
    const adapters = readFileSync(join(process.cwd(), 'adapters/README.md'), 'utf8');
    expect(adapters).toContain('http://localhost:8080');
    expect(adapters).toContain('Framework Adapters');
  });

  it('backup/restore/smoke scripts exist', () => {
    expect(existsSync(join(process.cwd(), 'scripts/backup.sh'))).toBe(true);
    expect(existsSync(join(process.cwd(), 'scripts/restore.sh'))).toBe(true);
    expect(existsSync(join(process.cwd(), 'scripts/smoke.ts'))).toBe(true);
    expect(existsSync(join(process.cwd(), 'scripts/retention-cleanup.ts'))).toBe(true);
  });

  it('compose has restart and non-root', () => {
    const compose = readFileSync(join(process.cwd(), 'docker-compose.yml'), 'utf8');
    expect(compose).toContain('restart: unless-stopped');
    expect(compose).toContain('user: "1000:1000"');
    expect(compose).toContain('PHASEONE_RETENTION_DAYS');
  });

  it('proxy.md and RECOMMENDATIONS.md exist with approved 1-9', () => {
    const rec = readFileSync(join(process.cwd(), 'docs/RECOMMENDATIONS.md'), 'utf8');
    expect(rec).toContain('## 1. Onboard / session secret');
    expect(rec).toContain('## 9. Admin allowlist + MFA email');
    expect(rec).toContain('noreply@clovisstar.com');
    expect(existsSync(join(process.cwd(), 'docs/proxy.md'))).toBe(true);
    expect(existsSync(join(process.cwd(), 'docker-compose.proxy.yml'))).toBe(true);
    expect(existsSync(join(process.cwd(), '.github/dependabot.yml'))).toBe(true);
    expect(existsSync(join(process.cwd(), 'scripts/windows/Register-PhaseOneScheduledTasks.ps1'))).toBe(true);
  });
});

