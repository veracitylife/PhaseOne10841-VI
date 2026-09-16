/**
 * Phase 5 API routes — retention status, rate-limit config, ops info.
 * DEFENSIVE ONLY.
 */
import type { Hono } from 'hono';
import { getPool } from '../../../recorder/src/db.js';
import {
  loadRetentionConfig,
  runRetentionWithPool,
} from '../../../shared/src/retention.js';
import { loadApiRateLimitConfig, loadOtpRateLimitConfig } from '../../../shared/src/rate-limit.js';
import { describeCookieDefaults, SECURITY_HEADERS } from '../../../shared/src/security-headers.js';
import type { GatewayConfig } from '../config.js';

export function registerPhase5Routes(app: Hono, cfg: GatewayConfig): void {
  app.get('/v1/phaseone/ops', (c) => {
    const retention = loadRetentionConfig();
    const apiRl = loadApiRateLimitConfig();
    const otpRl = loadOtpRateLimitConfig();
    const secure =
      (process.env.PHASEONE_SECURE_COOKIES ?? 'false').toLowerCase() === 'true';
    return c.json({
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
      site: 'https://VeracityIntegrity.com',
      version: cfg.productVersion,
      phase: 5,
      retention: {
        days: retention.retentionDays,
        prune_approvals: retention.pruneApprovals,
        prune_audit: retention.pruneAudit,
      },
      rate_limits: {
        api: { window_ms: apiRl.windowMs, max: apiRl.max },
        otp: { window_ms: otpRl.windowMs, max: otpRl.max },
      },
      security: {
        headers: SECURITY_HEADERS,
        cookies: describeCookieDefaults(secure),
      },
      openapi: '/docs/openapi.yaml',
    });
  });

  app.get('/v1/phaseone/retention', (c) => {
    const retention = loadRetentionConfig();
    return c.json({
      retention_days: retention.retentionDays,
      prune_approvals: retention.pruneApprovals,
      prune_audit: retention.pruneAudit,
      dry_run_default: retention.dryRun,
      run_via: 'npm run retention -- [--days N] [--dry-run]',
      note: 'Cleanup deletes events older than retention; then orphaned sessions; optional approvals/audit.',
    });
  });

  app.post('/v1/phaseone/retention/run', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      days?: number;
      dry_run?: boolean;
      actor_email?: string;
    };
    const retention = loadRetentionConfig({
      retentionDays: body.days,
      dryRun: body.dry_run ?? true, // API default dry-run for safety
    });
    const result = await runRetentionWithPool(getPool(), retention);
    return c.json(result, result.ok ? 200 : 500);
  });

  app.get('/v1/phaseone/rate-limits', (c) => {
    const apiRl = loadApiRateLimitConfig();
    const otpRl = loadOtpRateLimitConfig();
    return c.json({
      api: {
        window_ms: apiRl.windowMs,
        max: apiRl.max,
        applies_to: [
          '/v1/chat/completions',
          '/v1/phaseone/tools/*',
          '/v1/phaseone/events',
          '/v1/phaseone/a2a/*',
          '/v1/phaseone/scan/*',
          '/v1/phaseone/permissions/*',
        ],
        env: ['PHASEONE_API_RATE_LIMIT', 'PHASEONE_API_RATE_WINDOW_MS'],
      },
      otp: {
        window_ms: otpRl.windowMs,
        max: otpRl.max,
        applies_to: ['POST /api/auth/request-otp'],
        env: ['PHASEONE_OTP_RATE_LIMIT', 'PHASEONE_OTP_RATE_WINDOW_MS'],
      },
    });
  });
}
