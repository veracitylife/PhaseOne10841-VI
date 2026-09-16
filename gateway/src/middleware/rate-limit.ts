/**
 * Gateway API abuse rate limiting middleware.
 * DEFENSIVE ONLY — PhaseOne10841 / Veracity Integrity LLC
 */
import type { MiddlewareHandler } from 'hono';
import {
  recordRateLimitHit,
  loadApiRateLimitConfig,
  type RateLimitOptions,
} from '../../../shared/src/rate-limit.js';

/** Paths that skip API rate limits (probes / scrape) */
const SKIP_PREFIXES = ['/health', '/healthz', '/readyz', '/metrics'];

function clientKey(c: { req: { header: (n: string) => string | undefined } }): string {
  const xf = c.req.header('x-forwarded-for');
  if (xf) return xf.split(',')[0]!.trim();
  return c.req.header('x-real-ip') ?? c.req.header('x-phaseone-agent-id') ?? 'anon';
}

export function apiRateLimitMiddleware(opts?: RateLimitOptions): MiddlewareHandler {
  const cfg = opts ?? loadApiRateLimitConfig();
  return async (c, next) => {
    const path = c.req.path;
    if (SKIP_PREFIXES.some((p) => path === p || path.startsWith(p + '/'))) {
      await next();
      return;
    }
    // Only throttle chat + public-ish write endpoints
    const throttle =
      path.startsWith('/v1/chat') ||
      path.startsWith('/v1/phaseone/tools') ||
      path.startsWith('/v1/phaseone/events') ||
      path.startsWith('/v1/phaseone/a2a') ||
      path.startsWith('/v1/phaseone/scan') ||
      path.startsWith('/v1/phaseone/permissions');
    if (!throttle) {
      await next();
      return;
    }
    const key = clientKey(c);
    const hit = recordRateLimitHit(key, cfg);
    c.header('X-RateLimit-Limit', String(hit.limit));
    c.header('X-RateLimit-Remaining', String(hit.remaining));
    c.header('X-RateLimit-Reset', String(Math.ceil(hit.resetAt / 1000)));
    if (!hit.ok) {
      c.header('Retry-After', String(Math.ceil((hit.retryAfterMs ?? 1000) / 1000)));
      return c.json(
        {
          error: {
            message: 'PhaseOne10841 rate limit exceeded',
            type: 'rate_limit',
            code: 'phaseone.rate_limit',
            retry_after_ms: hit.retryAfterMs,
          },
        },
        429
      );
    }
    await next();
  };
}
