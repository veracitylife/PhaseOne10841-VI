/**
 * In-memory sliding-window rate limiter (defensive abuse protection).
 * PhaseOne10841 — Veracity Integrity LLC
 */

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  /** Optional key prefix for namespacing buckets */
  prefix?: string;
}

export interface RateLimitResult {
  ok: boolean;
  remaining: number;
  limit: number;
  retryAfterMs?: number;
  resetAt: number;
}

const buckets = new Map<string, number[]>();

export function checkRateLimit(key: string, opts: RateLimitOptions): RateLimitResult {
  const fullKey = `${opts.prefix ?? 'rl'}:${key}`;
  const now = Date.now();
  const hits = (buckets.get(fullKey) ?? []).filter((t) => now - t < opts.windowMs);
  buckets.set(fullKey, hits);
  const resetAt = hits.length ? hits[0] + opts.windowMs : now + opts.windowMs;
  if (hits.length >= opts.max) {
    return {
      ok: false,
      remaining: 0,
      limit: opts.max,
      retryAfterMs: Math.max(0, resetAt - now),
      resetAt,
    };
  }
  return {
    ok: true,
    remaining: Math.max(0, opts.max - hits.length - 1),
    limit: opts.max,
    resetAt,
  };
}

export function recordRateLimitHit(key: string, opts: RateLimitOptions): RateLimitResult {
  const check = checkRateLimit(key, opts);
  if (!check.ok) return check;
  const fullKey = `${opts.prefix ?? 'rl'}:${key}`;
  const hits = buckets.get(fullKey) ?? [];
  hits.push(Date.now());
  buckets.set(fullKey, hits);
  return {
    ok: true,
    remaining: Math.max(0, opts.max - hits.length),
    limit: opts.max,
    resetAt: hits[0] + opts.windowMs,
  };
}

export function loadApiRateLimitConfig(): RateLimitOptions {
  return {
    windowMs: Number(process.env.PHASEONE_API_RATE_WINDOW_MS ?? 60_000),
    max: Number(process.env.PHASEONE_API_RATE_LIMIT ?? 120),
    prefix: 'api',
  };
}

export function loadOtpRateLimitConfig(): RateLimitOptions {
  return {
    windowMs: Number(process.env.PHASEONE_OTP_RATE_WINDOW_MS ?? 15 * 60 * 1000),
    max: Number(process.env.PHASEONE_OTP_RATE_LIMIT ?? 5),
    prefix: 'otp',
  };
}

/** Clear all buckets (tests) */
export function __testResetRateLimits(): void {
  buckets.clear();
}
