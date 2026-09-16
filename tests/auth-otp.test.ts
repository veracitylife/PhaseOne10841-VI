/**
 * Dashboard MFA OTP harness — no real SMTP.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  loadAuthConfig,
  requestOtp,
  verifyOtp,
  getSession,
  destroySession,
  isEmailAllowlisted,
  checkOtpRateLimit,
  __testResetAuthState,
  __testGetLastOtp,
  __testPeekOtp,
  validateCsrf,
  createSession,
} from '../dashboard/src/auth.js';
import { canMutate } from '../shared/src/rbac.js';

describe('auth OTP (harness, no SMTP)', () => {
  const prev = { ...process.env };

  beforeEach(() => {
    process.env.PHASEONE_AUTH_TEST_MODE = 'true';
    process.env.PHASEONE_ADMIN_EMAILS = 'admin@veracityintegrity.com,ops@localhost';
    process.env.PHASEONE_DASHBOARD_AUTH = 'true';
    delete process.env.SMTP_HOST;
    process.env.PHASEONE_OTP_FALLBACK_FILE = '/tmp/phaseone-otp-test.log';
    process.env.PHASEONE_OTP_RATE_LIMIT = '20';
    __testResetAuthState();
  });

  afterEach(() => {
    __testResetAuthState();
    for (const k of Object.keys(process.env)) {
      if (!(k in prev)) delete process.env[k];
    }
    Object.assign(process.env, prev);
  });

  it('allowlists configured admin emails only', () => {
    const cfg = loadAuthConfig();
    expect(isEmailAllowlisted('admin@veracityintegrity.com', cfg)).toBe(true);
    expect(isEmailAllowlisted('ops@localhost', cfg)).toBe(true);
    expect(isEmailAllowlisted('evil@example.com', cfg)).toBe(false);
  });

  it('issues OTP via fallback channel when SMTP unset', async () => {
    const res = await requestOtp('admin@veracityintegrity.com');
    expect(res.ok).toBe(true);
    expect(res.channel).toBe('fallback');
    const last = __testGetLastOtp();
    expect(last?.email).toBe('admin@veracityintegrity.com');
    expect(last?.code).toMatch(/^\d{6}$/);
    expect(__testPeekOtp('admin@veracityintegrity.com')).toBe(last?.code);
  });

  it('rejects OTP for non-allowlisted email', async () => {
    const res = await requestOtp('stranger@example.com');
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/not authorized/i);
  });

  it('verifies correct OTP and creates session + CSRF', async () => {
    await requestOtp('ops@localhost');
    const code = __testGetLastOtp()!.code;
    const verified = verifyOtp('ops@localhost', code);
    expect(verified.ok).toBe(true);
    expect(verified.session?.email).toBe('ops@localhost');
    expect(verified.session?.csrfToken).toMatch(/^[a-f0-9]+$/);
    const session = getSession(verified.session!.id);
    expect(session?.email).toBe('ops@localhost');
    expect(validateCsrf(session!, session!.csrfToken, session!.csrfToken)).toBe(true);
    expect(validateCsrf(session!, 'bad', session!.csrfToken)).toBe(false);
    destroySession(session!.id);
    expect(getSession(session!.id)).toBeNull();
  });

  it('rejects wrong OTP', async () => {
    await requestOtp('admin@veracityintegrity.com');
    const bad = verifyOtp('admin@veracityintegrity.com', '000000');
    expect(bad.ok).toBe(false);
    expect(bad.error).toMatch(/invalid/i);
  });

  it('createSession works standalone', () => {
    const s = createSession('admin@veracityintegrity.com');
    expect(getSession(s.id)?.email).toBe('admin@veracityintegrity.com');
  });

  it('rate limit helper returns ok under limit', () => {
    const cfg = loadAuthConfig();
    const r = checkOtpRateLimit('admin@veracityintegrity.com', cfg);
    expect(r.ok).toBe(true);
  });

  it('viewer emails get viewer role (read-only)', async () => {
    process.env.PHASEONE_VIEWER_EMAILS = 'viewer@localhost';
    process.env.PHASEONE_ADMIN_EMAILS = 'admin@veracityintegrity.com';
    __testResetAuthState();
    const cfg = loadAuthConfig();
    expect(isEmailAllowlisted('viewer@localhost', cfg)).toBe(true);
    await requestOtp('viewer@localhost', cfg);
    const code = __testGetLastOtp()!.code;
    const verified = verifyOtp('viewer@localhost', code, cfg);
    expect(verified.session?.role).toBe('viewer');
    expect(canMutate(verified.session!.role)).toBe(false);
  });

});
