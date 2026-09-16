/**
 * Dashboard MFA — email one-time verification codes.
 * DEFENSIVE admin gate only. No real secrets committed.
 *
 * Dev/CI: when SMTP is unset, OTP is logged to console + PHASEONE_OTP_FALLBACK_FILE.
 */

import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  loadRbacConfig,
  resolveRole,
  isAuthorizedEmail,
  type DashboardRole,
} from '../../shared/src/rbac.js';

export interface AuthConfig {
  enabled: boolean;
  /** Comma-separated allowlist of admin emails */
  allowlist: string[];
  /** Viewer emails (read-only) */
  viewerAllowlist: string[];
  sessionTtlMs: number;
  otpTtlMs: number;
  otpLength: number;
  maxOtpAttempts: number;
  rateLimitWindowMs: number;
  rateLimitMax: number;
  cookieName: string;
  csrfCookieName: string;
  secureCookies: boolean;
  smtp?: {
    host: string;
    port: number;
    user?: string;
    pass?: string;
    from: string;
    secure?: boolean;
  };
  otpFallbackFile: string;
  /** Test-only: expose last OTP for harness */
  testMode: boolean;
}

export interface SessionRecord {
  id: string;
  email: string;
  role: DashboardRole;
  createdAt: number;
  expiresAt: number;
  csrfToken: string;
}

export interface OtpRecord {
  email: string;
  codeHash: string;
  createdAt: number;
  expiresAt: number;
  attempts: number;
  /** Only populated in testMode */
  codePlain?: string;
}

const sessions = new Map<string, SessionRecord>();
const otps = new Map<string, OtpRecord>();
const rateHits = new Map<string, number[]>();

/** Last issued OTP for CI harness when testMode */
let lastTestOtp: { email: string; code: string; at: number } | null = null;

export function loadAuthConfig(): AuthConfig {
  const rbac = loadRbacConfig();
  const allow = rbac.adminEmails;
  const viewers = rbac.viewerEmails;
  const smtpHost = process.env.SMTP_HOST ?? '';
  return {
    enabled: (process.env.PHASEONE_DASHBOARD_AUTH ?? 'true').toLowerCase() !== 'false',
    allowlist: allow,
    viewerAllowlist: viewers,
    sessionTtlMs: Number(process.env.PHASEONE_SESSION_TTL_MS ?? 8 * 60 * 60 * 1000),
    otpTtlMs: Number(process.env.PHASEONE_OTP_TTL_MS ?? 10 * 60 * 1000),
    otpLength: 6,
    maxOtpAttempts: 5,
    rateLimitWindowMs: Number(process.env.PHASEONE_OTP_RATE_WINDOW_MS ?? 15 * 60 * 1000),
    rateLimitMax: Number(process.env.PHASEONE_OTP_RATE_LIMIT ?? 5),
    cookieName: 'phaseone_session',
    csrfCookieName: 'phaseone_csrf',
    secureCookies: (process.env.PHASEONE_SECURE_COOKIES ?? 'false').toLowerCase() === 'true',
    smtp: smtpHost
      ? {
          host: smtpHost,
          port: Number(process.env.SMTP_PORT ?? 587),
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
          from: process.env.SMTP_FROM ?? 'noreply@veracityintegrity.com',
          secure: (process.env.SMTP_SECURE ?? 'false').toLowerCase() === 'true',
        }
      : undefined,
    otpFallbackFile: process.env.PHASEONE_OTP_FALLBACK_FILE ?? '/tmp/phaseone-otp.log',
    testMode: (process.env.PHASEONE_AUTH_TEST_MODE ?? '').toLowerCase() === 'true',
  };
}

function hashCode(code: string, email: string): string {
  return createHash('sha256').update(`${email.toLowerCase()}:${code}`).digest('hex');
}

function safeEqualHex(a: string, b: string): boolean {
  try {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length !== bb.length) return false;
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

export function isEmailAllowlisted(email: string, cfg = loadAuthConfig()): boolean {
  return isAuthorizedEmail(email, {
    adminEmails: cfg.allowlist,
    viewerEmails: cfg.viewerAllowlist,
    allowAllAdminsWildcard: cfg.allowlist.includes('*'),
  });
}

export function roleForEmail(email: string, cfg = loadAuthConfig()): DashboardRole {
  return resolveRole(email, {
    adminEmails: cfg.allowlist,
    viewerEmails: cfg.viewerAllowlist,
    allowAllAdminsWildcard: cfg.allowlist.includes('*'),
  });
}

export function checkOtpRateLimit(email: string, cfg = loadAuthConfig()): { ok: boolean; retryAfterMs?: number } {
  const key = email.toLowerCase();
  const now = Date.now();
  const window = cfg.rateLimitWindowMs;
  const hits = (rateHits.get(key) ?? []).filter((t) => now - t < window);
  rateHits.set(key, hits);
  if (hits.length >= cfg.rateLimitMax) {
    const oldest = hits[0];
    return { ok: false, retryAfterMs: window - (now - oldest) };
  }
  return { ok: true };
}

function recordRateHit(email: string): void {
  const key = email.toLowerCase();
  const hits = rateHits.get(key) ?? [];
  hits.push(Date.now());
  rateHits.set(key, hits);
}

function generateOtp(length: number): string {
  let code = '';
  for (let i = 0; i < length; i++) code += String(randomInt(0, 10));
  return code;
}

async function deliverOtp(
  email: string,
  code: string,
  cfg: AuthConfig
): Promise<{ channel: 'smtp' | 'fallback'; detail: string }> {
  const subject = 'PhaseOne10841 admin verification code';
  const body = [
    'PhaseOne10841 — Veracity Integrity LLC',
    'https://VeracityIntegrity.com',
    '',
    `Your one-time admin verification code is: ${code}`,
    '',
    'This code expires in 10 minutes. If you did not request it, ignore this message.',
  ].join('\n');

  if (cfg.smtp?.host) {
    // Minimal SMTP via Node net — avoid heavy deps; fail open to fallback on error
    try {
      await sendSmtpMail(cfg, email, subject, body);
      return { channel: 'smtp', detail: `sent via SMTP ${cfg.smtp.host}` };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'smtp failed';
      writeFallback(email, code, cfg, `SMTP failed: ${msg}`);
      return { channel: 'fallback', detail: `SMTP failed; logged to ${cfg.otpFallbackFile}` };
    }
  }

  writeFallback(email, code, cfg, 'SMTP not configured');
  return { channel: 'fallback', detail: `logged to ${cfg.otpFallbackFile}` };
}

function writeFallback(email: string, code: string, cfg: AuthConfig, reason: string): void {
  const line = `[${new Date().toISOString()}] PhaseOne10841 OTP for ${email}: ${code} (${reason})\n`;
  console.log(`[PhaseOne MFA] ${line.trim()}`);
  try {
    mkdirSync(dirname(cfg.otpFallbackFile), { recursive: true });
    appendFileSync(cfg.otpFallbackFile, line, 'utf8');
  } catch (err) {
    console.warn('[PhaseOne MFA] could not write OTP fallback file', err);
  }
}

async function sendSmtpMail(
  cfg: AuthConfig,
  to: string,
  subject: string,
  text: string
): Promise<void> {
  const net = await import('node:net');
  const tls = await import('node:tls');
  const smtp = cfg.smtp!;
  const host = smtp.host;
  const port = smtp.port;
  const useTls = smtp.secure || port === 465;

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const ok = () => {
      if (settled) return;
      settled = true;
      resolve();
    };

    const onConnected = (socket: import('node:net').Socket) => {
      let buf = '';
      let step:
        | 'greet'
        | 'ehlo'
        | 'user'
        | 'pass'
        | 'mail'
        | 'rcpt'
        | 'data'
        | 'body'
        | 'quit' = 'greet';
      const write = (s: string) => socket.write(s + '\r\n');
      const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

      const timer = setTimeout(() => {
        socket.destroy();
        fail(new Error('SMTP timeout'));
      }, 20000);

      socket.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        const parts = buf.split(/\r?\n/);
        buf = parts.pop() ?? '';
        for (const line of parts) {
          if (step === 'greet' && /^220 /.test(line)) {
            write('EHLO phaseone.local');
            step = 'ehlo';
            continue;
          }
          if (step === 'ehlo' && /^250 /.test(line)) {
            if (smtp.user && smtp.pass) {
              write('AUTH LOGIN');
              step = 'user';
            } else {
              write(`MAIL FROM:<${smtp.from}>`);
              step = 'rcpt';
            }
            continue;
          }
          if (step === 'user' && /^334 /.test(line)) {
            write(b64(smtp.user!));
            step = 'pass';
            continue;
          }
          if (step === 'pass' && /^334 /.test(line)) {
            write(b64(smtp.pass!));
            step = 'mail';
            continue;
          }
          if (step === 'mail') {
            if (/^235 /.test(line)) {
              write(`MAIL FROM:<${smtp.from}>`);
              step = 'rcpt';
              continue;
            }
            if (/^[45]/.test(line)) {
              clearTimeout(timer);
              fail(new Error(`SMTP AUTH failed: ${line}`));
              socket.end();
              return;
            }
          }
          if (step === 'rcpt' && /^250 /.test(line)) {
            write(`RCPT TO:<${to}>`);
            step = 'data';
            continue;
          }
          if (step === 'data' && /^250 /.test(line)) {
            write('DATA');
            step = 'body';
            continue;
          }
          if (step === 'body' && /^354 /.test(line)) {
            write(`From: ${smtp.from}`);
            write(`To: ${to}`);
            write(`Subject: ${subject}`);
            write('Content-Type: text/plain; charset=utf-8');
            write('');
            write(text);
            write('.');
            step = 'quit';
            continue;
          }
          if (step === 'quit' && /^250 /.test(line)) {
            write('QUIT');
            clearTimeout(timer);
            ok();
            socket.end();
            return;
          }
          if (/^[45]\d\d /.test(line) && step !== 'ehlo') {
            clearTimeout(timer);
            fail(new Error(`SMTP error at ${step}: ${line}`));
            socket.end();
            return;
          }
        }
      });
      socket.on('error', (err) => {
        clearTimeout(timer);
        fail(err instanceof Error ? err : new Error(String(err)));
      });
    };

    if (useTls) {
      const socket = tls.connect({ host, port, servername: host }, () => onConnected(socket));
      socket.on('error', (err) => fail(err instanceof Error ? err : new Error(String(err))));
    } else {
      const socket = net.createConnection({ host, port }, () => onConnected(socket));
      socket.on('error', (err) => fail(err instanceof Error ? err : new Error(String(err))));
    }
  });
}

export async function requestOtp(
  emailRaw: string,
  cfg = loadAuthConfig()
): Promise<{ ok: boolean; error?: string; channel?: string; retryAfterMs?: number }> {
  const email = emailRaw.trim().toLowerCase();
  if (!isEmailAllowlisted(email, cfg)) {
    return { ok: false, error: 'email not authorized for dashboard access' };
  }
  const rate = checkOtpRateLimit(email, cfg);
  if (!rate.ok) {
    return { ok: false, error: 'too many OTP requests', retryAfterMs: rate.retryAfterMs };
  }
  recordRateHit(email);

  const code = generateOtp(cfg.otpLength);
  const delivery = await deliverOtp(email, code, cfg);
  otps.set(email, {
    email,
    codeHash: hashCode(code, email),
    createdAt: Date.now(),
    expiresAt: Date.now() + cfg.otpTtlMs,
    attempts: 0,
    codePlain: cfg.testMode ? code : undefined,
  });
  if (cfg.testMode) {
    lastTestOtp = { email, code, at: Date.now() };
  }
  return { ok: true, channel: delivery.channel };
}

export function verifyOtp(
  emailRaw: string,
  codeRaw: string,
  cfg = loadAuthConfig()
): { ok: boolean; session?: SessionRecord; error?: string } {
  const email = emailRaw.trim().toLowerCase();
  const code = codeRaw.trim();
  const rec = otps.get(email);
  if (!rec) return { ok: false, error: 'no pending verification code' };
  if (Date.now() > rec.expiresAt) {
    otps.delete(email);
    return { ok: false, error: 'verification code expired' };
  }
  if (rec.attempts >= cfg.maxOtpAttempts) {
    otps.delete(email);
    return { ok: false, error: 'too many attempts' };
  }
  rec.attempts += 1;
  const candidate = hashCode(code, email);
  if (!safeEqualHex(candidate, rec.codeHash)) {
    return { ok: false, error: 'invalid verification code' };
  }
  otps.delete(email);
  const session = createSession(email, cfg);
  return { ok: true, session };
}

export function createSession(email: string, cfg = loadAuthConfig()): SessionRecord {
  const id = randomBytes(24).toString('hex');
  const csrfToken = randomBytes(16).toString('hex');
  const role = roleForEmail(email, cfg);
  const rec: SessionRecord = {
    id,
    email: email.toLowerCase(),
    role: role === 'none' ? 'viewer' : role,
    createdAt: Date.now(),
    expiresAt: Date.now() + cfg.sessionTtlMs,
    csrfToken,
  };
  sessions.set(id, rec);
  return rec;
}

export function getSession(sessionId: string | undefined | null): SessionRecord | null {
  if (!sessionId) return null;
  const rec = sessions.get(sessionId);
  if (!rec) return null;
  if (Date.now() > rec.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return rec;
}

export function destroySession(sessionId: string): void {
  sessions.delete(sessionId);
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (!k) continue;
    out[k] = decodeURIComponent(rest.join('=') ?? '');
  }
  return out;
}

export function sessionCookieHeader(session: SessionRecord, cfg = loadAuthConfig()): string {
  const parts = [
    `${cfg.cookieName}=${session.id}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(cfg.sessionTtlMs / 1000)}`,
  ];
  if (cfg.secureCookies) parts.push('Secure');
  return parts.join('; ');
}

export function csrfCookieHeader(session: SessionRecord, cfg = loadAuthConfig()): string {
  const parts = [
    `${cfg.csrfCookieName}=${session.csrfToken}`,
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${Math.floor(cfg.sessionTtlMs / 1000)}`,
  ];
  if (cfg.secureCookies) parts.push('Secure');
  return parts.join('; ');
}

export function clearSessionCookies(cfg = loadAuthConfig()): string[] {
  return [
    `${cfg.cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    `${cfg.csrfCookieName}=; Path=/; SameSite=Lax; Max-Age=0`,
  ];
}

export function validateCsrf(
  session: SessionRecord,
  headerToken: string | undefined,
  cookieToken: string | undefined
): boolean {
  if (!headerToken || !cookieToken) return false;
  if (headerToken !== session.csrfToken) return false;
  return cookieToken === session.csrfToken;
}

/** CI harness helpers */
export function __testGetLastOtp(): { email: string; code: string; at: number } | null {
  return lastTestOtp;
}

export function __testResetAuthState(): void {
  sessions.clear();
  otps.clear();
  rateHits.clear();
  lastTestOtp = null;
}

export function __testPeekOtp(email: string): string | undefined {
  return otps.get(email.toLowerCase())?.codePlain;
}
