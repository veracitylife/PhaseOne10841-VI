/**
 * Dashboard MFA — email one-time verification codes + OIDC/SSO.
 * DEFENSIVE admin gate only. No real secrets committed.
 *
 * Lab/CI only: when SMTP is unset, OTP is logged to console + PHASEONE_OTP_FALLBACK_FILE
 * with a loud warning. Production must use SMTP (From: noreply@clovisstar.com).
 * 
 * OIDC/SSO: Optional enterprise SSO via Okta, Azure AD, Auth0, etc.
 * Configure via PHASEONE_OIDC_* env vars. See docs/oidc-setup.md.
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
import {
  loadOidcConfig,
  isOidcEnabled,
  createPendingAuth,
  consumePendingAuth,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  fetchUserInfo,
  resolveRoleFromClaims,
  buildLogoutUrl,
  type OidcConfig,
  type OidcUserInfo,
} from '../../shared/src/oidc.js';

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
  /** Auth method: 'otp' for email OTP, 'oidc' for SSO */
  authMethod?: 'otp' | 'oidc';
  /** OIDC IdP subject identifier */
  idpSubject?: string;
  /** OIDC ID token for logout */
  idToken?: string;
  /** OIDC user info */
  oidcUserInfo?: OidcUserInfo;
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
          from: process.env.SMTP_FROM ?? 'noreply@clovisstar.com',
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
  const subject = 'PhaseOne10841 MFA verification code (Veracity Integrity)';
  const body = [
    'PhaseOne10841 — Defensive Agent Security Gateway',
    'Veracity Integrity LLC · https://VeracityIntegrity.com',
    'Sender: noreply@clovisstar.com (Clovis Star / Veracity SMTP path)',
    '',
    `Your one-time MFA verification code is: ${code}`,
    '',
    'This code expires in 10 minutes.',
    'If you did not request dashboard access, ignore this message and notify your operator.',
    '',
    'Do not forward this code. PhaseOne never asks for your password.',
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
  console.warn(
    '[PhaseOne MFA] ⚠ LAB-ONLY OTP FALLBACK — not for production. ' +
      'Configure SMTP_HOST and SMTP_FROM=noreply@clovisstar.com for real MFA email delivery. ' +
      `Reason: ${reason}`
  );
  const line = `[${new Date().toISOString()}] PhaseOne10841 OTP for ${email}: ${code} (${reason})\n`;
  console.log(`[PhaseOne MFA] ${line.trim()}`);
  try {
    mkdirSync(dirname(cfg.otpFallbackFile), { recursive: true });
    appendFileSync(cfg.otpFallbackFile, line, 'utf8');
  } catch (err) {
    console.warn('[PhaseOne MFA] could not write OTP fallback file', err);
  }
}

/** Very small SMTP client for STARTTLS-less / optional auth send. */
async function sendSmtpMail(
  cfg: AuthConfig,
  to: string,
  subject: string,
  text: string
): Promise<void> {
  const net = await import('node:net');
  const smtp = cfg.smtp!;
  await new Promise<void>((resolve, reject) => {
    const socket = net.createConnection({ host: smtp.host, port: smtp.port }, () => {
      const lines: string[] = [];
      const send = (cmd: string) => socket.write(cmd + '\r\n');
      socket.on('data', (buf) => {
        lines.push(buf.toString('utf8'));
        const all = lines.join('');
        if (all.includes('220') && !all.includes('HELO')) {
          send(`HELO phaseone.local`);
          if (smtp.user && smtp.pass) {
            // AUTH PLAIN
            const token = Buffer.from(`\0${smtp.user}\0${smtp.pass}`).toString('base64');
            send(`AUTH PLAIN ${token}`);
          }
          send(`MAIL FROM:<${smtp.from}>`);
          send(`RCPT TO:<${to}>`);
          send('DATA');
          send(
            [
              `From: ${smtp.from}`,
              `To: ${to}`,
              `Subject: ${subject}`,
              'Content-Type: text/plain; charset=utf-8',
              '',
              text,
              '.',
            ].join('\r\n')
          );
          send('QUIT');
        }
      });
      socket.on('end', () => resolve());
      socket.on('error', reject);
      setTimeout(() => {
        socket.destroy();
        resolve();
      }, 8000);
    });
    socket.on('error', reject);
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

export interface CreateSessionOptions {
  authMethod?: 'otp' | 'oidc';
  idpSubject?: string;
  idToken?: string;
  oidcUserInfo?: OidcUserInfo;
  roleOverride?: DashboardRole;
}

export function createSession(
  email: string,
  cfg = loadAuthConfig(),
  opts: CreateSessionOptions = {}
): SessionRecord {
  const id = randomBytes(24).toString('hex');
  const csrfToken = randomBytes(16).toString('hex');
  const role = opts.roleOverride ?? roleForEmail(email, cfg);
  const rec: SessionRecord = {
    id,
    email: email.toLowerCase(),
    role: role === 'none' ? 'viewer' : role,
    createdAt: Date.now(),
    expiresAt: Date.now() + cfg.sessionTtlMs,
    csrfToken,
    authMethod: opts.authMethod ?? 'otp',
    idpSubject: opts.idpSubject,
    idToken: opts.idToken,
    oidcUserInfo: opts.oidcUserInfo,
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

/**
 * OIDC/SSO Authentication
 */

export { loadOidcConfig, isOidcEnabled } from '../../shared/src/oidc.js';
export type { OidcConfig, OidcUserInfo } from '../../shared/src/oidc.js';

export interface OidcAuthInitResult {
  ok: boolean;
  authUrl?: string;
  error?: string;
}

export async function initiateOidcAuth(returnUrl?: string): Promise<OidcAuthInitResult> {
  const cfg = loadOidcConfig();
  if (!isOidcEnabled(cfg)) {
    return { ok: false, error: 'OIDC is not configured' };
  }
  try {
    const pending = createPendingAuth(cfg, returnUrl);
    const authUrl = await buildAuthorizationUrl(cfg, pending);
    return { ok: true, authUrl };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'Failed to initiate OIDC auth' };
  }
}

export interface OidcCallbackResult {
  ok: boolean;
  session?: SessionRecord;
  error?: string;
  returnUrl?: string;
}

export async function handleOidcCallback(
  code: string,
  state: string,
  authCfg = loadAuthConfig()
): Promise<OidcCallbackResult> {
  const oidcCfg = loadOidcConfig();
  if (!isOidcEnabled(oidcCfg)) {
    return { ok: false, error: 'OIDC is not configured' };
  }

  // Validate and consume pending auth state
  const pending = consumePendingAuth(state);
  if (!pending) {
    return { ok: false, error: 'Invalid or expired state parameter' };
  }

  try {
    // Exchange authorization code for tokens
    const tokens = await exchangeCodeForTokens(oidcCfg, code, pending.codeVerifier);

    // Use the TLS-protected userinfo response for identity and authorization.
    // The ID token is retained only as a logout hint; parsing its claims without
    // signature verification must never establish a dashboard session.
    const userInfo: OidcUserInfo = await fetchUserInfo(oidcCfg, tokens.access_token);
    const idToken = tokens.id_token;

    // Extract email from userinfo
    const email = userInfo.email ?? userInfo.preferred_username ?? userInfo.sub;
    if (!email) {
      return { ok: false, error: 'No email found in IdP response' };
    }

    // Resolve role from IdP claims (priority) or fallback to email-based role
    let role = resolveRoleFromClaims(userInfo, oidcCfg);
    
    // If OIDC SSO-only mode is not enabled, verify email is in allowlist
    if (!(oidcCfg.ssoOnly ?? false)) {
      if (!isEmailAllowlisted(email, authCfg)) {
        return { ok: false, error: 'Email not authorized for dashboard access' };
      }
      // Use email-based role if no role found from claims
      if (role === 'none') {
        role = roleForEmail(email, authCfg);
      }
    }

    // Ensure at minimum a viewer role
    if (role === 'none') {
      role = oidcCfg.defaultRole ?? 'viewer';
    }

    // Create session with OIDC metadata
    const session = createSession(email, authCfg, {
      authMethod: 'oidc',
      idpSubject: userInfo.sub,
      idToken,
      oidcUserInfo: userInfo,
      roleOverride: role,
    });

    return {
      ok: true,
      session,
      returnUrl: pending.returnUrl,
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'OIDC callback failed' };
  }
}

export interface OidcLogoutResult {
  ok: boolean;
  logoutUrl?: string;
  error?: string;
}

export async function handleOidcLogout(
  sessionId: string,
  postLogoutRedirectUri?: string
): Promise<OidcLogoutResult> {
  const session = getSession(sessionId);
  if (!session) {
    return { ok: true }; // Already logged out
  }

  const oidcCfg = loadOidcConfig();
  
  // Destroy local session first
  destroySession(sessionId);

  // If this was an OIDC session, try to build IdP logout URL
  if (session.authMethod === 'oidc' && isOidcEnabled(oidcCfg)) {
    try {
      const logoutUrl = await buildLogoutUrl(oidcCfg, session.idToken, postLogoutRedirectUri);
      if (logoutUrl) {
        return { ok: true, logoutUrl };
      }
    } catch (err) {
      console.warn('[PhaseOne OIDC] Failed to build logout URL:', err);
    }
  }

  return { ok: true };
}

export function getOidcStatus(): {
  enabled: boolean;
  issuer?: string;
  ssoOnly: boolean;
  hasPkce: boolean;
} {
  const cfg = loadOidcConfig();
  return {
    enabled: isOidcEnabled(cfg),
    issuer: cfg.issuer || undefined,
    ssoOnly: cfg.ssoOnly ?? false,
    hasPkce: cfg.usePkce ?? false,
  };
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

export function __testGetSession(sessionId: string): SessionRecord | null {
  return sessions.get(sessionId) ?? null;
}
