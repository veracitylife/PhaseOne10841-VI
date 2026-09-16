/**
 * Shared security header defaults for gateway + dashboard.
 * PhaseOne10841 — Veracity Integrity LLC
 */

export const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'X-XSS-Protection': '0',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'X-PhaseOne-Site': 'https://VeracityIntegrity.com',
};

/** CSP suitable for SPA dashboard (inline script in index.html for Phase 5 local) */
export function dashboardContentSecurityPolicy(): string {
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}

export interface CookieSecurityNotes {
  httpOnly: boolean;
  sameSite: 'Lax' | 'Strict' | 'None';
  secure: boolean;
  path: string;
  notes: string[];
}

export function describeCookieDefaults(secureCookies: boolean): CookieSecurityNotes {
  return {
    httpOnly: true,
    sameSite: 'Lax',
    secure: secureCookies,
    path: '/',
    notes: [
      'Session cookie is HttpOnly + SameSite=Lax always.',
      'Set PHASEONE_SECURE_COOKIES=true when serving dashboard over HTTPS (required for Secure flag).',
      'Local HTTP docker compose defaults PHASEONE_SECURE_COOKIES=false so browsers accept the cookie.',
      'CSRF double-submit cookie is NOT HttpOnly (readable by JS for X-CSRF-Token header).',
      'Prefer terminating TLS at a reverse proxy in production-ish local setups.',
    ],
  };
}
