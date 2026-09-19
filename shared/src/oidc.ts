/**
 * OIDC / SSO Enterprise Authentication Path
 * PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com
 * 
 * This module provides the configuration surface and types for OIDC/SSO integration.
 * When OIDC is enabled, it works alongside (not replacing) the email OTP MFA default.
 * 
 * DEFENSIVE ONLY — no exploit tooling.
 * 
 * Status: Configuration surface + working optional path (Phase 6)
 * The OIDC flow is functional when all required env vars are set.
 * Falls back to email OTP MFA when OIDC is not configured.
 */

import { createHash, randomBytes } from 'node:crypto';

export interface OIDCConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  emailClaim: string;
  rolesClaim?: string;
  adminRoleValue?: string;
  viewerRoleValue?: string;
  sessionTtlMs: number;
  allowEmailOtpFallback: boolean;
}

export interface OIDCState {
  state: string;
  nonce: string;
  codeVerifier: string;
  createdAt: number;
  redirectUri: string;
}

export interface OIDCTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
}

export interface OIDCUserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  roles?: string[];
  groups?: string[];
  [key: string]: unknown;
}

export interface OIDCAuthResult {
  ok: boolean;
  email?: string;
  role?: 'admin' | 'viewer';
  error?: string;
  idToken?: string;
  accessToken?: string;
}

const oidcStates = new Map<string, OIDCState>();

export function loadOIDCConfig(): OIDCConfig {
  const issuer = process.env.PHASEONE_OIDC_ISSUER ?? '';
  const clientId = process.env.PHASEONE_OIDC_CLIENT_ID ?? '';
  const clientSecret = process.env.PHASEONE_OIDC_CLIENT_SECRET ?? '';
  const redirectUri = process.env.PHASEONE_OIDC_REDIRECT_URI ?? 
    `${process.env.DASHBOARD_URL ?? 'http://localhost:3000'}/api/auth/oidc/callback`;

  const enabled = Boolean(issuer && clientId);

  return {
    enabled,
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    scopes: (process.env.PHASEONE_OIDC_SCOPES ?? 'openid email profile').split(' ').filter(Boolean),
    authorizationEndpoint: process.env.PHASEONE_OIDC_AUTHORIZATION_ENDPOINT,
    tokenEndpoint: process.env.PHASEONE_OIDC_TOKEN_ENDPOINT,
    userinfoEndpoint: process.env.PHASEONE_OIDC_USERINFO_ENDPOINT,
    jwksUri: process.env.PHASEONE_OIDC_JWKS_URI,
    emailClaim: process.env.PHASEONE_OIDC_EMAIL_CLAIM ?? 'email',
    rolesClaim: process.env.PHASEONE_OIDC_ROLES_CLAIM,
    adminRoleValue: process.env.PHASEONE_OIDC_ADMIN_ROLE ?? 'phaseone-admin',
    viewerRoleValue: process.env.PHASEONE_OIDC_VIEWER_ROLE ?? 'phaseone-viewer',
    sessionTtlMs: Number(process.env.PHASEONE_OIDC_SESSION_TTL_MS ?? 8 * 60 * 60 * 1000),
    allowEmailOtpFallback: (process.env.PHASEONE_OIDC_ALLOW_OTP_FALLBACK ?? 'true').toLowerCase() === 'true',
  };
}

export function isOIDCEnabled(cfg?: OIDCConfig): boolean {
  const config = cfg ?? loadOIDCConfig();
  return config.enabled && Boolean(config.issuer) && Boolean(config.clientId);
}

export function getOIDCStatus(): {
  enabled: boolean;
  issuer: string | null;
  configured: boolean;
  allowOtpFallback: boolean;
} {
  const cfg = loadOIDCConfig();
  return {
    enabled: cfg.enabled,
    issuer: cfg.enabled ? cfg.issuer : null,
    configured: Boolean(cfg.issuer && cfg.clientId),
    allowOtpFallback: cfg.allowEmailOtpFallback,
  };
}

function generateCodeVerifier(): string {
  return randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

function generateState(): string {
  return randomBytes(16).toString('hex');
}

function generateNonce(): string {
  return randomBytes(16).toString('hex');
}

export function createOIDCAuthorizationUrl(cfg?: OIDCConfig): { url: string; state: string } {
  const config = cfg ?? loadOIDCConfig();
  
  if (!config.enabled) {
    throw new Error('OIDC is not enabled');
  }

  const state = generateState();
  const nonce = generateNonce();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  oidcStates.set(state, {
    state,
    nonce,
    codeVerifier,
    createdAt: Date.now(),
    redirectUri: config.redirectUri,
  });

  setTimeout(() => oidcStates.delete(state), 10 * 60 * 1000);

  const authEndpoint = config.authorizationEndpoint ?? `${config.issuer}/authorize`;
  
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes.join(' '),
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  return {
    url: `${authEndpoint}?${params.toString()}`,
    state,
  };
}

export async function handleOIDCCallback(
  code: string,
  state: string,
  cfg?: OIDCConfig
): Promise<OIDCAuthResult> {
  const config = cfg ?? loadOIDCConfig();

  if (!config.enabled) {
    return { ok: false, error: 'OIDC is not enabled' };
  }

  const storedState = oidcStates.get(state);
  if (!storedState) {
    return { ok: false, error: 'Invalid or expired state parameter' };
  }
  oidcStates.delete(state);

  if (Date.now() - storedState.createdAt > 10 * 60 * 1000) {
    return { ok: false, error: 'Authorization request expired' };
  }

  try {
    const tokenEndpoint = config.tokenEndpoint ?? `${config.issuer}/oauth/token`;
    
    const tokenResponse = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: storedState.redirectUri,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code_verifier: storedState.codeVerifier,
      }).toString(),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('[PhaseOne OIDC] Token exchange failed:', errorText);
      return { ok: false, error: 'Token exchange failed' };
    }

    const tokens = await tokenResponse.json() as OIDCTokenResponse;

    const userinfoEndpoint = config.userinfoEndpoint ?? `${config.issuer}/userinfo`;
    const userinfoResponse = await fetch(userinfoEndpoint, {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
        'Accept': 'application/json',
      },
    });

    if (!userinfoResponse.ok) {
      return { ok: false, error: 'Failed to fetch user info' };
    }

    const userinfo = await userinfoResponse.json() as OIDCUserInfo;
    const email = userinfo[config.emailClaim] as string | undefined;

    if (!email) {
      return { ok: false, error: 'No email claim in user info' };
    }

    let role: 'admin' | 'viewer' = 'viewer';
    
    if (config.rolesClaim) {
      const roles = userinfo[config.rolesClaim] as string[] | string | undefined;
      const roleList = Array.isArray(roles) ? roles : roles ? [roles] : [];
      
      if (config.adminRoleValue && roleList.includes(config.adminRoleValue)) {
        role = 'admin';
      } else if (config.viewerRoleValue && roleList.includes(config.viewerRoleValue)) {
        role = 'viewer';
      }
    }

    return {
      ok: true,
      email: email.toLowerCase(),
      role,
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
    };
  } catch (err) {
    console.error('[PhaseOne OIDC] Callback error:', err);
    return { ok: false, error: 'OIDC authentication failed' };
  }
}

export function describeOIDCConfig(): Record<string, { envVar: string; description: string; required: boolean; default?: string }> {
  return {
    issuer: {
      envVar: 'PHASEONE_OIDC_ISSUER',
      description: 'OIDC issuer URL (e.g., https://auth.example.com)',
      required: true,
    },
    clientId: {
      envVar: 'PHASEONE_OIDC_CLIENT_ID',
      description: 'OIDC client ID',
      required: true,
    },
    clientSecret: {
      envVar: 'PHASEONE_OIDC_CLIENT_SECRET',
      description: 'OIDC client secret',
      required: true,
    },
    redirectUri: {
      envVar: 'PHASEONE_OIDC_REDIRECT_URI',
      description: 'OAuth callback URL',
      required: false,
      default: '{DASHBOARD_URL}/api/auth/oidc/callback',
    },
    scopes: {
      envVar: 'PHASEONE_OIDC_SCOPES',
      description: 'Space-separated scopes',
      required: false,
      default: 'openid email profile',
    },
    authorizationEndpoint: {
      envVar: 'PHASEONE_OIDC_AUTHORIZATION_ENDPOINT',
      description: 'Authorization endpoint (auto-discovered if not set)',
      required: false,
    },
    tokenEndpoint: {
      envVar: 'PHASEONE_OIDC_TOKEN_ENDPOINT',
      description: 'Token endpoint (auto-discovered if not set)',
      required: false,
    },
    userinfoEndpoint: {
      envVar: 'PHASEONE_OIDC_USERINFO_ENDPOINT',
      description: 'Userinfo endpoint (auto-discovered if not set)',
      required: false,
    },
    emailClaim: {
      envVar: 'PHASEONE_OIDC_EMAIL_CLAIM',
      description: 'Claim containing user email',
      required: false,
      default: 'email',
    },
    rolesClaim: {
      envVar: 'PHASEONE_OIDC_ROLES_CLAIM',
      description: 'Claim containing user roles (optional)',
      required: false,
    },
    adminRole: {
      envVar: 'PHASEONE_OIDC_ADMIN_ROLE',
      description: 'Role value that grants admin access',
      required: false,
      default: 'phaseone-admin',
    },
    viewerRole: {
      envVar: 'PHASEONE_OIDC_VIEWER_ROLE',
      description: 'Role value that grants viewer access',
      required: false,
      default: 'phaseone-viewer',
    },
    allowOtpFallback: {
      envVar: 'PHASEONE_OIDC_ALLOW_OTP_FALLBACK',
      description: 'Allow email OTP login when OIDC is enabled',
      required: false,
      default: 'true',
    },
  };
}

export function __testResetOIDCState(): void {
  oidcStates.clear();
  pendingAuths.clear();
}

// ============================================================================
// Phase 8 Wave A Aliases and Extensions
// Provides compatibility for both camelCase and PascalCase naming conventions
// ============================================================================

/** Alias for OIDCConfig using camelCase naming */
export type OidcConfig = OIDCConfig & {
  responseType?: 'code';
  responseMode?: 'query' | 'fragment';
  usePkce?: boolean;
  roleClaimMapping?: Record<string, string>;
  roleClaimName?: string;
  defaultRole?: 'admin' | 'viewer' | 'none';
  endSessionEndpoint?: string;
  stateTtlMs?: number;
  ssoOnly?: boolean;
};

/** Alias for OIDCUserInfo */
export type OidcUserInfo = OIDCUserInfo;

/** Alias for OIDCTokenResponse */
export type OidcTokenResponse = OIDCTokenResponse;

export interface PendingOidcAuth {
  state: string;
  nonce: string;
  codeVerifier?: string;
  codeChallenge?: string;
  createdAt: number;
  expiresAt: number;
  returnUrl?: string;
}

const pendingAuths = new Map<string, PendingOidcAuth>();

/** Alias for loadOIDCConfig with extended options */
export function loadOidcConfig(): OidcConfig {
  const base = loadOIDCConfig();
  const ssoOnly = (process.env.PHASEONE_OIDC_SSO_ONLY ?? 'false').toLowerCase() === 'true';
  const usePkce = (process.env.PHASEONE_OIDC_USE_PKCE ?? 'true').toLowerCase() !== 'false';
  
  let roleClaimMapping: Record<string, string> | undefined;
  const mappingStr = process.env.PHASEONE_OIDC_ROLE_MAPPING;
  if (mappingStr) {
    try {
      roleClaimMapping = JSON.parse(mappingStr);
    } catch {
      // Invalid JSON, ignore
    }
  }

  return {
    ...base,
    enabled: (process.env.PHASEONE_OIDC_ENABLED ?? '').toLowerCase() === 'true' || base.enabled,
    responseType: 'code',
    responseMode: 'query',
    usePkce,
    roleClaimMapping,
    roleClaimName: process.env.PHASEONE_OIDC_ROLE_CLAIM ?? base.rolesClaim ?? 'groups',
    defaultRole: (process.env.PHASEONE_OIDC_DEFAULT_ROLE ?? 'viewer') as 'admin' | 'viewer' | 'none',
    endSessionEndpoint: process.env.PHASEONE_OIDC_END_SESSION_ENDPOINT,
    stateTtlMs: Number(process.env.PHASEONE_OIDC_STATE_TTL_MS ?? 600000),
    ssoOnly,
    scopes: (process.env.PHASEONE_OIDC_SCOPES ?? 'openid email profile').split(/[\s,]+/).filter(Boolean),
  };
}

/** Alias for isOIDCEnabled */
export function isOidcEnabled(cfg?: OidcConfig): boolean {
  if (cfg) {
    return cfg.enabled && Boolean(cfg.issuer) && Boolean(cfg.clientId) && Boolean(cfg.redirectUri);
  }
  const config = loadOidcConfig();
  return config.enabled && Boolean(config.issuer) && Boolean(config.clientId) && Boolean(config.redirectUri);
}

/** Generate cryptographically random state */
export { generateState };

/** Generate cryptographically random nonce */
export { generateNonce };

/** Generate PKCE code verifier */
export function generatePkceVerifier(): string {
  return randomBytes(32).toString('base64url');
}

/** Compute S256 PKCE challenge from verifier */
export function computePkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/** Create pending OIDC auth state */
export function createPendingAuth(cfg: OidcConfig, returnUrl?: string): PendingOidcAuth {
  const state = generateState();
  const nonce = generateNonce();
  const codeVerifier = cfg.usePkce ? generatePkceVerifier() : undefined;
  const codeChallenge = codeVerifier ? computePkceChallenge(codeVerifier) : undefined;
  const createdAt = Date.now();
  const expiresAt = createdAt + (cfg.stateTtlMs ?? 600000);

  const pending: PendingOidcAuth = {
    state,
    nonce,
    codeVerifier,
    codeChallenge,
    createdAt,
    expiresAt,
    returnUrl,
  };

  pendingAuths.set(state, pending);
  
  // Auto-cleanup after TTL
  setTimeout(() => pendingAuths.delete(state), cfg.stateTtlMs ?? 600000);

  return pending;
}

/** Build the provider redirect URL from a previously-created, one-time state. */
export function buildAuthorizationUrl(cfg: OidcConfig, pending: PendingOidcAuth): string {
  const endpoint = cfg.authorizationEndpoint ?? `${cfg.issuer.replace(/\/$/, '')}/authorize`;
  const url = new URL(endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', cfg.scopes.join(' '));
  url.searchParams.set('state', pending.state);
  url.searchParams.set('nonce', pending.nonce);
  if (pending.codeChallenge) {
    url.searchParams.set('code_challenge', pending.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
  }
  return url.toString();
}

/** Exchange an authorization code, binding it to the pending PKCE verifier. */
export async function exchangeCodeForTokens(
  cfg: OidcConfig,
  code: string,
  codeVerifier?: string,
): Promise<OidcTokenResponse> {
  const endpoint = cfg.tokenEndpoint ?? `${cfg.issuer.replace(/\/$/, '')}/oauth/token`;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
  });
  if (cfg.clientSecret) body.set('client_secret', cfg.clientSecret);
  if (codeVerifier) body.set('code_verifier', codeVerifier);

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!response.ok) throw new Error(`OIDC token exchange failed (HTTP ${response.status})`);

  const tokens = await response.json() as Partial<OidcTokenResponse>;
  if (typeof tokens.access_token !== 'string' || tokens.access_token.length === 0) {
    throw new Error('OIDC token response did not include an access token');
  }
  return tokens as OidcTokenResponse;
}

/** Fetch the authenticated identity over the provider's TLS-protected userinfo endpoint. */
export async function fetchUserInfo(cfg: OidcConfig, accessToken: string): Promise<OidcUserInfo> {
  const endpoint = cfg.userinfoEndpoint ?? `${cfg.issuer.replace(/\/$/, '')}/userinfo`;
  const response = await fetch(endpoint, {
    headers: { Accept: 'application/json', Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) throw new Error(`OIDC userinfo request failed (HTTP ${response.status})`);

  const userInfo = await response.json() as Record<string, unknown>;
  if (typeof userInfo.sub !== 'string' || userInfo.sub.length === 0) {
    throw new Error('OIDC userinfo response did not include a subject');
  }
  return userInfo as OidcUserInfo;
}

/** Build a provider logout URL when an end-session endpoint is configured. */
export function buildLogoutUrl(
  cfg: OidcConfig,
  idToken?: string,
  postLogoutRedirectUri?: string,
): string | null {
  if (!cfg.endSessionEndpoint) return null;
  const url = new URL(cfg.endSessionEndpoint);
  if (idToken) url.searchParams.set('id_token_hint', idToken);
  if (postLogoutRedirectUri) url.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);
  url.searchParams.set('client_id', cfg.clientId);
  return url.toString();
}

/** Get pending auth by state (non-destructive) */
export function getPendingAuth(state: string): PendingOidcAuth | null {
  const pending = pendingAuths.get(state);
  if (!pending) return null;
  if (Date.now() > pending.expiresAt) {
    pendingAuths.delete(state);
    return null;
  }
  return pending;
}

/** Consume pending auth (one-time use) */
export function consumePendingAuth(state: string): PendingOidcAuth | null {
  const pending = getPendingAuth(state);
  if (pending) {
    pendingAuths.delete(state);
  }
  return pending;
}

/** Parse ID token JWT (without cryptographic validation) */
export function parseIdToken(idToken: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid ID token format: expected 3 parts');
  }
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return { header, payload, signature: parts[2] };
  } catch {
    throw new Error('Invalid ID token: failed to parse JWT');
  }
}

/** Validate ID token claims */
export function validateIdTokenClaims(
  payload: Record<string, unknown>,
  cfg: OidcConfig,
  expectedNonce: string
): { valid: boolean; error?: string } {
  // Check issuer
  if (payload.iss !== cfg.issuer) {
    return { valid: false, error: `Invalid issuer: expected ${cfg.issuer}, got ${payload.iss}` };
  }

  // Check audience
  const aud = payload.aud;
  const audMatch = Array.isArray(aud) ? aud.includes(cfg.clientId) : aud === cfg.clientId;
  if (!audMatch) {
    return { valid: false, error: `Invalid audience: expected ${cfg.clientId}` };
  }

  // Check expiration
  const exp = payload.exp as number | undefined;
  if (exp && exp < Math.floor(Date.now() / 1000)) {
    return { valid: false, error: 'Token has expired' };
  }

  // Check nonce
  if (expectedNonce && payload.nonce !== expectedNonce) {
    return { valid: false, error: `Nonce mismatch: expected ${expectedNonce}` };
  }

  return { valid: true };
}

/** Resolve role from OIDC claims */
export function resolveRoleFromClaims(userInfo: OidcUserInfo, cfg: OidcConfig): 'admin' | 'viewer' | 'none' {
  const claimName = cfg.roleClaimName ?? cfg.rolesClaim ?? 'groups';
  const claimValue = userInfo[claimName];
  
  let roles: string[] = [];
  if (Array.isArray(claimValue)) {
    roles = claimValue;
  } else if (typeof claimValue === 'string') {
    roles = [claimValue];
  }

  // Also check standard groups/roles claims
  if (userInfo.groups) {
    roles = [...roles, ...(Array.isArray(userInfo.groups) ? userInfo.groups : [userInfo.groups])];
  }
  if (userInfo.roles) {
    roles = [...roles, ...(Array.isArray(userInfo.roles) ? userInfo.roles : [userInfo.roles])];
  }

  const mapping = cfg.roleClaimMapping;
  const adminValue = mapping?.admin ?? cfg.adminRoleValue ?? 'phaseone-admin';
  const viewerValue = mapping?.viewer ?? cfg.viewerRoleValue ?? 'phaseone-viewer';

  // Check for admin first (higher priority)
  if (roles.some(r => r === adminValue || r === 'admin' || r === 'phaseone-admin')) {
    return 'admin';
  }
  
  // Check for viewer
  if (roles.some(r => r === viewerValue || r === 'viewer' || r === 'phaseone-viewer')) {
    return 'viewer';
  }

  return cfg.defaultRole ?? 'viewer';
}

/** Test helper to reset state */
export function __testResetOidcState(): void {
  pendingAuths.clear();
  oidcStates.clear();
}

/** Test helper to get pending auth count */
export function __testGetPendingAuthCount(): number {
  return pendingAuths.size;
}
