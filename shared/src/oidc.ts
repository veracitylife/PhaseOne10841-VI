/**
 * OIDC/SSO configuration and types.
 * Supports Okta, Azure AD, Auth0, and other standard OIDC providers.
 * DEFENSIVE ONLY — no secrets committed.
 */

import { randomBytes, createHash } from 'node:crypto';

export interface OidcConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  responseType: 'code';
  responseMode: 'query' | 'fragment';
  usePkce: boolean;
  /** Map IdP claim to PhaseOne role: e.g. { admin: 'phaseone-admin', viewer: 'phaseone-viewer' } */
  roleClaimMapping?: Record<string, string>;
  /** IdP claim name containing roles (e.g. 'groups', 'roles', 'phaseone_role') */
  roleClaimName?: string;
  /** Default role if no matching role claim found */
  defaultRole?: 'admin' | 'viewer' | 'none';
  /** Authorization endpoint override (discovered from issuer/.well-known if not set) */
  authorizationEndpoint?: string;
  /** Token endpoint override */
  tokenEndpoint?: string;
  /** Userinfo endpoint override */
  userinfoEndpoint?: string;
  /** End session endpoint for logout (optional) */
  endSessionEndpoint?: string;
  /** JWKS URI for token validation */
  jwksUri?: string;
  /** State/nonce TTL in ms (default 10 minutes) */
  stateTtlMs: number;
  /** Allow SSO-only login (if true, OTP MFA is disabled when OIDC is configured) */
  ssoOnly: boolean;
}

export interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  code_challenge_methods_supported?: string[];
}

export interface OidcTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface OidcUserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  groups?: string[];
  roles?: string[];
  [key: string]: unknown;
}

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
let discoveryCache: { doc: OidcDiscoveryDocument; fetchedAt: number } | null = null;
const DISCOVERY_CACHE_TTL_MS = 3600000; // 1 hour

export function loadOidcConfig(): OidcConfig {
  const enabled = (process.env.PHASEONE_OIDC_ENABLED ?? '').toLowerCase() === 'true';
  const issuer = process.env.PHASEONE_OIDC_ISSUER ?? '';
  const clientId = process.env.PHASEONE_OIDC_CLIENT_ID ?? '';
  const clientSecret = process.env.PHASEONE_OIDC_CLIENT_SECRET ?? '';
  const redirectUri = process.env.PHASEONE_OIDC_REDIRECT_URI ?? '';
  const scopes = (process.env.PHASEONE_OIDC_SCOPES ?? 'openid email profile').split(/[\s,]+/).filter(Boolean);
  const usePkce = (process.env.PHASEONE_OIDC_USE_PKCE ?? 'true').toLowerCase() !== 'false';
  const ssoOnly = (process.env.PHASEONE_OIDC_SSO_ONLY ?? 'false').toLowerCase() === 'true';
  
  let roleClaimMapping: Record<string, string> | undefined;
  const mappingStr = process.env.PHASEONE_OIDC_ROLE_MAPPING;
  if (mappingStr) {
    try {
      roleClaimMapping = JSON.parse(mappingStr);
    } catch {
      console.warn('[PhaseOne OIDC] Invalid PHASEONE_OIDC_ROLE_MAPPING JSON, ignoring');
    }
  }

  return {
    enabled,
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    scopes,
    responseType: 'code',
    responseMode: 'query',
    usePkce,
    roleClaimMapping,
    roleClaimName: process.env.PHASEONE_OIDC_ROLE_CLAIM ?? 'groups',
    defaultRole: (process.env.PHASEONE_OIDC_DEFAULT_ROLE ?? 'viewer') as 'admin' | 'viewer' | 'none',
    authorizationEndpoint: process.env.PHASEONE_OIDC_AUTH_ENDPOINT,
    tokenEndpoint: process.env.PHASEONE_OIDC_TOKEN_ENDPOINT,
    userinfoEndpoint: process.env.PHASEONE_OIDC_USERINFO_ENDPOINT,
    endSessionEndpoint: process.env.PHASEONE_OIDC_END_SESSION_ENDPOINT,
    jwksUri: process.env.PHASEONE_OIDC_JWKS_URI,
    stateTtlMs: Number(process.env.PHASEONE_OIDC_STATE_TTL_MS ?? 600000),
    ssoOnly,
  };
}

export function isOidcEnabled(cfg = loadOidcConfig()): boolean {
  return cfg.enabled && !!cfg.issuer && !!cfg.clientId && !!cfg.redirectUri;
}

export async function fetchDiscoveryDocument(issuer: string): Promise<OidcDiscoveryDocument> {
  if (discoveryCache && Date.now() - discoveryCache.fetchedAt < DISCOVERY_CACHE_TTL_MS) {
    return discoveryCache.doc;
  }
  const url = issuer.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const res = await fetch(url, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) {
    throw new Error(`OIDC discovery failed: ${res.status} ${res.statusText}`);
  }
  const doc = (await res.json()) as OidcDiscoveryDocument;
  discoveryCache = { doc, fetchedAt: Date.now() };
  return doc;
}

export function generateState(): string {
  return randomBytes(24).toString('base64url');
}

export function generateNonce(): string {
  return randomBytes(16).toString('base64url');
}

export function generatePkceVerifier(): string {
  return randomBytes(32).toString('base64url');
}

export function computePkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

export function createPendingAuth(cfg: OidcConfig, returnUrl?: string): PendingOidcAuth {
  const state = generateState();
  const nonce = generateNonce();
  const pending: PendingOidcAuth = {
    state,
    nonce,
    createdAt: Date.now(),
    expiresAt: Date.now() + cfg.stateTtlMs,
    returnUrl,
  };
  if (cfg.usePkce) {
    pending.codeVerifier = generatePkceVerifier();
    pending.codeChallenge = computePkceChallenge(pending.codeVerifier);
  }
  pendingAuths.set(state, pending);
  return pending;
}

export function getPendingAuth(state: string): PendingOidcAuth | null {
  const pending = pendingAuths.get(state);
  if (!pending) return null;
  if (Date.now() > pending.expiresAt) {
    pendingAuths.delete(state);
    return null;
  }
  return pending;
}

export function consumePendingAuth(state: string): PendingOidcAuth | null {
  const pending = getPendingAuth(state);
  if (pending) {
    pendingAuths.delete(state);
  }
  return pending;
}

export async function buildAuthorizationUrl(
  cfg: OidcConfig,
  pending: PendingOidcAuth
): Promise<string> {
  let authEndpoint = cfg.authorizationEndpoint;
  if (!authEndpoint) {
    const discovery = await fetchDiscoveryDocument(cfg.issuer);
    authEndpoint = discovery.authorization_endpoint;
  }
  const params = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    response_type: cfg.responseType,
    response_mode: cfg.responseMode,
    scope: cfg.scopes.join(' '),
    state: pending.state,
    nonce: pending.nonce,
  });
  if (cfg.usePkce && pending.codeChallenge) {
    params.set('code_challenge', pending.codeChallenge);
    params.set('code_challenge_method', 'S256');
  }
  return `${authEndpoint}?${params.toString()}`;
}

export async function exchangeCodeForTokens(
  cfg: OidcConfig,
  code: string,
  codeVerifier?: string
): Promise<OidcTokenResponse> {
  let tokenEndpoint = cfg.tokenEndpoint;
  if (!tokenEndpoint) {
    const discovery = await fetchDiscoveryDocument(cfg.issuer);
    tokenEndpoint = discovery.token_endpoint;
  }

  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    code,
  });

  if (cfg.clientSecret) {
    params.set('client_secret', cfg.clientSecret);
  }
  if (cfg.usePkce && codeVerifier) {
    params.set('code_verifier', codeVerifier);
  }

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: params.toString(),
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    throw new Error(`Token exchange failed: ${res.status} ${errBody.slice(0, 200)}`);
  }

  return (await res.json()) as OidcTokenResponse;
}

export async function fetchUserInfo(
  cfg: OidcConfig,
  accessToken: string
): Promise<OidcUserInfo> {
  let userinfoEndpoint = cfg.userinfoEndpoint;
  if (!userinfoEndpoint) {
    const discovery = await fetchDiscoveryDocument(cfg.issuer);
    userinfoEndpoint = discovery.userinfo_endpoint;
  }
  if (!userinfoEndpoint) {
    throw new Error('No userinfo endpoint available');
  }

  const res = await fetch(userinfoEndpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(10000),
  });

  if (!res.ok) {
    throw new Error(`Userinfo fetch failed: ${res.status}`);
  }

  return (await res.json()) as OidcUserInfo;
}

export function parseIdToken(idToken: string): { header: unknown; payload: OidcUserInfo; signature: string } {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid ID token format');
  }
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as OidcUserInfo;
    return { header, payload, signature: parts[2] };
  } catch {
    throw new Error('Failed to parse ID token');
  }
}

export function validateIdTokenClaims(
  payload: OidcUserInfo,
  cfg: OidcConfig,
  nonce: string
): { valid: boolean; error?: string } {
  const now = Math.floor(Date.now() / 1000);
  const iss = payload.iss as string | undefined;
  const aud = payload.aud as string | string[] | undefined;
  const exp = payload.exp as number | undefined;
  const iat = payload.iat as number | undefined;
  const tokenNonce = payload.nonce as string | undefined;

  if (!iss || iss !== cfg.issuer) {
    return { valid: false, error: `Invalid issuer: expected ${cfg.issuer}` };
  }

  const audList = Array.isArray(aud) ? aud : [aud];
  if (!audList.includes(cfg.clientId)) {
    return { valid: false, error: 'Token audience does not match client_id' };
  }

  if (typeof exp === 'number' && now > exp) {
    return { valid: false, error: 'Token has expired' };
  }

  if (typeof iat === 'number' && iat > now + 300) {
    return { valid: false, error: 'Token iat is in the future' };
  }

  if (tokenNonce && tokenNonce !== nonce) {
    return { valid: false, error: 'Nonce mismatch' };
  }

  return { valid: true };
}

export function resolveRoleFromClaims(
  userInfo: OidcUserInfo,
  cfg: OidcConfig
): 'admin' | 'viewer' | 'none' {
  const claimName = cfg.roleClaimName ?? 'groups';
  const claimValue = userInfo[claimName];
  const mapping = cfg.roleClaimMapping ?? {};

  let roles: string[] = [];
  if (Array.isArray(claimValue)) {
    roles = claimValue.map(String);
  } else if (typeof claimValue === 'string') {
    roles = [claimValue];
  }

  // Check for admin role first
  const adminMatch = mapping.admin ?? 'phaseone-admin';
  if (roles.some(r => r.toLowerCase() === adminMatch.toLowerCase() || r === 'admin')) {
    return 'admin';
  }

  // Check for viewer role
  const viewerMatch = mapping.viewer ?? 'phaseone-viewer';
  if (roles.some(r => r.toLowerCase() === viewerMatch.toLowerCase() || r === 'viewer')) {
    return 'viewer';
  }

  // Return default role
  return cfg.defaultRole ?? 'viewer';
}

export async function buildLogoutUrl(
  cfg: OidcConfig,
  idTokenHint?: string,
  postLogoutRedirectUri?: string
): Promise<string | null> {
  let endSessionEndpoint = cfg.endSessionEndpoint;
  if (!endSessionEndpoint) {
    try {
      const discovery = await fetchDiscoveryDocument(cfg.issuer);
      endSessionEndpoint = discovery.end_session_endpoint;
    } catch {
      return null;
    }
  }
  if (!endSessionEndpoint) {
    return null;
  }

  const params = new URLSearchParams();
  if (idTokenHint) {
    params.set('id_token_hint', idTokenHint);
  }
  if (postLogoutRedirectUri) {
    params.set('post_logout_redirect_uri', postLogoutRedirectUri);
  }
  params.set('client_id', cfg.clientId);

  return `${endSessionEndpoint}?${params.toString()}`;
}

export function clearDiscoveryCache(): void {
  discoveryCache = null;
}

export function __testResetOidcState(): void {
  pendingAuths.clear();
  discoveryCache = null;
}

export function __testGetPendingAuthCount(): number {
  return pendingAuths.size;
}
