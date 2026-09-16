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
}
