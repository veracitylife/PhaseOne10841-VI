/**
 * PhaseOne10841 OIDC Configuration Tests
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 *
 * Tests for OIDC/SSO enterprise auth path configuration.
 * DEFENSIVE ONLY — no exploit tooling.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  loadOIDCConfig,
  isOIDCEnabled,
  getOIDCStatus,
  describeOIDCConfig,
  createOIDCAuthorizationUrl,
  __testResetOIDCState,
} from '../shared/src/oidc.js';

describe('OIDC config loading', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
    __testResetOIDCState();
  });

  it('returns disabled config when env vars not set', () => {
    delete process.env.PHASEONE_OIDC_ISSUER;
    delete process.env.PHASEONE_OIDC_CLIENT_ID;
    delete process.env.PHASEONE_OIDC_CLIENT_SECRET;

    const cfg = loadOIDCConfig();
    expect(cfg.enabled).toBe(false);
    expect(cfg.issuer).toBe('');
    expect(cfg.clientId).toBe('');
  });

  it('enables when issuer and client_id are set', () => {
    process.env.PHASEONE_OIDC_ISSUER = 'https://auth.example.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client';
    process.env.PHASEONE_OIDC_CLIENT_SECRET = 'test-secret';

    const cfg = loadOIDCConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.issuer).toBe('https://auth.example.com');
    expect(cfg.clientId).toBe('test-client');
  });

  it('uses default scopes', () => {
    process.env.PHASEONE_OIDC_ISSUER = 'https://auth.example.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client';

    const cfg = loadOIDCConfig();
    expect(cfg.scopes).toContain('openid');
    expect(cfg.scopes).toContain('email');
    expect(cfg.scopes).toContain('profile');
  });

  it('parses custom scopes', () => {
    process.env.PHASEONE_OIDC_ISSUER = 'https://auth.example.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client';
    process.env.PHASEONE_OIDC_SCOPES = 'openid email groups';

    const cfg = loadOIDCConfig();
    expect(cfg.scopes).toEqual(['openid', 'email', 'groups']);
  });

  it('uses default email claim', () => {
    const cfg = loadOIDCConfig();
    expect(cfg.emailClaim).toBe('email');
  });

  it('uses custom email claim', () => {
    process.env.PHASEONE_OIDC_EMAIL_CLAIM = 'preferred_username';

    const cfg = loadOIDCConfig();
    expect(cfg.emailClaim).toBe('preferred_username');
  });

  it('sets default role values', () => {
    const cfg = loadOIDCConfig();
    expect(cfg.adminRoleValue).toBe('phaseone-admin');
    expect(cfg.viewerRoleValue).toBe('phaseone-viewer');
  });

  it('allows OTP fallback by default', () => {
    const cfg = loadOIDCConfig();
    expect(cfg.allowEmailOtpFallback).toBe(true);
  });

  it('can disable OTP fallback', () => {
    process.env.PHASEONE_OIDC_ALLOW_OTP_FALLBACK = 'false';

    const cfg = loadOIDCConfig();
    expect(cfg.allowEmailOtpFallback).toBe(false);
  });
});

describe('isOIDCEnabled', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('returns false when not configured', () => {
    delete process.env.PHASEONE_OIDC_ISSUER;
    delete process.env.PHASEONE_OIDC_CLIENT_ID;

    expect(isOIDCEnabled()).toBe(false);
  });

  it('returns true when configured', () => {
    process.env.PHASEONE_OIDC_ISSUER = 'https://auth.example.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client';

    expect(isOIDCEnabled()).toBe(true);
  });
});

describe('getOIDCStatus', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('returns disabled status when not configured', () => {
    delete process.env.PHASEONE_OIDC_ISSUER;
    delete process.env.PHASEONE_OIDC_CLIENT_ID;

    const status = getOIDCStatus();
    expect(status.enabled).toBe(false);
    expect(status.issuer).toBeNull();
    expect(status.configured).toBe(false);
  });

  it('returns enabled status when configured', () => {
    process.env.PHASEONE_OIDC_ISSUER = 'https://auth.example.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client';

    const status = getOIDCStatus();
    expect(status.enabled).toBe(true);
    expect(status.issuer).toBe('https://auth.example.com');
    expect(status.configured).toBe(true);
  });
});

describe('describeOIDCConfig', () => {
  it('returns config documentation', () => {
    const docs = describeOIDCConfig();
    expect(docs.issuer).toBeDefined();
    expect(docs.issuer.envVar).toBe('PHASEONE_OIDC_ISSUER');
    expect(docs.issuer.required).toBe(true);
    expect(docs.clientId.required).toBe(true);
    expect(docs.scopes.default).toBe('openid email profile');
  });
});

describe('createOIDCAuthorizationUrl', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    __testResetOIDCState();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    __testResetOIDCState();
  });

  it('throws when OIDC not enabled', () => {
    delete process.env.PHASEONE_OIDC_ISSUER;
    delete process.env.PHASEONE_OIDC_CLIENT_ID;

    expect(() => createOIDCAuthorizationUrl()).toThrow('OIDC is not enabled');
  });

  it('generates authorization URL with required params', () => {
    process.env.PHASEONE_OIDC_ISSUER = 'https://auth.example.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client';
    process.env.PHASEONE_OIDC_CLIENT_SECRET = 'test-secret';
    process.env.PHASEONE_OIDC_REDIRECT_URI = 'http://localhost:3000/callback';

    const { url, state } = createOIDCAuthorizationUrl();
    
    expect(url).toContain('https://auth.example.com/authorize');
    expect(url).toContain('client_id=test-client');
    expect(url).toContain('redirect_uri=');
    expect(url).toContain('response_type=code');
    expect(url).toContain('scope=openid');
    expect(url).toContain('state=');
    expect(url).toContain('code_challenge=');
    expect(url).toContain('code_challenge_method=S256');
    expect(state).toBeTruthy();
    expect(state.length).toBeGreaterThan(0);
  });

  it('uses custom authorization endpoint', () => {
    process.env.PHASEONE_OIDC_ISSUER = 'https://auth.example.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client';
    process.env.PHASEONE_OIDC_AUTHORIZATION_ENDPOINT = 'https://auth.example.com/oauth2/authorize';

    const { url } = createOIDCAuthorizationUrl();
    expect(url).toContain('https://auth.example.com/oauth2/authorize');
  });
});

// ============================================================================
// Phase 8 Wave A Extended Tests
// Tests for the camelCase API aliases and additional Wave A functionality
// ============================================================================

import {
  loadOidcConfig,
  isOidcEnabled,
  generatePkceVerifier,
  computePkceChallenge,
  createPendingAuth,
  getPendingAuth,
  consumePendingAuth,
  parseIdToken,
  validateIdTokenClaims,
  resolveRoleFromClaims,
  __testResetOidcState,
  __testGetPendingAuthCount,
  type OidcConfig,
  type OidcUserInfo,
} from '../shared/src/oidc.js';

describe('OIDC Configuration (camelCase API)', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    __testResetOidcState();
  });

  afterEach(() => {
    process.env = originalEnv;
    __testResetOidcState();
  });

  it('loads OIDC config from environment', () => {
    process.env.PHASEONE_OIDC_ENABLED = 'true';
    process.env.PHASEONE_OIDC_ISSUER = 'https://test.okta.com';
    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client-id';
    process.env.PHASEONE_OIDC_CLIENT_SECRET = 'test-secret';
    process.env.PHASEONE_OIDC_REDIRECT_URI = 'https://app.example.com/callback';
    process.env.PHASEONE_OIDC_SCOPES = 'openid email profile';

    const cfg = loadOidcConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.issuer).toBe('https://test.okta.com');
    expect(cfg.clientId).toBe('test-client-id');
    expect(cfg.clientSecret).toBe('test-secret');
    expect(cfg.redirectUri).toBe('https://app.example.com/callback');
    expect(cfg.scopes).toEqual(['openid', 'email', 'profile']);
    expect(cfg.usePkce).toBe(true);
    expect(cfg.ssoOnly).toBe(false);
  });

  it('parses role mapping from JSON', () => {
    process.env.PHASEONE_OIDC_ROLE_MAPPING = '{"admin":"SecurityAdmins","viewer":"SecurityViewers"}';
    const cfg = loadOidcConfig();
    expect(cfg.roleClaimMapping).toEqual({
      admin: 'SecurityAdmins',
      viewer: 'SecurityViewers',
    });
  });

  it('handles invalid role mapping JSON gracefully', () => {
    process.env.PHASEONE_OIDC_ROLE_MAPPING = 'not-valid-json';
    const cfg = loadOidcConfig();
    expect(cfg.roleClaimMapping).toBeUndefined();
  });
});

describe('OIDC State Management', () => {
  beforeEach(() => {
    __testResetOidcState();
  });

  afterEach(() => {
    __testResetOidcState();
  });

  it('creates and retrieves pending auth', () => {
    const cfg: OidcConfig = {
      enabled: true,
      issuer: 'https://test.okta.com',
      clientId: 'test-client',
      clientSecret: 'secret',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['openid', 'email'],
      responseType: 'code',
      responseMode: 'query',
      usePkce: true,
      stateTtlMs: 600000,
      ssoOnly: false,
      emailClaim: 'email',
      sessionTtlMs: 3600000,
      allowEmailOtpFallback: true,
    };

    const pending = createPendingAuth(cfg, '/dashboard');
    expect(pending.state).toBeTruthy();
    expect(pending.nonce).toBeTruthy();
    expect(pending.codeVerifier).toBeTruthy();
    expect(pending.codeChallenge).toBeTruthy();
    expect(pending.returnUrl).toBe('/dashboard');
    expect(__testGetPendingAuthCount()).toBe(1);

    const retrieved = getPendingAuth(pending.state);
    expect(retrieved).toEqual(pending);
  });

  it('consumes pending auth (one-time use)', () => {
    const cfg: OidcConfig = {
      enabled: true,
      issuer: 'https://test.okta.com',
      clientId: 'test-client',
      clientSecret: 'secret',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['openid', 'email'],
      responseType: 'code',
      responseMode: 'query',
      usePkce: false,
      stateTtlMs: 600000,
      ssoOnly: false,
      emailClaim: 'email',
      sessionTtlMs: 3600000,
      allowEmailOtpFallback: true,
    };

    const pending = createPendingAuth(cfg);
    expect(__testGetPendingAuthCount()).toBe(1);

    const consumed = consumePendingAuth(pending.state);
    expect(consumed).toEqual(pending);
    expect(__testGetPendingAuthCount()).toBe(0);

    const secondAttempt = consumePendingAuth(pending.state);
    expect(secondAttempt).toBeNull();
  });

  it('returns null for invalid state', () => {
    expect(getPendingAuth('invalid-state')).toBeNull();
    expect(consumePendingAuth('invalid-state')).toBeNull();
  });
});

describe('PKCE', () => {
  it('generates valid PKCE verifier', () => {
    const verifier = generatePkceVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(/^[A-Za-z0-9_-]+$/.test(verifier)).toBe(true);
  });

  it('computes S256 challenge from verifier', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = computePkceChallenge(verifier);
    expect(challenge.length).toBeGreaterThan(0);
    expect(/^[A-Za-z0-9_-]+$/.test(challenge)).toBe(true);
  });

  it('produces different challenges for different verifiers', () => {
    const verifier1 = generatePkceVerifier();
    const verifier2 = generatePkceVerifier();
    const challenge1 = computePkceChallenge(verifier1);
    const challenge2 = computePkceChallenge(verifier2);
    expect(challenge1).not.toBe(challenge2);
  });
});

describe('ID Token Parsing', () => {
  const mockIdToken = [
    Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify({
      sub: 'user123',
      email: 'test@example.com',
      iss: 'https://test.okta.com',
      aud: 'client123',
      exp: 9999999999,
      iat: Math.floor(Date.now() / 1000),
      nonce: 'test-nonce',
    })).toString('base64url'),
    'mock-signature',
  ].join('.');

  it('parses valid ID token', () => {
    const parsed = parseIdToken(mockIdToken);
    expect(parsed.payload.sub).toBe('user123');
    expect(parsed.payload.email).toBe('test@example.com');
    expect(parsed.signature).toBe('mock-signature');
  });

  it('throws on invalid token format', () => {
    expect(() => parseIdToken('not.a.valid.token.format')).toThrow();
    expect(() => parseIdToken('invalid')).toThrow();
  });

  it('validates token claims correctly', () => {
    const cfg: OidcConfig = {
      enabled: true,
      issuer: 'https://test.okta.com',
      clientId: 'client123',
      clientSecret: '',
      redirectUri: '',
      scopes: [],
      responseType: 'code',
      responseMode: 'query',
      usePkce: false,
      stateTtlMs: 600000,
      ssoOnly: false,
      emailClaim: 'email',
      sessionTtlMs: 3600000,
      allowEmailOtpFallback: true,
    };

    const parsed = parseIdToken(mockIdToken);
    const result = validateIdTokenClaims(parsed.payload, cfg, 'test-nonce');
    expect(result.valid).toBe(true);
  });

  it('rejects token with wrong issuer', () => {
    const cfg: OidcConfig = {
      enabled: true,
      issuer: 'https://wrong-issuer.com',
      clientId: 'client123',
      clientSecret: '',
      redirectUri: '',
      scopes: [],
      emailClaim: 'email',
      sessionTtlMs: 3600000,
      allowEmailOtpFallback: true,
    };

    const parsed = parseIdToken(mockIdToken);
    const result = validateIdTokenClaims(parsed.payload, cfg, 'test-nonce');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('issuer');
  });

  it('rejects token with wrong nonce', () => {
    const cfg: OidcConfig = {
      enabled: true,
      issuer: 'https://test.okta.com',
      clientId: 'client123',
      clientSecret: '',
      redirectUri: '',
      scopes: [],
      emailClaim: 'email',
      sessionTtlMs: 3600000,
      allowEmailOtpFallback: true,
    };

    const parsed = parseIdToken(mockIdToken);
    const result = validateIdTokenClaims(parsed.payload, cfg, 'wrong-nonce');
    expect(result.valid).toBe(false);
    expect(result.error?.toLowerCase()).toContain('nonce');
  });
});

describe('Role Resolution from Claims', () => {
  const baseCfg: OidcConfig = {
    enabled: true,
    issuer: 'https://test.okta.com',
    clientId: 'client',
    clientSecret: '',
    redirectUri: '',
    scopes: [],
    roleClaimName: 'groups',
    defaultRole: 'viewer',
    emailClaim: 'email',
    sessionTtlMs: 3600000,
    allowEmailOtpFallback: true,
  };

  it('resolves admin role from groups claim', () => {
    const userInfo: OidcUserInfo = {
      sub: 'user1',
      email: 'admin@example.com',
      groups: ['phaseone-admin', 'other-group'],
    };

    const role = resolveRoleFromClaims(userInfo, baseCfg);
    expect(role).toBe('admin');
  });

  it('resolves viewer role from groups claim', () => {
    const userInfo: OidcUserInfo = {
      sub: 'user1',
      email: 'viewer@example.com',
      groups: ['phaseone-viewer', 'other-group'],
    };

    const role = resolveRoleFromClaims(userInfo, baseCfg);
    expect(role).toBe('viewer');
  });

  it('uses custom role mapping', () => {
    const cfg = {
      ...baseCfg,
      roleClaimMapping: {
        admin: 'SecurityAdmins',
        viewer: 'SecurityViewers',
      },
    };

    const adminUser: OidcUserInfo = {
      sub: 'user1',
      groups: ['SecurityAdmins'],
    };
    expect(resolveRoleFromClaims(adminUser, cfg)).toBe('admin');
  });

  it('returns default role when no match', () => {
    const userInfo: OidcUserInfo = {
      sub: 'user1',
      groups: ['unrelated-group'],
    };

    const role = resolveRoleFromClaims(userInfo, baseCfg);
    expect(role).toBe('viewer');
  });

  it('prioritizes admin over viewer', () => {
    const userInfo: OidcUserInfo = {
      sub: 'user1',
      groups: ['phaseone-viewer', 'phaseone-admin'],
    };

    const role = resolveRoleFromClaims(userInfo, baseCfg);
    expect(role).toBe('admin');
  });
});
