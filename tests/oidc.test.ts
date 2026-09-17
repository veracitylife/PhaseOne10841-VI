/**
 * OIDC/SSO authentication tests.
 * Uses mock IdP responses — no live credentials required.
 * DEFENSIVE ONLY.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  loadOidcConfig,
  isOidcEnabled,
  createPendingAuth,
  getPendingAuth,
  consumePendingAuth,
  generateState,
  generateNonce,
  generatePkceVerifier,
  computePkceChallenge,
  parseIdToken,
  validateIdTokenClaims,
  resolveRoleFromClaims,
  __testResetOidcState,
  __testGetPendingAuthCount,
  type OidcConfig,
  type OidcUserInfo,
} from '../shared/src/oidc.js';

describe('OIDC Configuration', () => {
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

  it('defaults OIDC to disabled when not configured', () => {
    const cfg = loadOidcConfig();
    expect(cfg.enabled).toBe(false);
    expect(isOidcEnabled(cfg)).toBe(false);
  });

  it('requires issuer, clientId, and redirectUri to be enabled', () => {
    process.env.PHASEONE_OIDC_ENABLED = 'true';
    // Missing issuer, clientId, redirectUri
    expect(isOidcEnabled()).toBe(false);

    process.env.PHASEONE_OIDC_ISSUER = 'https://test.okta.com';
    expect(isOidcEnabled()).toBe(false);

    process.env.PHASEONE_OIDC_CLIENT_ID = 'test-client-id';
    expect(isOidcEnabled()).toBe(false);

    process.env.PHASEONE_OIDC_REDIRECT_URI = 'https://app.example.com/callback';
    expect(isOidcEnabled()).toBe(true);
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

  it('generates cryptographically random state', () => {
    const state1 = generateState();
    const state2 = generateState();
    expect(state1).not.toBe(state2);
    expect(state1.length).toBeGreaterThan(20);
  });

  it('generates cryptographically random nonce', () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();
    expect(nonce1).not.toBe(nonce2);
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

  it('expires pending auth after TTL', () => {
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
      stateTtlMs: 1, // 1ms TTL for testing
      ssoOnly: false,
    };

    const pending = createPendingAuth(cfg);
    
    // Wait for expiration
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        const retrieved = getPendingAuth(pending.state);
        expect(retrieved).toBeNull();
        resolve();
      }, 10);
    });
  });
});

describe('PKCE', () => {
  it('generates valid PKCE verifier', () => {
    const verifier = generatePkceVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    // base64url characters only
    expect(/^[A-Za-z0-9_-]+$/.test(verifier)).toBe(true);
  });

  it('computes S256 challenge from verifier', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = computePkceChallenge(verifier);
    // Challenge should be base64url encoded SHA-256 hash
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
  // Test JWT with payload: {"sub":"user123","email":"test@example.com","iss":"https://test.okta.com","aud":"client123","exp":9999999999,"nonce":"test-nonce"}
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
      responseType: 'code',
      responseMode: 'query',
      usePkce: false,
      stateTtlMs: 600000,
      ssoOnly: false,
    };

    const parsed = parseIdToken(mockIdToken);
    const result = validateIdTokenClaims(parsed.payload, cfg, 'test-nonce');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('issuer');
  });

  it('rejects token with wrong audience', () => {
    const cfg: OidcConfig = {
      enabled: true,
      issuer: 'https://test.okta.com',
      clientId: 'wrong-client',
      clientSecret: '',
      redirectUri: '',
      scopes: [],
      responseType: 'code',
      responseMode: 'query',
      usePkce: false,
      stateTtlMs: 600000,
      ssoOnly: false,
    };

    const parsed = parseIdToken(mockIdToken);
    const result = validateIdTokenClaims(parsed.payload, cfg, 'test-nonce');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('audience');
  });

  it('rejects token with wrong nonce', () => {
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
    };

    const parsed = parseIdToken(mockIdToken);
    const result = validateIdTokenClaims(parsed.payload, cfg, 'wrong-nonce');
    expect(result.valid).toBe(false);
    expect(result.error?.toLowerCase()).toContain('nonce');
  });

  it('rejects expired token', () => {
    const expiredToken = [
      Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url'),
      Buffer.from(JSON.stringify({
        sub: 'user123',
        iss: 'https://test.okta.com',
        aud: 'client123',
        exp: 1, // Expired
        iat: 0,
      })).toString('base64url'),
      'sig',
    ].join('.');

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
    };

    const parsed = parseIdToken(expiredToken);
    const result = validateIdTokenClaims(parsed.payload, cfg, '');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
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
    responseType: 'code',
    responseMode: 'query',
    usePkce: false,
    stateTtlMs: 600000,
    ssoOnly: false,
    roleClaimName: 'groups',
    defaultRole: 'viewer',
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

    const viewerUser: OidcUserInfo = {
      sub: 'user2',
      groups: ['SecurityViewers'],
    };
    expect(resolveRoleFromClaims(viewerUser, cfg)).toBe('viewer');
  });

  it('returns default role when no match', () => {
    const userInfo: OidcUserInfo = {
      sub: 'user1',
      groups: ['unrelated-group'],
    };

    const role = resolveRoleFromClaims(userInfo, baseCfg);
    expect(role).toBe('viewer');

    const cfgWithAdminDefault = { ...baseCfg, defaultRole: 'admin' as const };
    expect(resolveRoleFromClaims(userInfo, cfgWithAdminDefault)).toBe('admin');
  });

  it('handles string role claim', () => {
    const userInfo: OidcUserInfo = {
      sub: 'user1',
      groups: 'phaseone-admin' as unknown as string[],
    };

    const role = resolveRoleFromClaims(userInfo, baseCfg);
    expect(role).toBe('admin');
  });

  it('handles custom claim name', () => {
    const cfg = { ...baseCfg, roleClaimName: 'custom_roles' };
    const userInfo: OidcUserInfo = {
      sub: 'user1',
      custom_roles: ['admin'],
    };

    const role = resolveRoleFromClaims(userInfo, cfg);
    expect(role).toBe('admin');
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

describe('Auth Module OIDC Integration', () => {
  // These tests use the auth module's OIDC functions
  // They require the auth module to be available

  beforeEach(() => {
    __testResetOidcState();
  });

  afterEach(() => {
    __testResetOidcState();
  });

  it('creates session with OIDC metadata', async () => {
    const { createSession, __testGetSession } = await import('../dashboard/src/auth.js');
    
    const session = createSession('test@example.com', undefined, {
      authMethod: 'oidc',
      idpSubject: 'user123',
      idToken: 'mock-id-token',
      oidcUserInfo: { sub: 'user123', email: 'test@example.com' },
      roleOverride: 'admin',
    });

    expect(session.authMethod).toBe('oidc');
    expect(session.idpSubject).toBe('user123');
    expect(session.idToken).toBe('mock-id-token');
    expect(session.role).toBe('admin');
    expect(session.email).toBe('test@example.com');

    const retrieved = __testGetSession(session.id);
    expect(retrieved).toEqual(session);
  });

  it('getOidcStatus returns config status', async () => {
    const { getOidcStatus } = await import('../dashboard/src/auth.js');
    
    // With default env (OIDC disabled)
    const status = getOidcStatus();
    expect(status.enabled).toBe(false);
    expect(status.ssoOnly).toBe(false);
  });
});
