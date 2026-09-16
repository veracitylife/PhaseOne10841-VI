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
