/**
 * Onboard --defaults harness (non-interactive).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BANNER,
  defaultAnswers,
  renderEnv,
  writeEnvFile,
  parseArgs,
  generateSessionSecret,
  main,
} from '../scripts/onboard.js';

describe('onboard installer', () => {
  let dir: string;
  const prevSecret = process.env.PHASEONE_SESSION_SECRET;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'phaseone-onboard-'));
    delete process.env.PHASEONE_SESSION_SECRET;
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    if (prevSecret === undefined) delete process.env.PHASEONE_SESSION_SECRET;
    else process.env.PHASEONE_SESSION_SECRET = prevSecret;
  });

  it('banner brands Veracity Integrity', () => {
    expect(BANNER).toContain('Veracity Integrity LLC');
    expect(BANNER).toContain('VeracityIntegrity.com');
    expect(BANNER).toContain('PhaseOne10841');
  });

  it('parseArgs recognizes --defaults', () => {
    expect(parseArgs(['--defaults']).defaults).toBe(true);
    expect(parseArgs(['-y']).defaults).toBe(true);
    expect(parseArgs([]).defaults).toBe(false);
    expect(parseArgs(['--out', '/tmp/x.env']).out).toBe('/tmp/x.env');
  });

  it('generateSessionSecret is hex 64 chars', () => {
    const s = generateSessionSecret();
    expect(s).toMatch(/^[a-f0-9]{64}$/);
  });

  it('--defaults writes .env with required keys', async () => {
    const out = join(dir, '.env');
    const code = await main(['--defaults', '--out', out], dir);
    expect(code).toBe(0);
    expect(existsSync(out)).toBe(true);
    const body = readFileSync(out, 'utf8');
    expect(body).toContain('PHASEONE_ADMIN_EMAILS=');
    expect(body).toContain('DATABASE_URL=');
    expect(body).toContain('PHASEONE_SESSION_SECRET=');
    expect(body).toContain('GATEWAY_PORT=');
    expect(body).toContain('DASHBOARD_PORT=');
    expect(body).toContain('UPSTREAM_PROVIDER=mock');
    expect(body).toContain('PHASEONE_APPROVAL_TIMEOUT_MS=');
    expect(body).toContain('Veracity Integrity LLC');
    expect(body).toMatch(/PHASEONE_SESSION_SECRET=[a-f0-9]{64}/);
  });

  it('renderEnv omits SMTP when not configured', () => {
    const a = defaultAnswers({ useSmtp: false, smtpHost: '' });
    const env = renderEnv(a);
    expect(env).toContain('# SMTP_HOST=');
    expect(env).toContain('SMTP_FROM=');
  });

  it('writeEnvFile creates file', () => {
    const target = join(dir, 'custom.env');
    const result = writeEnvFile(target, defaultAnswers({ adminEmails: 'ci@localhost' }), {
      force: true,
    });
    expect(result.wrote).toBe(true);
    expect(readFileSync(target, 'utf8')).toContain('ci@localhost');
  });
});
