/**
 * Session secret hygiene — weak placeholder detection.
 */
import { describe, it, expect } from 'vitest';
import {
  isWeakSessionSecret,
  warnIfWeakSessionSecret,
} from '../shared/src/session-secret.js';
import { generateSessionSecret } from '../scripts/onboard.js';

describe('session secret hygiene', () => {
  it('flags change-me and short secrets', () => {
    expect(isWeakSessionSecret(undefined)).toBe(true);
    expect(isWeakSessionSecret('')).toBe(true);
    expect(isWeakSessionSecret('change-me-run-onboard-to-generate')).toBe(true);
    expect(isWeakSessionSecret('dev-only-change-me')).toBe(true);
    expect(isWeakSessionSecret('short')).toBe(true);
  });

  it('accepts onboard-generated hex secrets', () => {
    const s = generateSessionSecret();
    expect(s).toMatch(/^[a-f0-9]{64}$/);
    expect(isWeakSessionSecret(s)).toBe(false);
  });

  it('warnIfWeakSessionSecret logs for placeholders', () => {
    const lines: string[] = [];
    const weak = warnIfWeakSessionSecret('change-me', (m) => lines.push(m));
    expect(weak).toBe(true);
    expect(lines.join('')).toMatch(/WARNING.*SESSION_SECRET/i);
    const strong = warnIfWeakSessionSecret(generateSessionSecret(), (m) => lines.push(m));
    expect(strong).toBe(false);
  });
});
