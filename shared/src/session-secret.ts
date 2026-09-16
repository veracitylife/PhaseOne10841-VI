/**
 * Session secret hygiene — warn on weak / placeholder secrets.
 * DEFENSIVE only; does not generate or store credentials beyond env checks.
 */

/** Substrings that indicate a placeholder / lab default — never ship these. */
const WEAK_MARKERS = [
  'change-me',
  'changeme',
  'dev-only',
  'dev-only-change-me',
  'replace-me',
  'run-onboard-to-generate',
  'insecure',
  'placeholder',
];

/** True when secret is missing, too short, or matches known placeholders. */
export function isWeakSessionSecret(secret: string | undefined | null): boolean {
  if (secret == null) return true;
  const s = String(secret).trim();
  if (!s) return true;
  if (s.length < 32) return true;
  // Onboard generates 32-byte hex (64 chars) — always considered strong
  if (/^[a-f0-9]{64}$/i.test(s)) return false;
  const lower = s.toLowerCase();
  for (const m of WEAK_MARKERS) {
    if (lower.includes(m)) return true;
  }
  return false;
}

/** Loud console warning for operators; safe to call at process start. */
export function warnIfWeakSessionSecret(
  secret: string | undefined | null = process.env.PHASEONE_SESSION_SECRET,
  log: (msg: string) => void = console.warn
): boolean {
  if (!isWeakSessionSecret(secret)) return false;
  log(
    [
      '',
      '╔══════════════════════════════════════════════════════════════════╗',
      '║  WARNING: PHASEONE_SESSION_SECRET is weak or unset               ║',
      '║  Never leave change-me / dev-only placeholders in production.    ║',
      '║  Fix: npm run onboard   (or: npm run onboard -- --defaults)      ║',
      '║  Veracity Integrity LLC · https://VeracityIntegrity.com          ║',
      '╚══════════════════════════════════════════════════════════════════╝',
      '',
    ].join('\n')
  );
  return true;
}
