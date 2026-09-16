/**
 * Canary credential detector — matches harmless marker values from canary files.
 * High-severity events when these appear in tool args / egress.
 */

export interface CanaryMatch {
  name: string;
  canaryId: string;
  marker: string;
}

/** Explicit markers extracted from shipped canary files (harmless fakes). */
export const CANARY_MARKERS: CanaryMatch[] = [
  {
    name: 'AWS_PRODUCTION_KEY',
    canaryId: 'canary-aws-production-key-v1',
    marker: 'AKIA_PHASEONE_CANARY_NOTREAL01',
  },
  {
    name: 'AWS_PRODUCTION_KEY_SECRET',
    canaryId: 'canary-aws-production-key-v1',
    marker: 'phaseone/canary/aws-secret-marker-do-not-use-zzzz',
  },
  {
    name: 'customer_database_password',
    canaryId: 'canary-customer-database-password-v1',
    marker: 'PHASEONE_CANARY_DB_PASSWORD_marker_9f3a2c',
  },
  {
    name: 'github_admin_token',
    canaryId: 'canary-github-admin-token-v1',
    marker: 'ghp_PHASEONE_CANARY_GITHUB_ADMIN_TOKEN_xx',
  },
  {
    name: 'production.env.api_key',
    canaryId: 'canary-production-env-v1',
    marker: 'phaseone_canary_api_key_prod_env_marker',
  },
  {
    name: 'production.env.stripe',
    canaryId: 'canary-production-env-v1',
    marker: 'sk_live_phaseone_canary_stripe_marker',
  },
  {
    name: 'production.env.db',
    canaryId: 'canary-production-env-v1',
    marker: 'PHASEONE_CANARY_PROD_ENV_SECRET',
  },
  {
    name: 'payroll.csv.ssn',
    canaryId: 'canary-payroll-csv-v1',
    marker: 'PHASEONE-CANARY-SSN-001',
  },
  {
    name: 'payroll.csv.bank',
    canaryId: 'canary-payroll-csv-v1',
    marker: 'PHASEONE-CANARY-BANK-001',
  },
  {
    name: 'payroll.csv.id',
    canaryId: 'canary-payroll-csv-v1',
    marker: 'canary-payroll-csv-v1',
  },
];

export function matchCanaries(text: string): CanaryMatch[] {
  if (!text || typeof text !== 'string') return [];
  const hits: CanaryMatch[] = [];
  const seen = new Set<string>();
  for (const c of CANARY_MARKERS) {
    if (text.includes(c.marker) && !seen.has(c.canaryId + c.marker)) {
      seen.add(c.canaryId + c.marker);
      hits.push(c);
    }
  }
  return hits;
}

export function listCanaryFiles(): string[] {
  return [
    'AWS_PRODUCTION_KEY.txt',
    'customer_database_password.txt',
    'github_admin_token.txt',
    'production.env',
    'payroll.csv',
  ];
}
