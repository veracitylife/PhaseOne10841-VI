#!/usr/bin/env npx tsx
/**
 * Configurable event retention cleanup job.
 * Usage:
 *   npm run retention
 *   npm run retention -- --days 14 --dry-run
 *   npm run retention -- --days 30 --execute
 *
 * Env (also set via onboard): PHASEONE_RETENTION_DAYS, DATABASE_URL,
 * PHASEONE_RETENTION_PRUNE_APPROVALS, PHASEONE_RETENTION_PRUNE_AUDIT
 */
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { getPool } from '../recorder/src/db.js';
import {
  loadRetentionConfig,
  runRetentionWithPool,
} from '../shared/src/retention.js';

export function parseRetentionArgs(argv: string[]): {
  days?: number;
  dryRun: boolean;
  execute: boolean;
  help: boolean;
} {
  const help = argv.includes('--help') || argv.includes('-h');
  const execute = argv.includes('--execute') || argv.includes('--apply');
  const dryRunFlag = argv.includes('--dry-run') || argv.includes('-n');
  const daysIdx = argv.findIndex((a) => a === '--days' || a === '-d');
  const days = daysIdx >= 0 ? Number(argv[daysIdx + 1]) : undefined;
  // Default to dry-run unless --execute
  const dryRun = execute ? false : true;
  return { days, dryRun: dryRunFlag || dryRun, execute, help };
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const args = parseRetentionArgs(argv);
  if (args.help) {
    console.log(`PhaseOne10841 retention cleanup — Veracity Integrity LLC
Usage:
  npm run retention -- --dry-run [--days N]
  npm run retention -- --execute [--days N]
Env: PHASEONE_RETENTION_DAYS (default 30), DATABASE_URL
`);
    return 0;
  }
  const cfg = loadRetentionConfig({
    retentionDays: args.days,
    dryRun: args.dryRun,
  });
  console.log(
    `PhaseOne10841 retention: days=${cfg.retentionDays} dry_run=${cfg.dryRun}`
  );
  const result = await runRetentionWithPool(getPool(), cfg);
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) return 1;
  console.log('Veracity Integrity LLC · https://VeracityIntegrity.com');
  try {
    await getPool().end();
  } catch {
    /* ignore */
  }
  return 0;
}

const isDirect =
  process.argv[1] &&
  (resolve(process.argv[1]) === fileURLToPath(import.meta.url) ||
    process.argv[1].endsWith('retention-cleanup.ts'));

if (isDirect) {
  main()
    .then((c) => process.exit(c))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
