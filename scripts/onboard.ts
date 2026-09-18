#!/usr/bin/env npx tsx
/**
 * PhaseOne10841 terminal onboarding installer
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 *
 * Interactive:  npm run onboard
 * CI / defaults: npm run onboard -- --defaults
 * Env overrides: ONBOARD_* or existing process.env values used as defaults
 */
import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { isWeakSessionSecret } from '../shared/src/session-secret.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

export const BANNER = `
╔══════════════════════════════════════════════════════════════╗
║  PhaseOne10841 — Defensive Agent Security Gateway (EDR)     ║
║  A product of Veracity Integrity LLC                        ║
║  https://VeracityIntegrity.com                              ║
║  DEFENSIVE ONLY — no exploit tooling                        ║
╚══════════════════════════════════════════════════════════════╝
`.trim();

export interface OnboardAnswers {
  adminEmails: string;
  viewerEmails: string;
  smtpHost: string;
  smtpPort: string;
  smtpUser: string;
  smtpPass: string;
  smtpFrom: string;
  smtpSecure: string;
  useSmtp: boolean;
  databaseUrl: string;
  sessionSecret: string;
  upstreamProvider: string;
  openaiApiKey: string;
  openaiBaseUrl: string;
  ollamaBaseUrl: string;
  openrouterApiKey: string;
  openrouterBaseUrl: string;
  gatewayPort: string;
  dashboardPort: string;
  gatewayUrl: string;
  siemWebhookUrl: string;
  approvalTimeoutMs: string;
  authEnabled: string;
  otpFallbackFile: string;
  secureCookies: string;
  alertWebhookUrl: string;
  rulesDir: string;
  metricsEnabled: string;
  retentionDays: string;
  apiRateLimit: string;
  apiRateWindowMs: string;
  otpRateLimit: string;
  backupDir: string;
  gatekeeperEnabled: string;
  gatekeeperDryRun: string;
  playbooksDir: string;
  gatekeeperLlmPrimary: string;
  gatekeeperLlmFallback: string;
  gatekeeperOpenrouterModel: string;
  gatekeeperOpenrouterBaseUrl: string;
  gatekeeperOllamaBaseUrl: string;
  gatekeeperOllamaModel: string;
}

export function generateSessionSecret(): string {
  return randomBytes(32).toString('hex');
}

export function defaultAnswers(overrides: Partial<OnboardAnswers> = {}): OnboardAnswers {
  return {
    adminEmails: process.env.PHASEONE_ADMIN_EMAILS ?? process.env.ONBOARD_ADMIN_EMAILS ?? 'admin@localhost',
    viewerEmails: process.env.PHASEONE_VIEWER_EMAILS ?? '',
    smtpHost: process.env.SMTP_HOST ?? '',
    smtpPort: process.env.SMTP_PORT ?? '587',
    smtpUser: process.env.SMTP_USER ?? '',
    smtpPass: process.env.SMTP_PASS ?? '',
    smtpFrom: process.env.SMTP_FROM ?? 'noreply@clovisstar.com',
    smtpSecure: process.env.SMTP_SECURE ?? 'false',
    useSmtp: Boolean(process.env.SMTP_HOST),
    databaseUrl:
      process.env.DATABASE_URL ?? 'postgres://phaseone:phaseone@localhost:5432/phaseone',
    sessionSecret: (() => {
      const fromEnv = process.env.PHASEONE_SESSION_SECRET;
      // Never keep placeholders (change-me / short) — always mint a strong secret
      if (fromEnv && !isWeakSessionSecret(fromEnv)) return fromEnv;
      return generateSessionSecret();
    })(),
    upstreamProvider: process.env.UPSTREAM_PROVIDER ?? 'mock',
    openaiApiKey: process.env.OPENAI_API_KEY ?? '',
    openaiBaseUrl: process.env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1',
    ollamaBaseUrl: process.env.OLLAMA_BASE_URL ?? 'http://host.docker.internal:11434/v1',
    openrouterApiKey: process.env.OPENROUTER_API_KEY ?? '',
    openrouterBaseUrl: process.env.OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1',
    gatewayPort: process.env.GATEWAY_PORT ?? '8080',
    dashboardPort: process.env.DASHBOARD_PORT ?? '3000',
    gatewayUrl: process.env.GATEWAY_URL ?? 'http://localhost:8080',
    siemWebhookUrl: process.env.PHASEONE_SIEM_WEBHOOK_URL ?? process.env.SIEM_WEBHOOK_URL ?? '',
    approvalTimeoutMs: process.env.PHASEONE_APPROVAL_TIMEOUT_MS ?? '120000',
    authEnabled: process.env.PHASEONE_DASHBOARD_AUTH ?? 'true',
    otpFallbackFile: process.env.PHASEONE_OTP_FALLBACK_FILE ?? '/tmp/phaseone-otp.log',
    secureCookies: process.env.PHASEONE_SECURE_COOKIES ?? 'false',
    alertWebhookUrl: process.env.PHASEONE_ALERT_WEBHOOK_URL ?? '',
    rulesDir: process.env.PHASEONE_RULES_DIR ?? './rules',
    metricsEnabled: process.env.PHASEONE_METRICS_ENABLED ?? 'true',
    retentionDays: process.env.PHASEONE_RETENTION_DAYS ?? '30',
    apiRateLimit: process.env.PHASEONE_API_RATE_LIMIT ?? '120',
    apiRateWindowMs: process.env.PHASEONE_API_RATE_WINDOW_MS ?? '60000',
    otpRateLimit: process.env.PHASEONE_OTP_RATE_LIMIT ?? '5',
    backupDir: process.env.PHASEONE_BACKUP_DIR ?? './backups',
    gatekeeperEnabled: process.env.PHASEONE_GATEKEEPER_ENABLED ?? 'false',
    gatekeeperDryRun: process.env.PHASEONE_GATEKEEPER_DRY_RUN ?? 'true',
    playbooksDir: process.env.PHASEONE_PLAYBOOKS_DIR ?? './playbooks',
    gatekeeperLlmPrimary: process.env.PHASEONE_GATEKEEPER_LLM_PRIMARY ?? 'openrouter',
    gatekeeperLlmFallback: process.env.PHASEONE_GATEKEEPER_LLM_FALLBACK ?? 'ollama',
    gatekeeperOpenrouterModel: process.env.PHASEONE_GATEKEEPER_OPENROUTER_MODEL ?? 'openrouter/auto',
    gatekeeperOpenrouterBaseUrl: process.env.PHASEONE_GATEKEEPER_OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1',
    gatekeeperOllamaBaseUrl: process.env.PHASEONE_GATEKEEPER_OLLAMA_BASE_URL ?? 'http://100.124.238.112:11434/v1',
    gatekeeperOllamaModel: process.env.PHASEONE_GATEKEEPER_OLLAMA_MODEL ?? 'unrestricted:latest',
    ...overrides,
  };
}

export function renderEnv(a: OnboardAnswers): string {
  const lines = [
    '# PhaseOne10841 v0.8.0 — generated by npm run onboard',
    '# Veracity Integrity LLC · https://VeracityIntegrity.com',
    `# Generated: ${new Date().toISOString()}`,
    '',
    '# --- Admin MFA (email OTP) ---',
    `PHASEONE_ADMIN_EMAILS=${a.adminEmails}`,
    a.viewerEmails ? `PHASEONE_VIEWER_EMAILS=${a.viewerEmails}` : '# PHASEONE_VIEWER_EMAILS=',
    `PHASEONE_DASHBOARD_AUTH=${a.authEnabled}`,
    `PHASEONE_SESSION_SECRET=${a.sessionSecret}`,
    `PHASEONE_OTP_FALLBACK_FILE=${a.otpFallbackFile}`,
    `PHASEONE_SECURE_COOKIES=${a.secureCookies}`,
    '',
    '# --- SMTP (leave SMTP_HOST empty ONLY for lab console OTP fallback) ---',
    '# Production From: noreply@clovisstar.com (Veracity / Clovis Star)',
  ];
  if (a.useSmtp && a.smtpHost) {
    lines.push(
      `SMTP_HOST=${a.smtpHost}`,
      `SMTP_PORT=${a.smtpPort}`,
      `SMTP_USER=${a.smtpUser}`,
      `SMTP_PASS=${a.smtpPass}`,
      `SMTP_FROM=${a.smtpFrom}`,
      `SMTP_SECURE=${a.smtpSecure}`
    );
  } else {
    lines.push(
      '# SMTP_HOST=',
      '# SMTP_PORT=587',
      '# SMTP_USER=',
      '# SMTP_PASS=',
      `SMTP_FROM=${a.smtpFrom}`,
      '# SMTP_SECURE=false'
    );
  }
  lines.push(
    '',
    '# --- Database ---',
    `DATABASE_URL=${a.databaseUrl}`,
    '',
    '# --- Upstream LLM ---',
    `UPSTREAM_PROVIDER=${a.upstreamProvider}`,
    `OPENAI_API_KEY=${a.openaiApiKey}`,
    `OPENAI_BASE_URL=${a.openaiBaseUrl}`,
    `OLLAMA_BASE_URL=${a.ollamaBaseUrl}`,
    `OPENROUTER_API_KEY=${a.openrouterApiKey}`,
    `OPENROUTER_BASE_URL=${a.openrouterBaseUrl}`,
    '',
    '# --- Ports ---',
    `GATEWAY_PORT=${a.gatewayPort}`,
    `DASHBOARD_PORT=${a.dashboardPort}`,
    `GATEWAY_URL=${a.gatewayUrl}`,
    '',
    '# --- Phase 3 ---',
    `PHASEONE_APPROVAL_TIMEOUT_MS=${a.approvalTimeoutMs}`,
    a.siemWebhookUrl
      ? `PHASEONE_SIEM_WEBHOOK_URL=${a.siemWebhookUrl}`
      : '# PHASEONE_SIEM_WEBHOOK_URL=',
    '',
    '# --- Phase 4 ---',
    a.alertWebhookUrl
      ? `PHASEONE_ALERT_WEBHOOK_URL=${a.alertWebhookUrl}`
      : '# PHASEONE_ALERT_WEBHOOK_URL=',
    `PHASEONE_RULES_DIR=${a.rulesDir}`,
    `PHASEONE_METRICS_ENABLED=${a.metricsEnabled}`,
    '# PHASEONE_ALERTS_ENABLED=true',
    '',
    '# --- Phase 5 ---',
    `PHASEONE_RETENTION_DAYS=${a.retentionDays}`,
    '# PHASEONE_RETENTION_PRUNE_APPROVALS=true',
    '# PHASEONE_RETENTION_PRUNE_AUDIT=true',
    `PHASEONE_API_RATE_LIMIT=${a.apiRateLimit}`,
    `PHASEONE_API_RATE_WINDOW_MS=${a.apiRateWindowMs}`,
    `PHASEONE_OTP_RATE_LIMIT=${a.otpRateLimit}`,
    `PHASEONE_BACKUP_DIR=${a.backupDir}`,
    '',
    '# --- Phase 7 (Gatekeeper) ---',
    `PHASEONE_GATEKEEPER_ENABLED=${a.gatekeeperEnabled}`,
    `PHASEONE_GATEKEEPER_DRY_RUN=${a.gatekeeperDryRun}`,
    `PHASEONE_PLAYBOOKS_DIR=${a.playbooksDir}`,
    '# PHASEONE_GATEKEEPER_WEBHOOK_URL=',
    '# PHASEONE_GATEKEEPER_POLL_MS=5000',
    '# PHASEONE_GATEKEEPER_EVENT_WINDOW_MS=60000',
    '',
    '# --- Phase 7 LLM Advisor (optional, advisory only) ---',
    '# Primary: OpenRouter; Fallback: Ollama. LLM advises, playbooks decide.',
    `# PHASEONE_GATEKEEPER_LLM_PRIMARY=${a.gatekeeperLlmPrimary}`,
    `# PHASEONE_GATEKEEPER_LLM_FALLBACK=${a.gatekeeperLlmFallback}`,
    `# PHASEONE_GATEKEEPER_OPENROUTER_MODEL=${a.gatekeeperOpenrouterModel}`,
    `# PHASEONE_GATEKEEPER_OPENROUTER_BASE_URL=${a.gatekeeperOpenrouterBaseUrl}`,
    `# PHASEONE_GATEKEEPER_OLLAMA_BASE_URL=${a.gatekeeperOllamaBaseUrl}`,
    `# PHASEONE_GATEKEEPER_OLLAMA_MODEL=${a.gatekeeperOllamaModel}`,
    '# PHASEONE_GATEKEEPER_LLM_TIMEOUT_MS=30000',
    '# PHASEONE_GATEKEEPER_LLM_MAX_TOKENS=512',
    '',
    '# Optional policy override',
    '# PHASEONE_POLICY_PATH=./policy/default-policy.yaml',
    ''
  );
  return lines.join('\n');
}

export function writeEnvFile(targetPath: string, answers: OnboardAnswers, opts?: { force?: boolean }): {
  path: string;
  wrote: boolean;
  bytes: number;
} {
  if (existsSync(targetPath) && !opts?.force) {
    const bak = `${targetPath}.bak.${Date.now()}`;
    writeFileSync(bak, readFileSync(targetPath));
  }
  const body = renderEnv(answers);
  writeFileSync(targetPath, body, { mode: 0o600 });
  return { path: targetPath, wrote: true, bytes: Buffer.byteLength(body) };
}

async function prompt(rl: ReturnType<typeof createInterface>, q: string, def: string): Promise<string> {
  const suffix = def ? ` [${def}]` : '';
  return new Promise((resolveAns) => {
    rl.question(`${q}${suffix}: `, (ans) => {
      const v = (ans ?? '').trim();
      resolveAns(v || def);
    });
  });
}

async function promptYesNo(rl: ReturnType<typeof createInterface>, q: string, defYes: boolean): Promise<boolean> {
  const def = defYes ? 'Y/n' : 'y/N';
  const ans = await prompt(rl, `${q} (${def})`, defYes ? 'y' : 'n');
  return /^y(es)?$/i.test(ans);
}

export async function runInteractive(root = ROOT): Promise<OnboardAnswers> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const base = defaultAnswers();
  try {
    console.log(BANNER);
    console.log('\nInteractive setup — press Enter to accept defaults.\n');

    console.log(
      '  → Set PHASEONE_ADMIN_EMAILS to real operator addresses (e.g. techpronow@gmail.com).'
    );
    console.log('  → admin@localhost is lab-only and will not receive real MFA email.\n');
    let adminEmails = await prompt(
      rl,
      'Admin email(s) for MFA — real addresses, comma-separated',
      base.adminEmails === 'admin@localhost' ? '' : base.adminEmails
    );
    if (!adminEmails) {
      console.warn(
        '  ⚠ No admin email entered — falling back to admin@localhost (lab only).'
      );
      adminEmails = 'admin@localhost';
    } else if (adminEmails === 'admin@localhost') {
      console.warn(
        '  ⚠ Using admin@localhost — lab only. Re-run onboard with a real inbox before shared use.'
      );
    }
    const useSmtp = await promptYesNo(rl, 'Configure SMTP for OTP delivery?', false);
    let smtpHost = '';
    let smtpPort = base.smtpPort;
    let smtpUser = '';
    let smtpPass = '';
    let smtpFrom = base.smtpFrom;
    let smtpSecure = base.smtpSecure;
    if (useSmtp) {
      smtpHost = await prompt(rl, 'SMTP host', 'smtp.example.com');
      smtpPort = await prompt(rl, 'SMTP port', '587');
      smtpUser = await prompt(rl, 'SMTP user', '');
      smtpPass = await prompt(rl, 'SMTP password', '');
      smtpFrom = await prompt(rl, 'SMTP from address (Veracity/Clovis Star)', base.smtpFrom || 'noreply@clovisstar.com');
      smtpSecure = (await promptYesNo(rl, 'SMTP TLS (secure)?', false)) ? 'true' : 'false';
    } else {
      console.warn('  ⚠ LAB-ONLY: OTP will log to console + PHASEONE_OTP_FALLBACK_FILE — not for production.');
      console.warn('  → Production MFA: set SMTP_* with SMTP_FROM=noreply@clovisstar.com');
    }

    const databaseUrl = await prompt(rl, 'DATABASE_URL', base.databaseUrl);
    const genSecret = await promptYesNo(rl, 'Auto-generate PHASEONE_SESSION_SECRET?', true);
    const sessionSecret = genSecret
      ? generateSessionSecret()
      : await prompt(rl, 'PHASEONE_SESSION_SECRET', base.sessionSecret);

    const upstreamProvider = await prompt(
      rl,
      'Upstream provider (mock|openai|ollama|openrouter)',
      base.upstreamProvider
    );
    let openaiApiKey = base.openaiApiKey;
    let openaiBaseUrl = base.openaiBaseUrl;
    let ollamaBaseUrl = base.ollamaBaseUrl;
    let openrouterApiKey = base.openrouterApiKey;
    let openrouterBaseUrl = base.openrouterBaseUrl;
    if (upstreamProvider === 'openai') {
      openaiApiKey = await prompt(rl, 'OPENAI_API_KEY', openaiApiKey);
      openaiBaseUrl = await prompt(rl, 'OPENAI_BASE_URL', openaiBaseUrl);
    } else if (upstreamProvider === 'ollama') {
      ollamaBaseUrl = await prompt(rl, 'OLLAMA_BASE_URL', ollamaBaseUrl);
    } else if (upstreamProvider === 'openrouter') {
      openrouterApiKey = await prompt(rl, 'OPENROUTER_API_KEY', openrouterApiKey);
      openrouterBaseUrl = await prompt(rl, 'OPENROUTER_BASE_URL', openrouterBaseUrl);
    }

    const gatewayPort = await prompt(rl, 'GATEWAY_PORT', base.gatewayPort);
    const dashboardPort = await prompt(rl, 'DASHBOARD_PORT', base.dashboardPort);
    const gatewayUrl = await prompt(
      rl,
      'GATEWAY_URL (dashboard → gateway)',
      `http://localhost:${gatewayPort}`
    );
    const viewerEmails = await prompt(
      rl,
      'Viewer email(s) read-only (comma-separated, optional)',
      base.viewerEmails
    );
    const siemWebhookUrl = await prompt(rl, 'SIEM webhook URL (optional)', base.siemWebhookUrl);
    const alertWebhookUrl = await prompt(
      rl,
      'Alert webhook URL for high-severity events (optional)',
      base.alertWebhookUrl
    );
    const rulesDir = await prompt(rl, 'Detection rules directory', base.rulesDir);
    const approvalTimeoutMs = await prompt(
      rl,
      'Approval timeout ms',
      base.approvalTimeoutMs
    );
    const otpFallbackFile = await prompt(rl, 'OTP fallback file', base.otpFallbackFile);
    const retentionDays = await prompt(rl, 'Event retention days', base.retentionDays);
    const apiRateLimit = await prompt(rl, 'API rate limit (req/window)', base.apiRateLimit);

    return {
      ...base,
      adminEmails,
      viewerEmails,
      alertWebhookUrl,
      rulesDir,
      retentionDays,
      apiRateLimit,
      useSmtp,
      smtpHost,
      smtpPort,
      smtpUser,
      smtpPass,
      smtpFrom,
      smtpSecure,
      databaseUrl,
      sessionSecret,
      upstreamProvider,
      openaiApiKey,
      openaiBaseUrl,
      ollamaBaseUrl,
      openrouterApiKey,
      openrouterBaseUrl,
      gatewayPort,
      dashboardPort,
      gatewayUrl,
      siemWebhookUrl,
      approvalTimeoutMs,
      otpFallbackFile,
    };
  } finally {
    rl.close();
  }
}

export function parseArgs(argv: string[]): {
  defaults: boolean;
  force: boolean;
  out?: string;
  help: boolean;
} {
  const defaults = argv.includes('--defaults') || argv.includes('-y') || argv.includes('--yes');
  const force = argv.includes('--force') || argv.includes('-f');
  const help = argv.includes('--help') || argv.includes('-h');
  const outIdx = argv.findIndex((a) => a === '--out' || a === '-o');
  const out = outIdx >= 0 ? argv[outIdx + 1] : undefined;
  return { defaults, force, out, help };
}

export async function main(argv = process.argv.slice(2), root = ROOT): Promise<number> {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(BANNER);
    console.log(`
Usage:
  npm run onboard                 Interactive setup → writes .env
  npm run onboard -- --defaults   Non-interactive CI-friendly defaults
  npm run onboard -- --defaults --out /tmp/.env
  npm run onboard -- --force      Overwrite without .bak (still backs up if exists unless --force)

Env overrides (used as defaults): PHASEONE_ADMIN_EMAILS, DATABASE_URL, SMTP_*, UPSTREAM_PROVIDER, …
`);
    return 0;
  }

  console.log(BANNER);
  const answers = args.defaults ? defaultAnswers() : await runInteractive(root);
  if (isWeakSessionSecret(answers.sessionSecret)) {
    answers.sessionSecret = generateSessionSecret();
    console.warn('  ⚠ Regenerated weak/placeholder PHASEONE_SESSION_SECRET (never leave change-me).');
  }
  const target = resolve(root, args.out ?? '.env');
  const result = writeEnvFile(target, answers, { force: args.force || args.defaults });
  console.log(`\n✓ Wrote ${result.path} (${result.bytes} bytes)`);
  console.log(`  Admin emails: ${answers.adminEmails}`);
  if (/admin@localhost/i.test(answers.adminEmails)) {
    console.warn('  ⚠ Admin allowlist still includes admin@localhost — set real emails (e.g. techpronow@gmail.com).');
  }
  console.log(`  SMTP: ${answers.useSmtp && answers.smtpHost ? answers.smtpHost : 'LAB-ONLY console/fallback OTP'}`);
  if (!answers.useSmtp || !answers.smtpHost) {
    console.warn('  ⚠ Configure SMTP (From: noreply@clovisstar.com) before shared/production MFA.');
  }
  if (/change-me|dev-only/i.test(answers.sessionSecret) || answers.sessionSecret.length < 32) {
    console.warn('  ⚠ PHASEONE_SESSION_SECRET looks weak — re-run with auto-generate.');
  }
  console.log(`  Database: ${answers.databaseUrl.replace(/:[^:@]+@/, ':***@')}`);
  console.log(`  Gateway :${answers.gatewayPort} · Dashboard :${answers.dashboardPort}`);
  console.log(`  Upstream: ${answers.upstreamProvider}`);
  try {
    const { ensureCanaryKeys } = await import('../shared/src/canary-sign.js');
    const { signAllCanaries } = await import('../canaries/src/manager.js');
    const keys = ensureCanaryKeys();
    const signed = signAllCanaries();
    console.log(`  Canary signing key: ${keys.keyId} (${signed.signed} packages signed)`);
  } catch (err) {
    console.warn(
      `  ⚠ Canary key generation skipped: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  console.log(`\nNext:`);
  console.log(`  docker compose up --build`);
  console.log(`  open http://localhost:${answers.dashboardPort}  (MFA login)`);
  console.log(`\nVeracity Integrity LLC · https://VeracityIntegrity.com\n`);
  return 0;
}

const isDirect =
  process.argv[1] &&
  (resolve(process.argv[1]) === fileURLToPath(import.meta.url) ||
    process.argv[1].endsWith('scripts/onboard.ts') ||
    process.argv[1].endsWith('onboard.ts'));

if (isDirect) {
  main().then((code) => process.exit(code)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
