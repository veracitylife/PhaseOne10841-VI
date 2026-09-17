/**
 * PhaseOne10841 CLI Command Registry
 * Shared command implementations for CLI and GUI.
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 *
 * DEFENSIVE ONLY — no exploit tooling.
 */

import { spawn, execSync, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const ROOT = resolve(__dirname, '..');

export const VERSION = '0.7.0';
export const PRODUCT_NAME = 'PhaseOne10841';
export const COMPANY = 'Veracity Integrity LLC';
export const WEBSITE = 'https://VeracityIntegrity.com';

export const BANNER = `
╔══════════════════════════════════════════════════════════════╗
║  PhaseOne10841 — Defensive Agent Security Gateway (EDR)     ║
║  CLI Operator Console v${VERSION}                               ║
║  A product of ${COMPANY}                        ║
║  ${WEBSITE}                              ║
║  DEFENSIVE ONLY — no exploit tooling                        ║
╚══════════════════════════════════════════════════════════════╝
`.trim();

export interface CommandResult {
  ok: boolean;
  exitCode: number;
  output: string;
  error?: string;
  data?: unknown;
}

export type CommandCategory = 
  | 'getting-started'
  | 'health-ops'
  | 'defense-detection'
  | 'gatekeeper'
  | 'dangerous';

export interface CommandDefinition {
  name: string;
  description: string;
  usage: string;
  category?: CommandCategory;
  options?: Array<{
    flag: string;
    description: string;
    default?: string;
  }>;
  examples?: string[];
  tips?: string[];
  dangerous?: boolean;
  requiresConfirmation?: boolean;
  execute: (args: string[], opts: CommandOptions) => Promise<CommandResult>;
}

export interface CommandOptions {
  cwd?: string;
  env?: Record<string, string>;
  timeout?: number;
  onOutput?: (data: string) => void;
  onError?: (data: string) => void;
  confirm?: boolean;
}

export const CATEGORY_INFO: Record<CommandCategory, { label: string; icon: string; description: string }> = {
  'getting-started': {
    label: 'Getting Started',
    icon: '🚀',
    description: 'Setup and first-run commands',
  },
  'health-ops': {
    label: 'Health & Operations',
    icon: '🩺',
    description: 'Health checks, metrics, and stack operations',
  },
  'defense-detection': {
    label: 'Defense & Detection',
    icon: '🛡️',
    description: 'Rules, permissions, and lab validation',
  },
  'gatekeeper': {
    label: 'Gatekeeper (Phase 7)',
    icon: '🤖',
    description: 'Automated defense playbooks and orchestration',
  },
  'dangerous': {
    label: 'Dangerous (⚠️ Data Modification)',
    icon: '⚠️',
    description: 'Commands that modify data — require --confirm',
  },
};

export const RECOMMENDED_FIRST_RUN = [
  { step: 1, cmd: 'onboard', desc: 'Generate .env configuration' },
  { step: 2, cmd: 'compose up', desc: 'Start Docker services' },
  { step: 3, cmd: 'health', desc: 'Verify services are running' },
  { step: 4, cmd: 'smoke', desc: 'Run smoke tests' },
  { step: 5, cmd: 'gui', desc: 'Launch browser GUI (optional)' },
];

function getEnvWithDefaults(): Record<string, string> {
  const env = { ...process.env } as Record<string, string>;
  if (!env.GATEWAY_URL) {
    env.GATEWAY_URL = 'http://localhost:8080';
  }
  if (!env.DASHBOARD_URL) {
    env.DASHBOARD_URL = 'http://localhost:3000';
  }
  return env;
}

async function runCommand(
  command: string,
  args: string[],
  opts: CommandOptions = {}
): Promise<CommandResult> {
  const cwd = opts.cwd ?? ROOT;
  const env = { ...getEnvWithDefaults(), ...opts.env };
  const timeout = opts.timeout ?? 270000;

  return new Promise((resolveResult) => {
    const spawnOpts: SpawnOptions = {
      cwd,
      env,
      shell: true,
      stdio: 'pipe',
    };

    const proc = spawn(command, args, spawnOpts);
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    // timeout <= 0 means no timeout (e.g., gui command runs indefinitely)
    const timeoutId = timeout > 0
      ? setTimeout(() => {
          timedOut = true;
          proc.kill('SIGTERM');
        }, timeout)
      : null;

    proc.stdout?.on('data', (data: Buffer) => {
      const str = data.toString();
      stdout += str;
      opts.onOutput?.(str);
    });

    proc.stderr?.on('data', (data: Buffer) => {
      const str = data.toString();
      stderr += str;
      opts.onError?.(str);
    });

    proc.on('close', (code) => {
      if (timeoutId) clearTimeout(timeoutId);
      if (timedOut) {
        resolveResult({
          ok: false,
          exitCode: 124,
          output: stdout,
          error: `Command timed out after ${timeout}ms. ${stderr}`,
        });
      } else {
        resolveResult({
          ok: code === 0,
          exitCode: code ?? 1,
          output: stdout,
          error: stderr || undefined,
        });
      }
    });

    proc.on('error', (err) => {
      if (timeoutId) clearTimeout(timeoutId);
      resolveResult({
        ok: false,
        exitCode: 1,
        output: stdout,
        error: err.message,
      });
    });
  });
}

async function runNpmScript(script: string, args: string[], opts: CommandOptions = {}): Promise<CommandResult> {
  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  return runCommand(npmCmd, ['run', script, '--', ...args], opts);
}

async function runTsx(scriptPath: string, args: string[], opts: CommandOptions = {}): Promise<CommandResult> {
  const tsxPath = join(ROOT, 'node_modules', '.bin', process.platform === 'win32' ? 'tsx.cmd' : 'tsx');
  const fullPath = resolve(ROOT, scriptPath);
  return runCommand(tsxPath, [fullPath, ...args], opts);
}

function formatGroupedHelp(): string {
  const lines = [
    BANNER,
    '',
    '┌─────────────────────────────────────────────────────────────┐',
    '│  DEFENSIVE ONLY — no exploit tooling                       │',
    '│  Product: https://phaseone10841.me                         │',
    '│  Company: https://VeracityIntegrity.com                    │',
    '└─────────────────────────────────────────────────────────────┘',
    '',
    '📋 RECOMMENDED FIRST RUN:',
    '',
  ];

  for (const step of RECOMMENDED_FIRST_RUN) {
    lines.push(`   ${step.step}. phaseone ${step.cmd.padEnd(14)} → ${step.desc}`);
  }

  lines.push('', '─'.repeat(65), '');

  const categoryOrder: CommandCategory[] = ['getting-started', 'health-ops', 'defense-detection', 'gatekeeper', 'dangerous'];
  
  for (const category of categoryOrder) {
    const info = CATEGORY_INFO[category];
    const cmds = commands.filter(c => c.category === category || (category === 'dangerous' && c.dangerous && c.category !== 'gatekeeper'));
    
    if (cmds.length === 0) continue;

    lines.push(`${info.icon} ${info.label.toUpperCase()}`);
    lines.push(`   ${info.description}`);
    lines.push('');

    const maxLen = Math.max(...cmds.map(c => c.name.length));
    for (const cmd of cmds) {
      const warn = cmd.dangerous ? ' ⚠️' : '';
      lines.push(`   ${cmd.name.padEnd(maxLen + 2)} ${cmd.description}${warn}`);
    }
    lines.push('');
  }

  lines.push('─'.repeat(65));
  lines.push('');
  lines.push('💡 TIPS:');
  lines.push('   • Run `phaseone help <command>` for detailed usage + examples');
  lines.push('   • Run `phaseone menu` for interactive exploration');
  lines.push('   • Commands marked ⚠️ require --confirm for destructive actions');
  lines.push('');
  lines.push(`${COMPANY} · ${WEBSITE}`);

  return lines.join('\n');
}

function formatCommandHelp(cmd: CommandDefinition): string {
  const lines = [
    BANNER,
    '',
    `━━━ ${cmd.name.toUpperCase()} ━━━`,
    '',
    `📖 Description: ${cmd.description}`,
    '',
    `📝 Usage: ${cmd.usage}`,
  ];

  if (cmd.category) {
    const info = CATEGORY_INFO[cmd.category];
    lines.push('', `📁 Category: ${info.icon} ${info.label}`);
  }

  if (cmd.options?.length) {
    lines.push('', '⚙️  Options:');
    for (const opt of cmd.options) {
      const def = opt.default ? ` (default: ${opt.default})` : '';
      lines.push(`   ${opt.flag.padEnd(26)} ${opt.description}${def}`);
    }
  }

  if (cmd.examples?.length) {
    lines.push('', '💻 Examples:');
    for (const ex of cmd.examples) {
      lines.push(`   ${ex}`);
    }
  }

  if (cmd.tips?.length) {
    lines.push('', '💡 Tips:');
    for (const tip of cmd.tips) {
      lines.push(`   • ${tip}`);
    }
  }

  if (cmd.dangerous) {
    lines.push('');
    lines.push('⚠️  WARNING: This command modifies data.');
    lines.push('   Pass --confirm to execute, or use --dry-run to preview.');
  }

  lines.push('', '─'.repeat(50));
  lines.push(`${COMPANY} · ${WEBSITE}`);

  return lines.join('\n');
}

function suggestCommands(input: string): string {
  const lowerInput = input.toLowerCase();
  const matches = commands.filter(c => 
    c.name.toLowerCase().includes(lowerInput) ||
    c.description.toLowerCase().includes(lowerInput)
  ).slice(0, 3);

  if (matches.length === 0) return '';

  return `\nDid you mean:\n${matches.map(m => `  • ${m.name} — ${m.description}`).join('\n')}`;
}

async function runInteractiveMenu(): Promise<string> {
  const readline = await import('node:readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = (q: string): Promise<string> => new Promise(resolve => {
    rl.question(q, answer => resolve(answer.trim()));
  });

  const categoryOrder: CommandCategory[] = ['getting-started', 'health-ops', 'defense-detection', 'gatekeeper', 'dangerous'];
  
  console.log(BANNER);
  console.log('');
  console.log('📋 INTERACTIVE MENU — Select a category:');
  console.log('');

  categoryOrder.forEach((cat, i) => {
    const info = CATEGORY_INFO[cat];
    const count = commands.filter(c => c.category === cat || (cat === 'dangerous' && c.dangerous)).length;
    console.log(`  ${i + 1}. ${info.icon} ${info.label} (${count} commands)`);
  });
  console.log('');
  console.log('  0. Exit');
  console.log('');

  const categoryChoice = await prompt('Enter number (0-5): ');
  const catIndex = parseInt(categoryChoice, 10);

  if (isNaN(catIndex) || catIndex === 0 || catIndex < 0 || catIndex > categoryOrder.length) {
    rl.close();
    return '\n✓ Exited menu. Run `phaseone help` anytime.\n';
  }

  const selectedCategory = categoryOrder[catIndex - 1];
  const catInfo = CATEGORY_INFO[selectedCategory];
  const catCommands = commands.filter(c => 
    c.category === selectedCategory || 
    (selectedCategory === 'dangerous' && c.dangerous)
  );

  console.log('');
  console.log(`${catInfo.icon} ${catInfo.label.toUpperCase()}`);
  console.log(`   ${catInfo.description}`);
  console.log('');

  catCommands.forEach((cmd, i) => {
    const warn = cmd.dangerous ? ' ⚠️' : '';
    console.log(`  ${i + 1}. ${cmd.name}${warn} — ${cmd.description}`);
  });
  console.log('');
  console.log('  0. Back to categories');
  console.log('');

  const cmdChoice = await prompt(`Select command (0-${catCommands.length}): `);
  const cmdIndex = parseInt(cmdChoice, 10);

  rl.close();

  if (isNaN(cmdIndex) || cmdIndex === 0 || cmdIndex < 0 || cmdIndex > catCommands.length) {
    return '\n✓ Exited menu. Run `phaseone menu` to try again.\n';
  }

  const selectedCmd = catCommands[cmdIndex - 1];
  return '\n' + formatCommandHelp(selectedCmd);
}

export const commands: CommandDefinition[] = [
  {
    name: 'help',
    description: 'Show help and available commands',
    usage: 'phaseone help [command]',
    category: 'getting-started',
    examples: [
      'phaseone help              # Show all commands by category',
      'phaseone help onboard      # Detailed help for onboard command',
      'phaseone help gatekeeper   # Learn about gatekeeper commands',
    ],
    execute: async (args) => {
      const cmdName = args[0];
      if (cmdName) {
        const cmd = commands.find((c) => c.name === cmdName);
        if (!cmd) {
          const suggestions = suggestCommands(cmdName);
          return {
            ok: false,
            exitCode: 1,
            output: '',
            error: `Unknown command: ${cmdName}\n${suggestions}\nRun 'phaseone help' or 'phaseone menu' for available commands.`,
          };
        }
        return { ok: true, exitCode: 0, output: formatCommandHelp(cmd) };
      }

      return { ok: true, exitCode: 0, output: formatGroupedHelp() };
    },
  },

  {
    name: 'menu',
    description: 'Interactive menu for exploring commands',
    usage: 'phaseone menu',
    category: 'getting-started',
    examples: [
      'phaseone menu   # Launch interactive menu (TTY)',
      'phaseone help   # Non-interactive alternative',
    ],
    tips: [
      'In non-TTY environments (CI), menu falls back to help output',
      'Use arrow keys or numbers to navigate categories',
    ],
    execute: async () => {
      const isTTY = process.stdin.isTTY && !process.env.CI;
      
      if (!isTTY) {
        return { ok: true, exitCode: 0, output: formatGroupedHelp() };
      }

      return { ok: true, exitCode: 0, output: await runInteractiveMenu() };
    },
  },

  {
    name: 'version',
    description: 'Show version information',
    usage: 'phaseone version',
    category: 'getting-started',
    examples: [
      'phaseone version           # Display current version',
      'phaseone -v                # Short form',
    ],
    execute: async () => {
      const pkgPath = join(ROOT, 'package.json');
      let pkgVersion = VERSION;
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
        pkgVersion = pkg.version ?? VERSION;
      } catch {
        // use default
      }
      const output = [
        `${PRODUCT_NAME} v${pkgVersion}`,
        `CLI v${VERSION}`,
        `${COMPANY}`,
        WEBSITE,
        '',
        'Defensive Agent Security Gateway (Agent EDR)',
        'DEFENSIVE ONLY — no exploit tooling',
      ].join('\n');
      return { ok: true, exitCode: 0, output, data: { version: pkgVersion, cli: VERSION } };
    },
  },

  {
    name: 'onboard',
    description: 'Run interactive onboarding or generate .env with defaults',
    usage: 'phaseone onboard [--defaults] [--out <path>]',
    category: 'getting-started',
    options: [
      { flag: '--defaults, -y', description: 'Non-interactive with default values' },
      { flag: '--out, -o <path>', description: 'Output path for .env file', default: '.env' },
      { flag: '--force, -f', description: 'Overwrite existing file without backup' },
    ],
    examples: [
      'phaseone onboard                     # Interactive wizard',
      'phaseone onboard --defaults          # Quick setup with defaults',
      'phaseone onboard --defaults --force  # Overwrite existing .env',
    ],
    tips: [
      'Run this FIRST before compose up',
      'Configures database, gateway, dashboard, and gatekeeper LLM',
      'Backs up existing .env unless --force is used',
    ],
    execute: async (args, opts) => {
      return runTsx('scripts/onboard.ts', args, opts);
    },
  },

  {
    name: 'health',
    description: 'Check gateway and dashboard health endpoints',
    usage: 'phaseone health [--gateway <url>] [--dashboard <url>]',
    category: 'health-ops',
    options: [
      { flag: '--gateway <url>', description: 'Gateway URL', default: 'http://localhost:8080' },
      { flag: '--dashboard <url>', description: 'Dashboard URL', default: 'http://localhost:3000' },
      { flag: '--json', description: 'Output as JSON' },
    ],
    examples: [
      'phaseone health                           # Check local services',
      'phaseone health --json                    # JSON output for scripts',
      'phaseone health --gateway http://gw:8080  # Custom gateway URL',
    ],
    tips: [
      'Run after `compose up` to verify services started',
      'Use --json for CI/scripting integration',
      'Check individual endpoints if some fail',
    ],
    execute: async (args, opts) => {
      const env = getEnvWithDefaults();
      let gatewayUrl = env.GATEWAY_URL ?? 'http://localhost:8080';
      let dashboardUrl = env.DASHBOARD_URL ?? 'http://localhost:3000';
      let json = false;

      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--gateway' && args[i + 1]) gatewayUrl = args[++i];
        else if (args[i] === '--dashboard' && args[i + 1]) dashboardUrl = args[++i];
        else if (args[i] === '--json') json = true;
      }

      const results: Record<string, { status: string; ok: boolean; detail?: string }> = {};
      const endpoints = [
        { name: 'gateway_healthz', url: `${gatewayUrl}/healthz` },
        { name: 'gateway_readyz', url: `${gatewayUrl}/readyz` },
        { name: 'gateway_metrics', url: `${gatewayUrl}/metrics` },
        { name: 'dashboard_healthz', url: `${dashboardUrl}/healthz` },
      ];

      for (const ep of endpoints) {
        try {
          const res = await fetch(ep.url);
          const text = await res.text();
          results[ep.name] = {
            status: res.status.toString(),
            ok: res.ok,
            detail: res.ok ? undefined : text.slice(0, 200),
          };
        } catch (err) {
          results[ep.name] = {
            status: 'error',
            ok: false,
            detail: err instanceof Error ? err.message : String(err),
          };
        }
      }

      const allOk = Object.values(results).every((r) => r.ok);

      if (json) {
        return {
          ok: allOk,
          exitCode: allOk ? 0 : 1,
          output: JSON.stringify({ ok: allOk, endpoints: results }, null, 2),
          data: { ok: allOk, endpoints: results },
        };
      }

      const lines = [`${PRODUCT_NAME} Health Check`, ''];
      for (const [name, r] of Object.entries(results)) {
        const icon = r.ok ? '✓' : '✗';
        lines.push(`${icon} ${name}: ${r.status}${r.detail ? ` — ${r.detail}` : ''}`);
      }
      lines.push('', allOk ? 'All endpoints healthy' : 'Some endpoints unhealthy');
      lines.push(`${COMPANY}`);

      return { ok: allOk, exitCode: allOk ? 0 : 1, output: lines.join('\n'), data: results };
    },
  },

  {
    name: 'ready',
    description: 'Check if services are ready (gateway + db)',
    usage: 'phaseone ready [--gateway <url>]',
    category: 'health-ops',
    options: [
      { flag: '--gateway <url>', description: 'Gateway URL', default: 'http://localhost:8080' },
      { flag: '--json', description: 'Output as JSON' },
    ],
    examples: [
      'phaseone ready         # Quick readiness check',
      'phaseone ready --json  # For scripting',
    ],
    tips: [
      'Use in startup scripts to wait for services',
      'Checks both gateway and database connectivity',
    ],
    execute: async (args) => {
      const env = getEnvWithDefaults();
      let gatewayUrl = env.GATEWAY_URL ?? 'http://localhost:8080';
      let json = false;

      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--gateway' && args[i + 1]) gatewayUrl = args[++i];
        else if (args[i] === '--json') json = true;
      }

      try {
        const res = await fetch(`${gatewayUrl}/readyz`);
        const data = await res.json() as { status?: string };
        const ready = res.ok && data?.status === 'ready';
        const output = json
          ? JSON.stringify({ ready, status: data?.status }, null, 2)
          : `${ready ? '✓' : '✗'} Ready: ${data?.status ?? 'unknown'}`;
        return { ok: ready, exitCode: ready ? 0 : 1, output, data: { ready, status: data?.status } };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const output = json
          ? JSON.stringify({ ready: false, error: msg }, null, 2)
          : `✗ Not ready: ${msg}`;
        return { ok: false, exitCode: 1, output, error: msg };
      }
    },
  },

  {
    name: 'metrics',
    description: 'Fetch Prometheus metrics from gateway',
    usage: 'phaseone metrics [--gateway <url>]',
    category: 'health-ops',
    options: [
      { flag: '--gateway <url>', description: 'Gateway URL', default: 'http://localhost:8080' },
    ],
    examples: [
      'phaseone metrics                    # Full Prometheus output',
      'phaseone metrics | grep phaseone_   # Filter PhaseOne metrics',
    ],
    tips: [
      'Use metrics-sniff for a summarized view',
      'Metrics are in Prometheus text format',
    ],
    execute: async (args) => {
      const env = getEnvWithDefaults();
      let gatewayUrl = env.GATEWAY_URL ?? 'http://localhost:8080';

      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--gateway' && args[i + 1]) gatewayUrl = args[++i];
      }

      try {
        const res = await fetch(`${gatewayUrl}/metrics`);
        const text = await res.text();
        return { ok: res.ok, exitCode: res.ok ? 0 : 1, output: text };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { ok: false, exitCode: 1, output: '', error: msg };
      }
    },
  },

  {
    name: 'smoke',
    description: 'Run post-compose smoke tests',
    usage: 'phaseone smoke [--gateway <url>] [--dashboard <url>]',
    category: 'health-ops',
    options: [
      { flag: '--gateway <url>', description: 'Gateway URL', default: 'http://localhost:8080' },
      { flag: '--dashboard <url>', description: 'Dashboard URL', default: 'http://localhost:3000' },
    ],
    examples: [
      'phaseone smoke                       # Run all smoke tests',
      'phaseone smoke --gateway http://..   # Custom gateway',
    ],
    tips: [
      'Run after health passes to validate full functionality',
      'Tests: healthz, metrics, chat, policy deny, canary, ops endpoint',
    ],
    execute: async (args, opts) => {
      const env: Record<string, string> = {};
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--gateway' && args[i + 1]) env.GATEWAY_URL = args[++i];
        else if (args[i] === '--dashboard' && args[i + 1]) env.DASHBOARD_URL = args[++i];
      }
      return runTsx('scripts/smoke.ts', [], { ...opts, env: { ...opts.env, ...env } });
    },
  },

  {
    name: 'migrate',
    description: 'Run database migrations',
    usage: 'phaseone migrate',
    category: 'health-ops',
    examples: [
      'phaseone migrate  # Apply pending migrations',
    ],
    tips: [
      'Usually handled automatically by compose up',
      'Safe to run multiple times (idempotent)',
    ],
    execute: async (args, opts) => {
      return runTsx('db/migrate.ts', args, opts);
    },
  },

  {
    name: 'retention',
    description: 'Run event retention cleanup',
    usage: 'phaseone retention [--dry-run] [--execute] [--days <n>]',
    category: 'dangerous',
    options: [
      { flag: '--dry-run, -n', description: 'Preview what would be deleted (default)' },
      { flag: '--execute, --apply', description: 'Actually delete old data' },
      { flag: '--days, -d <n>', description: 'Retention period in days', default: '30' },
    ],
    examples: [
      'phaseone retention --dry-run           # Preview (safe)',
      'phaseone retention --dry-run --days 14 # Preview 14-day retention',
      'phaseone retention --execute --confirm # Actually delete ⚠️',
    ],
    tips: [
      'ALWAYS run --dry-run first to preview',
      'Default retention is 30 days',
      'Requires --confirm for actual deletion',
    ],
    dangerous: true,
    requiresConfirmation: true,
    execute: async (args, opts) => {
      const hasExecute = args.includes('--execute') || args.includes('--apply');
      if (hasExecute && !opts.confirm) {
        return {
          ok: false,
          exitCode: 1,
          output: '',
          error: 'Retention --execute requires confirmation. Pass --confirm or use --dry-run.',
        };
      }
      return runTsx('scripts/retention-cleanup.ts', args, opts);
    },
  },

  {
    name: 'backup',
    description: 'Backup Postgres + policy + rules',
    usage: 'phaseone backup',
    category: 'health-ops',
    examples: [
      'phaseone backup  # Create timestamped backup',
    ],
    tips: [
      'Creates backups/YYYYMMDD-HHMMSS/ directory',
      'Includes: database dump, policy YAML, rules YAML',
      'Run before restore or major changes',
    ],
    execute: async (args, opts) => {
      const isWin = process.platform === 'win32';
      if (isWin) {
        const psPath = join(ROOT, 'scripts', 'backup-windows.ps1');
        return runCommand('powershell', ['-ExecutionPolicy', 'Bypass', '-File', psPath], opts);
      }
      return runCommand('bash', [join(ROOT, 'scripts', 'backup.sh')], opts);
    },
  },

  {
    name: 'restore',
    description: 'Restore from backup directory',
    usage: 'phaseone restore <backup-dir>',
    category: 'dangerous',
    examples: [
      'phaseone restore backups/20260916-123000 --confirm  # Restore ⚠️',
    ],
    tips: [
      'REPLACES database contents completely',
      'Always backup current state first',
      'Windows: Use WSL or Git Bash',
    ],
    dangerous: true,
    requiresConfirmation: true,
    execute: async (args, opts) => {
      if (!args[0]) {
        return {
          ok: false,
          exitCode: 1,
          output: '',
          error: 'Usage: phaseone restore <backup-dir>\nExample: phaseone restore backups/20260916-123000',
        };
      }
      if (!opts.confirm) {
        return {
          ok: false,
          exitCode: 1,
          output: '',
          error: 'Restore requires confirmation. This REPLACES database contents.\nPass --confirm to proceed.',
        };
      }
      const isWin = process.platform === 'win32';
      if (isWin) {
        return {
          ok: false,
          exitCode: 1,
          output: '',
          error: 'Restore script requires bash. Use WSL or Git Bash:\n  bash scripts/restore.sh ' + args[0],
        };
      }
      return runCommand('bash', [join(ROOT, 'scripts', 'restore.sh'), args[0]], opts);
    },
  },

  {
    name: 'lab',
    description: 'Run defensive lab harness (inert fixtures + detectors)',
    usage: 'phaseone lab',
    category: 'defense-detection',
    examples: [
      'phaseone lab  # Run lab validation suite',
    ],
    tips: [
      'Uses inert/benign fixtures — no real attacks',
      'Tests detection accuracy against known patterns',
      'Returns JSON with stub and monitor results',
    ],
    execute: async (args, opts) => {
      return runTsx('lab/index.ts', args, opts);
    },
  },

  {
    name: 'permissions',
    description: 'Analyze tool permissions and capability matrix',
    usage: 'phaseone permissions [agent-id]',
    category: 'defense-detection',
    examples: [
      'phaseone permissions                # Analyze default agent',
      'phaseone permissions my-agent-123   # Analyze specific agent',
    ],
    tips: [
      'Reports capability matrix (filesystem, shell, network, MCP)',
      'Identifies excessive agency findings',
      'Useful for security audits',
    ],
    execute: async (args, opts) => {
      return runTsx('gateway/src/permissions.ts', args, opts);
    },
  },

  {
    name: 'compose',
    description: 'Docker Compose operations (up, down, ps, logs)',
    usage: 'phaseone compose <up|down|ps|logs|restart> [service]',
    category: 'health-ops',
    options: [
      { flag: 'up', description: 'Start services (--build)' },
      { flag: 'down', description: 'Stop and remove services' },
      { flag: 'ps', description: 'List running services' },
      { flag: 'logs', description: 'Show service logs' },
      { flag: 'restart', description: 'Restart a service' },
    ],
    examples: [
      'phaseone compose up                # Start all services',
      'phaseone compose up gateway        # Start specific service',
      'phaseone compose ps                # List running services',
      'phaseone compose logs gateway      # View gateway logs',
      'phaseone compose down --confirm    # Stop all services ⚠️',
    ],
    tips: [
      'Run after onboard to start the stack',
      '`compose down` requires --confirm',
      'Use `compose logs` to debug startup issues',
    ],
    dangerous: true,
    execute: async (args, opts) => {
      const action = args[0];
      const service = args[1];

      if (!action || !['up', 'down', 'ps', 'logs', 'restart'].includes(action)) {
        return {
          ok: false,
          exitCode: 1,
          output: '',
          error: 'Usage: phaseone compose <up|down|ps|logs|restart> [service]',
        };
      }

      if (action === 'down' && !opts.confirm) {
        return {
          ok: false,
          exitCode: 1,
          output: '',
          error: 'compose down requires confirmation. Pass --confirm to proceed.',
        };
      }

      const docker = process.platform === 'win32' ? 'docker' : 'docker';
      let composeArgs: string[];

      switch (action) {
        case 'up':
          composeArgs = ['compose', 'up', '--build', '-d'];
          if (service) composeArgs.push(service);
          break;
        case 'down':
          composeArgs = ['compose', 'down'];
          break;
        case 'ps':
          composeArgs = ['compose', 'ps'];
          break;
        case 'logs':
          composeArgs = ['compose', 'logs', '--tail=100'];
          if (service) composeArgs.push(service);
          break;
        case 'restart':
          if (!service) {
            return { ok: false, exitCode: 1, output: '', error: 'Specify service to restart' };
          }
          composeArgs = ['compose', 'restart', service];
          break;
        default:
          composeArgs = ['compose', action];
      }

      return runCommand(docker, composeArgs, opts);
    },
  },

  {
    name: 'rules',
    description: 'List or evaluate detection rules',
    usage: 'phaseone rules [list|evaluate] [options]',
    category: 'defense-detection',
    options: [
      { flag: '--dir <path>', description: 'Rules directory', default: './rules' },
      { flag: '--json', description: 'Output as JSON' },
      { flag: '--event <json>', description: 'Event JSON for evaluate subcommand' },
      { flag: '--file <path>', description: 'Event JSON file for evaluate subcommand' },
    ],
    examples: [
      'phaseone rules                           # List all rules',
      'phaseone rules list --json               # JSON output',
      'phaseone rules evaluate --event \'{"tool_name":"run_shell","decision":"deny"}\'',
      'phaseone rules evaluate --file event.json',
    ],
    tips: [
      'Rules are YAML files in the rules/ directory',
      'Use evaluate to test rule matching against events',
      'Severity levels: low, medium, high, critical',
    ],
    execute: async (args) => {
      let rulesDir = process.env.PHASEONE_RULES_DIR ?? join(ROOT, 'rules');
      let json = false;
      let subcommand = 'list';
      let eventJson = '';
      let eventFile = '';

      for (let i = 0; i < args.length; i++) {
        if (args[i] === 'list' || args[i] === 'evaluate') {
          subcommand = args[i];
        } else if (args[i] === '--dir' && args[i + 1]) {
          rulesDir = args[++i];
        } else if (args[i] === '--json') {
          json = true;
        } else if (args[i] === '--event' && args[i + 1]) {
          eventJson = args[++i];
        } else if (args[i] === '--file' && args[i + 1]) {
          eventFile = args[++i];
        }
      }

      const { readdirSync, readFileSync } = await import('node:fs');
      const { parse } = await import('yaml');

      if (subcommand === 'evaluate') {
        try {
          let eventData: Record<string, unknown> = {};
          if (eventFile) {
            const content = readFileSync(eventFile, 'utf8');
            eventData = JSON.parse(content);
          } else if (eventJson) {
            eventData = JSON.parse(eventJson);
          } else {
            return {
              ok: false,
              exitCode: 1,
              output: '',
              error: 'Usage: phaseone rules evaluate --event \'{"tool_name":"run_shell","decision":"deny"}\' [--dir <path>]\nOr: phaseone rules evaluate --file event.json',
            };
          }

          const { evaluateRules } = await import('../rules/src/engine.js');
          const hits = evaluateRules(eventData, rulesDir);

          if (json) {
            return { ok: true, exitCode: 0, output: JSON.stringify({ event: eventData, hits, count: hits.length }, null, 2), data: { event: eventData, hits } };
          }

          const lines = [`${PRODUCT_NAME} Rules Evaluation`, `Directory: ${rulesDir}`, ''];
          lines.push(`Event: ${JSON.stringify(eventData)}`, '');
          if (hits.length === 0) {
            lines.push('No rules matched.');
          } else {
            lines.push(`Matched ${hits.length} rule(s):`, '');
            for (const hit of hits) {
              lines.push(`  [${hit.level.toUpperCase()}] ${hit.rule_id}: ${hit.title}`);
              lines.push(`    Matched: ${JSON.stringify(hit.matched)}`);
            }
          }
          lines.push('', `${COMPANY}`);
          return { ok: true, exitCode: 0, output: lines.join('\n'), data: { event: eventData, hits } };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return { ok: false, exitCode: 1, output: '', error: `Failed to evaluate rules: ${msg}` };
        }
      }

      try {
        const files = readdirSync(rulesDir).filter((f) => f.endsWith('.yaml'));
        const rules: Array<{ file: string; id?: string; title?: string; severity?: string; level?: string; enabled?: boolean }> = [];

        for (const file of files) {
          try {
            const content = readFileSync(join(rulesDir, file), 'utf8');
            const parsed = parse(content) as { id?: string; title?: string; severity?: string; level?: string; enabled?: boolean };
            rules.push({
              file,
              id: parsed?.id,
              title: parsed?.title,
              severity: parsed?.severity ?? parsed?.level,
              level: parsed?.level,
              enabled: parsed?.enabled !== false,
            });
          } catch {
            rules.push({ file, id: 'parse-error' });
          }
        }

        if (json) {
          return { ok: true, exitCode: 0, output: JSON.stringify(rules, null, 2), data: rules };
        }

        const lines = [`${PRODUCT_NAME} Detection Rules`, `Directory: ${rulesDir}`, ''];
        for (const r of rules) {
          const status = r.enabled === false ? ' (disabled)' : '';
          lines.push(`  ${r.file}: ${r.title ?? r.id ?? 'untitled'} (${r.severity ?? r.level ?? 'unknown'})${status}`);
        }
        lines.push('', `${rules.length} rule(s) found`);
        lines.push('', 'Use `phaseone rules evaluate --event \'...\' ` to test rule matching.');
        return { ok: true, exitCode: 0, output: lines.join('\n'), data: rules };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { ok: false, exitCode: 1, output: '', error: `Failed to list rules: ${msg}` };
      }
    },
  },

  {
    name: 'metrics-sniff',
    description: 'Sniff and display live metrics summary (read-only)',
    usage: 'phaseone metrics-sniff [--gateway <url>] [--interval <ms>] [--count <n>]',
    category: 'health-ops',
    options: [
      { flag: '--gateway <url>', description: 'Gateway URL', default: 'http://localhost:8080' },
      { flag: '--interval <ms>', description: 'Polling interval in ms', default: '5000' },
      { flag: '--count <n>', description: 'Number of samples (0 = continuous)', default: '1' },
      { flag: '--json', description: 'Output as JSON' },
    ],
    examples: [
      'phaseone metrics-sniff                    # Single snapshot',
      'phaseone metrics-sniff --count 5 --interval 3000',
      'phaseone metrics-sniff --count 0          # Continuous polling',
      'phaseone metrics-sniff --json             # For scripting',
    ],
    tips: [
      'Shows key PhaseOne metrics in human-readable format',
      'Use --count 0 for continuous monitoring',
      'Lighter than full Prometheus scrape',
    ],
    execute: async (args) => {
      const env = getEnvWithDefaults();
      let gatewayUrl = env.GATEWAY_URL ?? 'http://localhost:8080';
      let interval = 5000;
      let count = 1;
      let json = false;

      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--gateway' && args[i + 1]) gatewayUrl = args[++i];
        else if (args[i] === '--interval' && args[i + 1]) interval = parseInt(args[++i], 10);
        else if (args[i] === '--count' && args[i + 1]) count = parseInt(args[++i], 10);
        else if (args[i] === '--json') json = true;
      }

      const parseMetrics = (text: string): Record<string, number> => {
        const metrics: Record<string, number> = {};
        const lines = text.split('\n');
        for (const line of lines) {
          if (line.startsWith('#') || !line.trim()) continue;
          const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(\d+(?:\.\d+)?)/);
          if (match) {
            metrics[match[1]] = parseFloat(match[2]);
          }
        }
        return metrics;
      };

      const summaryKeys = [
        'phaseone_requests_total',
        'phaseone_decisions_allow',
        'phaseone_decisions_deny',
        'phaseone_decisions_approval_required',
        'phaseone_canary_triggers_total',
        'phaseone_injection_scans_total',
        'phaseone_injection_blocked_total',
        'phaseone_a2a_messages_total',
        'phaseone_rule_hits_total',
      ];

      const samples: Array<{ timestamp: string; metrics: Record<string, number> }> = [];
      let iterations = 0;

      const fetchSample = async () => {
        try {
          const res = await fetch(`${gatewayUrl}/metrics`);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const text = await res.text();
          const allMetrics = parseMetrics(text);
          const summary: Record<string, number> = {};
          for (const key of summaryKeys) {
            if (key in allMetrics) summary[key] = allMetrics[key];
          }
          return { timestamp: new Date().toISOString(), metrics: summary };
        } catch (err) {
          return { timestamp: new Date().toISOString(), metrics: {}, error: err instanceof Error ? err.message : String(err) };
        }
      };

      const formatSample = (sample: { timestamp: string; metrics: Record<string, number>; error?: string }): string => {
        const lines = [`[${sample.timestamp}]`];
        if (sample.error) {
          lines.push(`  Error: ${sample.error}`);
        } else if (Object.keys(sample.metrics).length === 0) {
          lines.push('  No PhaseOne metrics found (gateway may not have processed requests yet)');
        } else {
          for (const [k, v] of Object.entries(sample.metrics)) {
            const shortKey = k.replace('phaseone_', '');
            lines.push(`  ${shortKey}: ${v}`);
          }
        }
        return lines.join('\n');
      };

      if (count === 1) {
        const sample = await fetchSample();
        samples.push(sample);
        if (json) {
          return { ok: true, exitCode: 0, output: JSON.stringify(sample, null, 2), data: sample };
        }
        const output = [`${PRODUCT_NAME} Metrics Snapshot`, `Gateway: ${gatewayUrl}`, '', formatSample(sample), '', `${COMPANY}`].join('\n');
        return { ok: true, exitCode: 0, output, data: sample };
      }

      while (count === 0 || iterations < count) {
        const sample = await fetchSample();
        samples.push(sample);
        iterations++;
        if (!json) {
          console.log(formatSample(sample));
        }
        if (count > 0 && iterations >= count) break;
        await new Promise((r) => setTimeout(r, interval));
      }

      if (json) {
        return { ok: true, exitCode: 0, output: JSON.stringify(samples, null, 2), data: samples };
      }
      return { ok: true, exitCode: 0, output: `Collected ${samples.length} sample(s)`, data: samples };
    },
  },

  {
    name: 'gui',
    description: 'Launch local GUI for CLI commands',
    usage: 'phaseone gui [--port <n>]',
    category: 'getting-started',
    options: [
      { flag: '--port, -p <n>', description: 'GUI server port', default: '8888' },
    ],
    examples: [
      'phaseone gui              # Start on http://localhost:8888',
      'phaseone gui --port 9000  # Custom port',
    ],
    tips: [
      'Opens browser-based CLI interface',
      'All CLI commands available with forms',
      'Destructive commands show confirmation dialog',
    ],
    execute: async (args, opts) => {
      let port = 8888;
      for (let i = 0; i < args.length; i++) {
        if ((args[i] === '--port' || args[i] === '-p') && args[i + 1]) {
          port = parseInt(args[++i], 10);
        }
      }

      const guiPath = join(ROOT, 'cli', 'gui.ts');
      if (!existsSync(guiPath)) {
        return { ok: false, exitCode: 1, output: '', error: 'GUI server not found' };
      }

      console.log(`Starting ${PRODUCT_NAME} GUI on http://localhost:${port}`);
      console.log(`${COMPANY} · ${WEBSITE}`);
      console.log('');
      console.log('Press Ctrl+C to stop');

      const result = await runTsx('cli/gui.ts', ['--port', port.toString()], {
        ...opts,
        timeout: 0,
        onOutput: (data) => process.stdout.write(data),
        onError: (data) => process.stderr.write(data),
      });

      return result;
    },
  },

  {
    name: 'gatekeeper',
    description: 'Manage automated defense playbooks (status, run, dry-run, simulate, list-playbooks, llm-check)',
    usage: 'phaseone gatekeeper <status|run|dry-run|simulate|blast-radius|list-playbooks|confirm|deny|llm-check> [options]',
    category: 'gatekeeper',
    options: [
      { flag: 'status', description: 'Show gatekeeper status and config' },
      { flag: 'run', description: 'Process queued events through playbooks' },
      { flag: 'dry-run', description: 'Run playbooks in dry-run mode (no mutations)' },
      { flag: 'simulate', description: 'Dry-run simulation of historical events (Phase 8)' },
      { flag: 'blast-radius', description: 'Calculate blast-radius summary (Phase 8)' },
      { flag: 'list-playbooks', description: 'List available playbooks' },
      { flag: 'confirm <id>', description: 'Confirm a pending action' },
      { flag: 'deny <id>', description: 'Deny a pending action' },
      { flag: 'llm-check', description: 'Check LLM advisor configuration and health' },
      { flag: '--dir <path>', description: 'Playbooks directory', default: './playbooks' },
      { flag: '--json', description: 'Output as JSON' },
      { flag: '--event <json>', description: 'Process a single event (JSON)' },
      { flag: '--limit <n>', description: 'Limit events for simulate/blast-radius', default: '100' },
      { flag: '--event-type <type>', description: 'Filter by event type for simulate' },
      { flag: '--verbose', description: 'Show detailed simulation output' },
    ],
    examples: [
      'phaseone gatekeeper status                   # View current state',
      'phaseone gatekeeper list-playbooks           # See available playbooks',
      'phaseone gatekeeper dry-run                  # Safe test run (DEFAULT)',
      'phaseone gatekeeper run                      # Live processing',
      'phaseone gatekeeper dry-run --event \'{"event_type":"canary_trigger","severity":"high"}\'',
      'phaseone gatekeeper confirm abc-123          # Approve pending action',
      'phaseone gatekeeper llm-check                # Check LLM advisor health',
      'phaseone gatekeeper simulate --limit 50      # Simulate last 50 events',
      'phaseone gatekeeper blast-radius             # Show blast-radius summary',
    ],
    tips: [
      '🛡️ DRY-RUN IS DEFAULT — no mutations without explicit run',
      '🔒 HARDEN tier actions require human confirmation',
      '🤖 LLM advisor is ADVISORY ONLY — playbooks decide mutations',
      'Use llm-check to verify OpenRouter/Ollama connectivity',
      'High-impact actions (rotate_canary, reload_rules) require confirm/deny',
    ],
    execute: async (args) => {
      let subcommand = 'status';
      let playbooksDir = process.env.PHASEONE_PLAYBOOKS_DIR ?? join(ROOT, 'playbooks');
      let json = false;
      let eventJson = '';
      let confirmationId = '';

      for (let i = 0; i < args.length; i++) {
        if (['status', 'run', 'dry-run', 'list-playbooks', 'confirm', 'deny', 'llm-check', 'simulate', 'blast-radius'].includes(args[i])) {
          subcommand = args[i];
          if ((subcommand === 'confirm' || subcommand === 'deny') && args[i + 1]) {
            confirmationId = args[++i];
          }
        } else if (args[i] === '--dir' && args[i + 1]) {
          playbooksDir = args[++i];
        } else if (args[i] === '--json') {
          json = true;
        } else if (args[i] === '--event' && args[i + 1]) {
          eventJson = args[++i];
        }
      }

      try {
        const { loadPlaybooks, listPlaybooksDetailed } = await import('../gatekeeper/src/playbooks.js');
        const {
          getGatekeeperStatus,
          processEvent,
          runGatekeeperCycle,
          confirmPendingAction,
          denyPendingAction,
          loadGatekeeperConfig,
        } = await import('../gatekeeper/src/worker.js');

        if (subcommand === 'list-playbooks') {
          const playbooks = listPlaybooksDetailed(playbooksDir);

          if (json) {
            return { ok: true, exitCode: 0, output: JSON.stringify(playbooks, null, 2), data: playbooks };
          }

          const lines = [`${PRODUCT_NAME} Gatekeeper Playbooks`, `Directory: ${playbooksDir}`, ''];
          if (playbooks.length === 0) {
            lines.push('No playbooks found.');
          } else {
            const tierOrder = { observe: 1, contain: 2, harden: 3 };
            const sorted = [...playbooks].sort((a, b) => tierOrder[a.tier] - tierOrder[b.tier]);

            for (const p of sorted) {
              const status = p.enabled ? '' : ' (disabled)';
              const tierIcon = p.tier === 'observe' ? '👁️' : p.tier === 'contain' ? '🛡️' : '🔒';
              lines.push(`  ${tierIcon} [${p.tier.toUpperCase()}] ${p.id}${status}`);
              lines.push(`     ${p.name}`);
              if (p.description) lines.push(`     ${p.description}`);
              lines.push(`     Actions: ${p.actions.map(a => a.type).join(', ')}`);
              lines.push('');
            }
          }
          lines.push(`${playbooks.length} playbook(s) found`, '', `${COMPANY}`);
          return { ok: true, exitCode: 0, output: lines.join('\n'), data: playbooks };
        }

        if (subcommand === 'status') {
          const status = getGatekeeperStatus();
          const config = loadGatekeeperConfig();

          if (json) {
            return { ok: true, exitCode: 0, output: JSON.stringify({ status, config }, null, 2), data: { status, config } };
          }

          const lines = [
            `${PRODUCT_NAME} Gatekeeper Status`,
            '',
            `Enabled: ${status.state.enabled ? '✓ Yes' : '✗ No'}`,
            `Dry-run: ${status.state.dry_run ? '✓ Yes (safe mode)' : '✗ No (live)'}`,
            `Last run: ${status.state.last_run_at ?? 'Never'}`,
            `Executions: ${status.state.executions_count}`,
            `Pending confirmations: ${status.state.pending_confirmations.length}`,
            `Recent actions: ${status.state.recent_actions.length}`,
            `Queue size: ${status.queue_size}`,
            '',
            'Configuration:',
            `  Playbooks dir: ${config.playbooks_dir}`,
            `  Poll interval: ${config.poll_interval_ms}ms`,
            `  Event window: ${config.event_window_ms}ms`,
            `  Webhook: ${config.webhook_url ?? '(not set)'}`,
            '',
          ];

          if (status.state.pending_confirmations.length > 0) {
            lines.push('Pending Confirmations:');
            for (const p of status.state.pending_confirmations) {
              lines.push(`  ${p.id}: ${p.action_type} (${p.playbook_id}) — expires ${p.expires_at}`);
            }
            lines.push('');
          }

          if (Object.keys(status.overrides).length > 0) {
            lines.push('Active Overrides:');
            for (const [k, v] of Object.entries(status.overrides)) {
              lines.push(`  ${k}: ${JSON.stringify(v)}`);
            }
            lines.push('');
          }

          lines.push(`${COMPANY}`);
          return { ok: true, exitCode: 0, output: lines.join('\n'), data: { status, config } };
        }

        if (subcommand === 'run' || subcommand === 'dry-run') {
          const dryRun = subcommand === 'dry-run';

          if (eventJson) {
            const event = JSON.parse(eventJson);
            event.id = event.id ?? `cli-${Date.now()}`;
            event.timestamp = event.timestamp ?? Date.now();
            const executions = await processEvent(event, { dryRunOverride: dryRun, playbooksDir });

            if (json) {
              return { ok: true, exitCode: 0, output: JSON.stringify({ event, executions }, null, 2), data: { event, executions } };
            }

            const lines = [`${PRODUCT_NAME} Gatekeeper ${dryRun ? 'Dry-Run' : 'Run'}`, ''];
            lines.push(`Event: ${event.event_type} (${event.rule_id ?? 'no rule'})`);
            if (executions.length === 0) {
              lines.push('No playbooks matched.');
            } else {
              lines.push(`Matched ${executions.length} playbook(s):`);
              for (const exec of executions) {
                lines.push(`  ${exec.playbook_name} (${exec.tier})`);
                for (const action of exec.actions) {
                  const icon = action.ok ? '✓' : action.requires_confirmation ? '⏳' : '✗';
                  lines.push(`    ${icon} ${action.action_type}: ${action.detail ?? action.error ?? 'done'}`);
                }
              }
            }
            lines.push('', `${COMPANY}`);
            return { ok: true, exitCode: 0, output: lines.join('\n'), data: { event, executions } };
          }

          const result = await runGatekeeperCycle({ dryRunOverride: dryRun, playbooksDir });

          if (json) {
            return { ok: true, exitCode: 0, output: JSON.stringify(result, null, 2), data: result };
          }

          const lines = [
            `${PRODUCT_NAME} Gatekeeper ${dryRun ? 'Dry-Run' : 'Run'} Complete`,
            '',
            `Processed: ${result.processed} event(s)`,
            `Executions: ${result.executions.length}`,
          ];
          if (result.executions.length > 0) {
            lines.push('', 'Playbooks executed:');
            for (const exec of result.executions) {
              lines.push(`  ${exec.playbook_name} — ${exec.actions.length} action(s)`);
            }
          }
          lines.push('', `${COMPANY}`);
          return { ok: true, exitCode: 0, output: lines.join('\n'), data: result };
        }

        if (subcommand === 'confirm') {
          if (!confirmationId) {
            return { ok: false, exitCode: 1, output: '', error: 'Usage: phaseone gatekeeper confirm <id>' };
          }
          const result = await confirmPendingAction(confirmationId, 'cli-admin');

          if (json) {
            return { ok: result.ok, exitCode: result.ok ? 0 : 1, output: JSON.stringify(result, null, 2), data: result };
          }

          if (result.ok) {
            return { ok: true, exitCode: 0, output: `✓ Confirmed: ${confirmationId}\n${result.execution?.actions[0]?.detail ?? ''}` };
          }
          return { ok: false, exitCode: 1, output: '', error: result.error ?? 'Failed to confirm' };
        }

        if (subcommand === 'deny') {
          if (!confirmationId) {
            return { ok: false, exitCode: 1, output: '', error: 'Usage: phaseone gatekeeper deny <id>' };
          }
          const result = await denyPendingAction(confirmationId, 'cli-admin');

          if (json) {
            return { ok: result.ok, exitCode: result.ok ? 0 : 1, output: JSON.stringify(result, null, 2), data: result };
          }

          if (result.ok) {
            return { ok: true, exitCode: 0, output: `✓ Denied: ${confirmationId}` };
          }
          return { ok: false, exitCode: 1, output: '', error: result.error ?? 'Failed to deny' };
        }

        if (subcommand === 'llm-check') {
          const { getAdvisorConfig, getAdvisorHealth } = await import('../gatekeeper/src/worker.js');
          const config = getAdvisorConfig();

          const lines = [
            `${PRODUCT_NAME} Gatekeeper LLM Advisor Check`,
            '',
            'Configuration:',
            `  Enabled: ${config.enabled ? '✓ Yes' : '✗ No'}`,
            `  Primary: ${config.primary}`,
            `  Fallback: ${config.fallback}`,
            '',
            'OpenRouter:',
            `  Configured: ${(config.openrouter as { configured?: boolean })?.configured ? '✓ Yes (API key set)' : '✗ No (OPENROUTER_API_KEY not set)'}`,
            `  Base URL: ${(config.openrouter as { base_url?: string })?.base_url}`,
            `  Model: ${(config.openrouter as { model?: string })?.model}`,
            '',
            'Ollama:',
            `  Base URL: ${(config.ollama as { base_url?: string })?.base_url}`,
            `  Model: ${(config.ollama as { model?: string })?.model}`,
            '',
          ];

          let health: Awaited<ReturnType<typeof getAdvisorHealth>> | null = null;
          if ((config.openrouter as { configured?: boolean })?.configured || (config.ollama as { base_url?: string })?.base_url) {
            lines.push('Running health checks...');
            try {
              health = await getAdvisorHealth();
              lines.push('');
              lines.push('Health Check Results:');
              lines.push(`  OpenRouter: ${health.openrouter.ok ? `✓ OK (${health.openrouter.latency_ms}ms)` : `✗ Failed: ${health.openrouter.error}`}`);
              lines.push(`  Ollama: ${health.ollama.ok ? `✓ OK (${health.ollama.latency_ms}ms)` : `✗ Failed: ${health.ollama.error}`}`);
              lines.push(`  Recommended: ${health.recommended_provider || '(none available)'}`);
            } catch (err) {
              const errMsg = err instanceof Error ? err.message : String(err);
              lines.push(`  Error: ${errMsg}`);
            }
          } else {
            lines.push('⚠ No providers configured. Set OPENROUTER_API_KEY or configure Ollama.');
          }

          lines.push('', `${COMPANY}`);

          if (json) {
            return { ok: true, exitCode: 0, output: JSON.stringify({ config, health }, null, 2), data: { config, health } };
          }

          return { ok: true, exitCode: 0, output: lines.join('\n'), data: { config, health } };
        }

        if (subcommand === 'simulate' || subcommand === 'blast-radius') {
          const { simulateEvents, calculateBlastRadius, getRateCapStatus } = await import('../shared/src/gatekeeper.js');
          const { listEvents } = await import('../recorder/src/recorder.js');
          
          let limit = 100;
          let eventType = '';
          let verbose = false;
          
          for (let i = 0; i < args.length; i++) {
            if ((args[i] === '--limit' || args[i] === '-l') && args[i + 1]) {
              limit = parseInt(args[++i], 10);
            } else if ((args[i] === '--event-type' || args[i] === '-t') && args[i + 1]) {
              eventType = args[++i];
            } else if (args[i] === '--verbose' || args[i] === '-v') {
              verbose = true;
            }
          }

          const events = await listEvents({ eventType: eventType || undefined, limit });
          const simEvents = events.map(e => ({
            id: e.id,
            timestamp: e.created_at,
            event_type: e.event_type,
            agent_id: e.agent_id,
            session_id: e.session_id,
            tool_name: e.tool_name,
            destination: e.destination,
          }));

          const output = simulateEvents(simEvents, { max_events: limit, event_types: eventType ? [eventType] : undefined });

          if (subcommand === 'blast-radius') {
            const blast = output.blast_radius;
            if (json) {
              return { ok: true, exitCode: 0, output: JSON.stringify(blast, null, 2), data: blast };
            }
            
            const lines = [
              `${PRODUCT_NAME} Gatekeeper Blast-Radius Summary`,
              '',
              `Events analyzed: ${blast.total_events}`,
              `Blocked: ${blast.blocked_count}`,
              `Approval required: ${blast.approval_required_count}`,
              `Allowed: ${blast.allowed_count}`,
              '',
              `Affected agents: ${blast.affected_agents.length}`,
              `Affected tools: ${blast.affected_tools.length}`,
              `Affected domains: ${blast.affected_domains.length}`,
            ];
            if (verbose && Object.keys(blast.rule_hits).length > 0) {
              lines.push('', 'Rule hits:');
              for (const [rule, count] of Object.entries(blast.rule_hits)) {
                lines.push(`  ${rule}: ${count}`);
              }
            }
            lines.push('', `${COMPANY}`);
            return { ok: true, exitCode: 0, output: lines.join('\n'), data: blast };
          }

          if (json) {
            return { ok: true, exitCode: 0, output: JSON.stringify(output, null, 2), data: output };
          }

          const lines = [
            `${PRODUCT_NAME} Gatekeeper Simulation`,
            '',
            `Events simulated: ${output.results.length}`,
            `Simulation time: ${output.simulation_time_ms}ms`,
            '',
            'Summary:',
            `  Would block: ${output.blast_radius.blocked_count}`,
            `  Would require approval: ${output.blast_radius.approval_required_count}`,
            `  Would allow: ${output.blast_radius.allowed_count}`,
          ];
          if (verbose && output.results.length > 0) {
            lines.push('', 'Results:');
            for (const r of output.results.slice(0, 20)) {
              const icon = r.would_block ? '✗' : r.would_require_approval ? '⏳' : '✓';
              lines.push(`  ${icon} ${r.event.event_type ?? 'unknown'} (${r.event.agent_id ?? 'unknown'})`);
            }
            if (output.results.length > 20) {
              lines.push(`  ... and ${output.results.length - 20} more`);
            }
          }
          lines.push('', `${COMPANY}`);
          return { ok: true, exitCode: 0, output: lines.join('\n'), data: output };
        }

        return { ok: false, exitCode: 1, output: '', error: 'Unknown subcommand. Use: status, run, dry-run, simulate, blast-radius, list-playbooks, confirm, deny, llm-check' };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { ok: false, exitCode: 1, output: '', error: `Gatekeeper error: ${msg}` };
      }
    },
  },
];

export function findCommand(name: string): CommandDefinition | undefined {
  return commands.find((c) => c.name === name);
}

export async function executeCommand(
  name: string,
  args: string[],
  opts: CommandOptions = {}
): Promise<CommandResult> {
  const cmd = findCommand(name);
  if (!cmd) {
    return {
      ok: false,
      exitCode: 1,
      output: '',
      error: `Unknown command: ${name}\nRun 'phaseone help' for available commands.`,
    };
  }

  const hasConfirm = args.includes('--confirm') || args.includes('-y');
  const filteredArgs = args.filter((a) => a !== '--confirm' && a !== '-y');

  return cmd.execute(filteredArgs, { ...opts, confirm: hasConfirm || opts.confirm });
}

export { runCommand, runTsx, runNpmScript };
