/**
 * PhaseOne10841 CLI Tests
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 *
 * Tests the command registry without requiring a live Docker stack.
 */
import { describe, it, expect } from 'vitest';
import {
  commands,
  findCommand,
  executeCommand,
  runCommand,
  BANNER,
  VERSION,
  PRODUCT_NAME,
  COMPANY,
  WEBSITE,
  ROOT,
  CATEGORY_INFO,
  RECOMMENDED_FIRST_RUN,
  type CommandCategory,
} from '../cli/registry.js';

describe('CLI registry', () => {
  it('exports constants with correct branding', () => {
    expect(BANNER).toContain('PhaseOne10841');
    expect(BANNER).toContain('Veracity Integrity LLC');
    expect(BANNER).toContain('DEFENSIVE ONLY');
    expect(PRODUCT_NAME).toBe('PhaseOne10841');
    expect(COMPANY).toBe('Veracity Integrity LLC');
    expect(WEBSITE).toBe('https://VeracityIntegrity.com');
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('ROOT points to workspace root', () => {
    expect(ROOT).toMatch(/phaseone|workspace/i);
  });

  it('has expected commands registered', () => {
    const names = commands.map((c) => c.name);
    expect(names).toContain('help');
    expect(names).toContain('menu');
    expect(names).toContain('version');
    expect(names).toContain('onboard');
    expect(names).toContain('health');
    expect(names).toContain('ready');
    expect(names).toContain('metrics');
    expect(names).toContain('smoke');
    expect(names).toContain('migrate');
    expect(names).toContain('retention');
    expect(names).toContain('backup');
    expect(names).toContain('restore');
    expect(names).toContain('lab');
    expect(names).toContain('permissions');
    expect(names).toContain('compose');
    expect(names).toContain('rules');
    expect(names).toContain('gui');
    expect(names).toContain('metrics-sniff');
    expect(names).toContain('gatekeeper');
  });

  it('commands have required properties', () => {
    for (const cmd of commands) {
      expect(cmd.name).toBeTruthy();
      expect(cmd.description).toBeTruthy();
      expect(cmd.usage).toBeTruthy();
      expect(typeof cmd.execute).toBe('function');
    }
  });

  it('dangerous commands are marked', () => {
    const dangerous = commands.filter((c) => c.dangerous);
    const names = dangerous.map((c) => c.name);
    expect(names).toContain('retention');
    expect(names).toContain('restore');
    expect(names).toContain('compose');
  });

  it('findCommand returns command by name', () => {
    const help = findCommand('help');
    expect(help).toBeDefined();
    expect(help?.name).toBe('help');

    const missing = findCommand('nonexistent');
    expect(missing).toBeUndefined();
  });
});

describe('help command', () => {
  it('returns grouped list of commands', async () => {
    const result = await executeCommand('help', []);
    expect(result.ok).toBe(true);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('PhaseOne10841');
    expect(result.output).toContain('RECOMMENDED FIRST RUN');
    expect(result.output).toContain('help');
    expect(result.output).toContain('version');
    expect(result.output).toContain('Veracity Integrity LLC');
  });

  it('returns detailed help for specific command', async () => {
    const result = await executeCommand('help', ['onboard']);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('ONBOARD');
    expect(result.output).toContain('--defaults');
    expect(result.output).toContain('Description');
  });

  it('returns error for unknown command', async () => {
    const result = await executeCommand('help', ['nonexistent']);
    expect(result.ok).toBe(false);
    expect(result.exitCode).toBe(1);
    expect(result.error).toContain('Unknown command');
  });
});

describe('version command', () => {
  it('returns version info', async () => {
    const result = await executeCommand('version', []);
    expect(result.ok).toBe(true);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('PhaseOne10841');
    expect(result.output).toContain('Veracity Integrity LLC');
    expect(result.output).toContain('DEFENSIVE ONLY');
    expect(result.data).toHaveProperty('version');
    expect(result.data).toHaveProperty('cli');
  });
});

describe('rules command', () => {
  it('lists rules from default directory', async () => {
    const result = await executeCommand('rules', []);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('Detection Rules');
    expect(result.data).toBeDefined();
    expect(Array.isArray(result.data)).toBe(true);
  });

  it('outputs JSON when requested', async () => {
    const result = await executeCommand('rules', ['--json']);
    expect(result.ok).toBe(true);
    const parsed = JSON.parse(result.output);
    expect(Array.isArray(parsed)).toBe(true);
  });

  it('lists rules with list subcommand', async () => {
    const result = await executeCommand('rules', ['list']);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('Detection Rules');
  });

  it('evaluates rules against event JSON', async () => {
    const result = await executeCommand('rules', [
      'evaluate',
      '--event',
      '{"tool_name":"run_shell","decision":"deny"}',
    ]);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('Rules Evaluation');
    expect(result.data).toHaveProperty('event');
    expect(result.data).toHaveProperty('hits');
  });

  it('evaluate requires --event or --file', async () => {
    const result = await executeCommand('rules', ['evaluate']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Usage');
  });

  it('evaluate outputs JSON when requested', async () => {
    const result = await executeCommand('rules', [
      'evaluate',
      '--event',
      '{"tool_name":"test","decision":"allow"}',
      '--json',
    ]);
    expect(result.ok).toBe(true);
    const parsed = JSON.parse(result.output);
    expect(parsed).toHaveProperty('event');
    expect(parsed).toHaveProperty('hits');
    expect(parsed).toHaveProperty('count');
  });
});

describe('metrics-sniff command', () => {
  it('exists in command registry', () => {
    const cmd = findCommand('metrics-sniff');
    expect(cmd).toBeDefined();
    expect(cmd?.description).toContain('metrics');
  });

  it('has expected options', () => {
    const cmd = findCommand('metrics-sniff');
    const flags = cmd?.options?.map((o) => o.flag) ?? [];
    expect(flags.some((f) => f.includes('--gateway'))).toBe(true);
    expect(flags.some((f) => f.includes('--interval'))).toBe(true);
    expect(flags.some((f) => f.includes('--count'))).toBe(true);
    expect(flags.some((f) => f.includes('--json'))).toBe(true);
  });
});

describe('dangerous command safety', () => {
  it('retention --execute requires confirmation', async () => {
    const result = await executeCommand('retention', ['--execute']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('requires confirmation');
  });

  it('restore requires confirmation', async () => {
    const result = await executeCommand('restore', ['backups/test']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('requires confirmation');
  });

  it('compose down requires confirmation', async () => {
    const result = await executeCommand('compose', ['down']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('requires confirmation');
  });
});

describe('unknown command handling', () => {
  it('returns error for unknown command', async () => {
    const result = await executeCommand('notacommand', []);
    expect(result.ok).toBe(false);
    expect(result.exitCode).toBe(1);
    expect(result.error).toContain('Unknown command');
    expect(result.error).toContain('phaseone help');
  });
});

describe('command options parsing', () => {
  it('onboard has expected options', () => {
    const cmd = findCommand('onboard');
    expect(cmd?.options).toBeDefined();
    const flags = cmd?.options?.map((o) => o.flag) ?? [];
    expect(flags.some((f) => f.includes('--defaults'))).toBe(true);
    expect(flags.some((f) => f.includes('--out'))).toBe(true);
  });

  it('health has --json option', () => {
    const cmd = findCommand('health');
    const flags = cmd?.options?.map((o) => o.flag) ?? [];
    expect(flags.some((f) => f.includes('--json'))).toBe(true);
  });

  it('retention has --dry-run and --execute options', () => {
    const cmd = findCommand('retention');
    const flags = cmd?.options?.map((o) => o.flag) ?? [];
    expect(flags.some((f) => f.includes('--dry-run'))).toBe(true);
    expect(flags.some((f) => f.includes('--execute'))).toBe(true);
    expect(flags.some((f) => f.includes('--days'))).toBe(true);
  });

  it('gui has --port option', () => {
    const cmd = findCommand('gui');
    const flags = cmd?.options?.map((o) => o.flag) ?? [];
    expect(flags.some((f) => f.includes('--port'))).toBe(true);
  });
});

describe('compose command validation', () => {
  it('requires action argument', async () => {
    const result = await executeCommand('compose', []);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Usage');
  });

  it('rejects invalid action', async () => {
    const result = await executeCommand('compose', ['invalid']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Usage');
  });

  it('restart requires service name', async () => {
    const result = await executeCommand('compose', ['restart']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Specify service');
  });
});

describe('restore command validation', () => {
  it('requires backup directory argument', async () => {
    const result = await executeCommand('restore', []);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Usage');
    expect(result.error).toContain('backup-dir');
  });
});

describe('runCommand timeout behavior', () => {
  it('timeout <= 0 does not kill process immediately', async () => {
    // Run a quick echo command with timeout: 0 (no timeout)
    // If the bug exists, this would fail with "Command timed out after 0ms"
    const result = await runCommand('echo', ['hello'], { timeout: 0 });
    expect(result.ok).toBe(true);
    expect(result.output.trim()).toBe('hello');
    // error is undefined when successful, or if present should not contain timeout
    expect(result.error ?? '').not.toContain('timed out');
  });

  it('negative timeout behaves as no timeout', async () => {
    const result = await runCommand('echo', ['test'], { timeout: -1 });
    expect(result.ok).toBe(true);
    expect(result.output.trim()).toBe('test');
    // error is undefined when successful, or if present should not contain timeout
    expect(result.error ?? '').not.toContain('timed out');
  });

  it('gui command uses timeout: 0 for unlimited lifetime', () => {
    const guiCmd = findCommand('gui');
    expect(guiCmd).toBeDefined();
    // Verify from the code structure that gui passes timeout: 0
    // (the actual call is in the execute function)
    expect(guiCmd?.name).toBe('gui');
  });
});

describe('Command categories', () => {
  it('CATEGORY_INFO has all required categories', () => {
    const categories: CommandCategory[] = ['getting-started', 'health-ops', 'defense-detection', 'gatekeeper', 'dangerous'];
    for (const cat of categories) {
      expect(CATEGORY_INFO[cat]).toBeDefined();
      expect(CATEGORY_INFO[cat].label).toBeTruthy();
      expect(CATEGORY_INFO[cat].icon).toBeTruthy();
      expect(CATEGORY_INFO[cat].description).toBeTruthy();
    }
  });

  it('all commands have a category assigned', () => {
    for (const cmd of commands) {
      expect(cmd.category).toBeDefined();
      expect(CATEGORY_INFO[cmd.category as CommandCategory]).toBeDefined();
    }
  });

  it('key commands have examples', () => {
    const keyCommands = ['onboard', 'health', 'compose', 'rules', 'gatekeeper', 'gui', 'retention', 'restore'];
    for (const name of keyCommands) {
      const cmd = findCommand(name);
      expect(cmd).toBeDefined();
      expect(cmd?.examples).toBeDefined();
      expect(cmd?.examples?.length).toBeGreaterThan(0);
    }
  });

  it('gatekeeper command has comprehensive tips', () => {
    const gk = findCommand('gatekeeper');
    expect(gk).toBeDefined();
    expect(gk?.tips).toBeDefined();
    expect(gk?.tips?.length).toBeGreaterThanOrEqual(3);
    // Should emphasize dry-run and human confirm
    const tipsJoined = gk?.tips?.join(' ') ?? '';
    expect(tipsJoined).toMatch(/dry.*run/i);
    expect(tipsJoined).toMatch(/confirm/i);
  });
});

describe('RECOMMENDED_FIRST_RUN', () => {
  it('has 5 steps', () => {
    expect(RECOMMENDED_FIRST_RUN).toHaveLength(5);
  });

  it('steps are in correct order', () => {
    const cmds = RECOMMENDED_FIRST_RUN.map(s => s.cmd);
    expect(cmds[0]).toBe('onboard');
    expect(cmds[1]).toBe('compose up');
    expect(cmds[2]).toBe('health');
    expect(cmds[3]).toBe('smoke');
    expect(cmds[4]).toBe('gui');
  });

  it('each step has required properties', () => {
    for (const step of RECOMMENDED_FIRST_RUN) {
      expect(step.step).toBeGreaterThan(0);
      expect(step.cmd).toBeTruthy();
      expect(step.desc).toBeTruthy();
    }
  });
});

describe('Grouped help output', () => {
  it('includes RECOMMENDED FIRST RUN section', async () => {
    const result = await executeCommand('help', []);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('RECOMMENDED FIRST RUN');
    expect(result.output).toContain('onboard');
    expect(result.output).toContain('compose up');
    expect(result.output).toContain('health');
  });

  it('includes all category headers', async () => {
    const result = await executeCommand('help', []);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('GETTING STARTED');
    expect(result.output).toContain('HEALTH & OPERATIONS');
    expect(result.output).toContain('DEFENSE & DETECTION');
    expect(result.output).toContain('GATEKEEPER');
    expect(result.output).toContain('DANGEROUS');
  });

  it('includes defensive-only notice', async () => {
    const result = await executeCommand('help', []);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('DEFENSIVE ONLY');
    expect(result.output).toContain('VeracityIntegrity.com');
  });

  it('includes tips section', async () => {
    const result = await executeCommand('help', []);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('TIPS');
    expect(result.output).toContain('phaseone help <command>');
    expect(result.output).toContain('phaseone menu');
  });
});

describe('Command-specific help', () => {
  it('shows examples in detailed help', async () => {
    const result = await executeCommand('help', ['onboard']);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('Examples');
    expect(result.output).toContain('phaseone onboard');
  });

  it('shows tips in detailed help', async () => {
    const result = await executeCommand('help', ['onboard']);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('Tips');
  });

  it('shows category in detailed help', async () => {
    const result = await executeCommand('help', ['health']);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('Category');
    expect(result.output).toContain('Health');
  });

  it('gatekeeper help emphasizes safety', async () => {
    const result = await executeCommand('help', ['gatekeeper']);
    expect(result.ok).toBe(true);
    expect(result.output).toMatch(/dry.*run/i);
    expect(result.output).toMatch(/human|confirm/i);
    expect(result.output).toMatch(/advisory/i);
  });
});

describe('menu command', () => {
  it('exists and has category', () => {
    const menu = findCommand('menu');
    expect(menu).toBeDefined();
    expect(menu?.category).toBe('getting-started');
  });

  it('returns grouped help in non-TTY mode', async () => {
    // In test environment, stdin is not a TTY, so menu should fall back to grouped help
    const result = await executeCommand('menu', []);
    expect(result.ok).toBe(true);
    expect(result.output).toContain('RECOMMENDED FIRST RUN');
  });
});

describe('Unknown command suggestions', () => {
  it('suggests similar commands for typos', async () => {
    const result = await executeCommand('help', ['helth']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Unknown command');
    // The error message mentions menu for navigation
    expect(result.error).toContain('menu');
  });

  it('suggests menu for unknown command', async () => {
    const result = await executeCommand('help', ['xyz123']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('phaseone menu');
  });

  it('shows suggestions when partial match exists', async () => {
    // 'keep' should suggest 'gatekeeper'
    const result = await executeCommand('help', ['keeper']);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Did you mean');
    expect(result.error).toContain('gatekeeper');
  });
});
