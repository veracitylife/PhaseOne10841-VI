#!/usr/bin/env node
/**
 * PhaseOne10841 CLI — Operator Command Console
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 *
 * Usage:
 *   npx phaseone <command> [options]
 *   npm run phaseone -- <command> [options]
 *   phaseone <command> [options]  (if npm linked)
 *
 * DEFENSIVE ONLY — no exploit tooling.
 */

import { 
  commands, 
  executeCommand, 
  findCommand,
  VERSION, 
  COMPANY, 
  WEBSITE 
} from './registry.js';

const EXIT_SUCCESS = 0;
const EXIT_ERROR = 1;

function printVersion(): void {
  console.log(`PhaseOne10841 CLI v${VERSION}`);
  console.log(`${COMPANY} · ${WEBSITE}`);
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

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const isTTY = process.stdin.isTTY && !process.env.CI;

  // No args: show grouped help (or interactive menu if TTY)
  if (args.length === 0) {
    // If TTY and not in CI, default to menu-like experience
    const result = await executeCommand('help', [], {});
    console.log(result.output);
    if (isTTY) {
      console.log('\n💡 Tip: Run `phaseone menu` for interactive navigation.\n');
    }
    return EXIT_SUCCESS;
  }

  const firstArg = args[0];

  // Version flags
  if (firstArg === '--version' || firstArg === '-v') {
    printVersion();
    return EXIT_SUCCESS;
  }

  // Help flags — show grouped help
  if (firstArg === '--help' || firstArg === '-h' || firstArg === 'help') {
    const helpArgs = firstArg === 'help' ? args.slice(1) : [];
    const result = await executeCommand('help', helpArgs, {});
    console.log(result.output);
    if (result.error) {
      console.error(result.error);
    }
    return result.exitCode;
  }

  const commandName = firstArg;
  const commandArgs = args.slice(1);

  // Check if command exists and provide friendly error
  const cmd = findCommand(commandName);
  if (!cmd) {
    const suggestions = suggestCommands(commandName);
    console.error(`❌ Unknown command: ${commandName}`);
    console.error(suggestions);
    console.error('\n📋 Run `phaseone help` to see all commands.');
    console.error('📋 Run `phaseone menu` for interactive navigation.');
    return EXIT_ERROR;
  }

  // Check for --help on specific command
  if (commandArgs.includes('--help') || commandArgs.includes('-h')) {
    const result = await executeCommand('help', [commandName], {});
    console.log(result.output);
    return result.exitCode;
  }

  // Execute the command
  const result = await executeCommand(commandName, commandArgs, {
    onOutput: (data) => process.stdout.write(data),
    onError: (data) => process.stderr.write(data),
  });

  if (result.output && !result.output.endsWith('\n')) {
    console.log(result.output);
  } else if (result.output) {
    process.stdout.write(result.output);
  }

  if (result.error) {
    // Provide friendly error with examples if available
    console.error(result.error);
    if (cmd.examples?.length && !result.ok) {
      console.error('\n💡 Examples:');
      for (const ex of cmd.examples.slice(0, 2)) {
        console.error(`   ${ex}`);
      }
    }
  }

  return result.exitCode;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    console.error('Fatal error:', err);
    process.exitCode = EXIT_ERROR;
  });
