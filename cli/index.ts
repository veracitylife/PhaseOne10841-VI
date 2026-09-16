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

import { BANNER, commands, executeCommand, VERSION, COMPANY, WEBSITE } from './registry.js';

const EXIT_SUCCESS = 0;
const EXIT_ERROR = 1;
const EXIT_USAGE = 2;

function printVersion(): void {
  console.log(`PhaseOne10841 CLI v${VERSION}`);
  console.log(`${COMPANY} · ${WEBSITE}`);
}

function printUsage(): void {
  console.log(BANNER);
  console.log('');
  console.log('Usage: phaseone <command> [options]');
  console.log('');
  console.log('Commands:');
  const maxLen = Math.max(...commands.map((c) => c.name.length));
  for (const cmd of commands) {
    const warn = cmd.dangerous ? ' ⚠️' : '';
    console.log(`  ${cmd.name.padEnd(maxLen + 2)} ${cmd.description}${warn}`);
  }
  console.log('');
  console.log('Run `phaseone help <command>` for detailed usage.');
  console.log('');
  console.log(`${COMPANY} · ${WEBSITE}`);
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    printUsage();
    return EXIT_SUCCESS;
  }

  const firstArg = args[0];

  if (firstArg === '--version' || firstArg === '-v') {
    printVersion();
    return EXIT_SUCCESS;
  }

  if (firstArg === '--help' || firstArg === '-h') {
    printUsage();
    return EXIT_SUCCESS;
  }

  const commandName = firstArg;
  const commandArgs = args.slice(1);

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
    console.error(result.error);
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
