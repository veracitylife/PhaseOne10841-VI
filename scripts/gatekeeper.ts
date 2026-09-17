#!/usr/bin/env tsx
/**
 * PhaseOne10841 Gatekeeper CLI
 * Simulation and blast-radius analysis.
 * DEFENSIVE ONLY.
 * 
 * Usage:
 *   npm run gatekeeper -- simulate [options]
 *   npm run gatekeeper -- blast-radius [options]
 *   npm run gatekeeper -- status
 * 
 * Examples:
 *   npm run gatekeeper -- simulate --limit 100
 *   npm run gatekeeper -- simulate --event-type tool.call --agent-id my-agent
 *   npm run gatekeeper -- simulate --from "2024-01-01" --to "2024-01-02"
 *   npm run gatekeeper -- blast-radius --limit 500
 *   npm run gatekeeper -- status
 */

import { readFileSync } from 'node:fs';
import {
  simulateEvents,
  getRateCapStatus,
  type SimulationEvent,
  type SimulationConfig,
} from '../shared/src/gatekeeper.js';

const GATEWAY_URL = process.env.GATEWAY_URL ?? 'http://localhost:8080';

function printHelp(): void {
  console.log(`
PhaseOne10841 Gatekeeper CLI
============================
Veracity Integrity LLC · https://VeracityIntegrity.com

Commands:
  simulate      Run dry-run simulation against policy
  blast-radius  Calculate blast-radius summary
  status        Show gatekeeper status and rate-cap state

Simulate Options:
  --limit N          Max events to process (default: 100)
  --event-type TYPE  Filter by event type (e.g., tool.call)
  --agent-id ID      Filter by agent ID
  --tool-name NAME   Filter by tool name
  --from DATE        Start time (ISO date or epoch ms)
  --to DATE          End time (ISO date or epoch ms)
  --file PATH        Load events from JSON file instead of API
  --output json      Output as JSON (default: human-readable)
  --verbose          Show detailed results

Examples:
  npm run gatekeeper -- simulate --limit 100
  npm run gatekeeper -- simulate --event-type tool.call --verbose
  npm run gatekeeper -- simulate --file events.json
  npm run gatekeeper -- blast-radius --limit 500
  npm run gatekeeper -- status
`);
}

function parseArgs(): {
  command: string;
  limit: number;
  eventType?: string;
  agentId?: string;
  toolName?: string;
  from?: string;
  to?: string;
  file?: string;
  output: 'json' | 'human';
  verbose: boolean;
} {
  const args = process.argv.slice(2);
  const result = {
    command: args[0] ?? 'help',
    limit: 100,
    eventType: undefined as string | undefined,
    agentId: undefined as string | undefined,
    toolName: undefined as string | undefined,
    from: undefined as string | undefined,
    to: undefined as string | undefined,
    file: undefined as string | undefined,
    output: 'human' as 'json' | 'human',
    verbose: false,
  };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    if (arg === '--limit' && next) {
      result.limit = parseInt(next, 10);
      i++;
    } else if (arg === '--event-type' && next) {
      result.eventType = next;
      i++;
    } else if (arg === '--agent-id' && next) {
      result.agentId = next;
      i++;
    } else if (arg === '--tool-name' && next) {
      result.toolName = next;
      i++;
    } else if (arg === '--from' && next) {
      result.from = next;
      i++;
    } else if (arg === '--to' && next) {
      result.to = next;
      i++;
    } else if (arg === '--file' && next) {
      result.file = next;
      i++;
    } else if (arg === '--output' && next) {
      result.output = next as 'json' | 'human';
      i++;
    } else if (arg === '--verbose' || arg === '-v') {
      result.verbose = true;
    }
  }

  return result;
}

async function fetchEvents(args: ReturnType<typeof parseArgs>): Promise<SimulationEvent[]> {
  if (args.file) {
    const content = readFileSync(args.file, 'utf8');
    return JSON.parse(content);
  }

  // Fetch from gateway API
  const params = new URLSearchParams();
  params.set('limit', String(args.limit));
  if (args.eventType) params.set('event_type', args.eventType);

  const res = await fetch(`${GATEWAY_URL}/v1/phaseone/events?${params}`, {
    headers: { Accept: 'application/json' },
  });

  if (!res.ok) {
    console.error(`Failed to fetch events: ${res.status}`);
    const text = await res.text().catch(() => '');
    if (text) console.error(text);
    return [];
  }

  const data = await res.json() as { data: Array<Record<string, unknown>> };
  return data.data.map((e) => ({
    id: e.id as string,
    session_id: e.session_id as string,
    agent_id: e.agent_id as string,
    event_type: e.event_type as string,
    tool_name: e.tool_name as string | undefined,
    tool_args: e.tool_args,
    destination: e.destination as string | undefined,
    timestamp: e.timestamp as string,
  }));
}

async function runSimulate(args: ReturnType<typeof parseArgs>): Promise<void> {
  console.log('PhaseOne10841 Gatekeeper Simulation');
  console.log('===================================');
  console.log('');

  const events = await fetchEvents(args);
  if (events.length === 0) {
    console.log('No events found to simulate.');
    return;
  }

  console.log(`Loaded ${events.length} events for simulation...`);

  const config: SimulationConfig = {
    max_events: args.limit,
    event_types: args.eventType ? [args.eventType] : undefined,
    agent_ids: args.agentId ? [args.agentId] : undefined,
    tool_names: args.toolName ? [args.toolName] : undefined,
    from_time: args.from,
    to_time: args.to,
  };

  const result = simulateEvents(events, config);

  if (args.output === 'json') {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  // Human-readable output
  console.log('');
  console.log('Blast Radius Summary');
  console.log('--------------------');
  console.log(`Total events:          ${result.blast_radius.total_events}`);
  console.log(`Would block:           ${result.blast_radius.blocked_count}`);
  console.log(`Would require approval: ${result.blast_radius.approval_required_count}`);
  console.log(`Would allow:           ${result.blast_radius.allowed_count}`);
  console.log(`Canary matches:        ${result.blast_radius.canary_matches}`);
  console.log(`Secret matches:        ${result.blast_radius.secret_matches}`);
  console.log('');
  console.log('Affected Entities');
  console.log('-----------------');
  console.log(`Agents (${result.blast_radius.affected_agents.length}): ${result.blast_radius.affected_agents.slice(0, 5).join(', ')}${result.blast_radius.affected_agents.length > 5 ? '...' : ''}`);
  console.log(`Tools (${result.blast_radius.affected_tools.length}): ${result.blast_radius.affected_tools.slice(0, 5).join(', ')}${result.blast_radius.affected_tools.length > 5 ? '...' : ''}`);
  console.log(`Domains (${result.blast_radius.affected_domains.length}): ${result.blast_radius.affected_domains.slice(0, 5).join(', ')}${result.blast_radius.affected_domains.length > 5 ? '...' : ''}`);
  console.log('');
  console.log('Rule Hits');
  console.log('---------');
  const sortedRules = Object.entries(result.blast_radius.rule_hits)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10);
  for (const [rule, count] of sortedRules) {
    console.log(`  ${rule}: ${count}`);
  }
  console.log('');
  console.log(`Simulation time: ${result.simulation_time_ms}ms`);
  console.log('DRY RUN - no actions were taken');

  if (args.verbose && result.results.length > 0) {
    console.log('');
    console.log('Detailed Results (first 20)');
    console.log('---------------------------');
    for (const r of result.results.slice(0, 20)) {
      const action = r.would_block ? '❌ BLOCK' : r.would_require_approval ? '⚠️  APPROVAL' : '✅ ALLOW';
      console.log(`${action} | ${r.event.tool_name ?? r.event.event_type ?? 'unknown'} | ${r.decision.reason.slice(0, 60)}`);
    }
  }
}

async function runBlastRadius(args: ReturnType<typeof parseArgs>): Promise<void> {
  console.log('PhaseOne10841 Blast Radius Analysis');
  console.log('====================================');
  console.log('');

  const events = await fetchEvents(args);
  if (events.length === 0) {
    console.log('No events found to analyze.');
    return;
  }

  const result = simulateEvents(events, { max_events: args.limit });

  if (args.output === 'json') {
    console.log(JSON.stringify({ blast_radius: result.blast_radius, events_analyzed: events.length }, null, 2));
    return;
  }

  console.log(`Events analyzed: ${result.blast_radius.total_events}`);
  console.log('');
  console.log('Impact Summary');
  console.log('--------------');
  const blockPct = ((result.blast_radius.blocked_count / result.blast_radius.total_events) * 100).toFixed(1);
  const approvalPct = ((result.blast_radius.approval_required_count / result.blast_radius.total_events) * 100).toFixed(1);
  console.log(`  Blocked:           ${result.blast_radius.blocked_count} (${blockPct}%)`);
  console.log(`  Require approval:  ${result.blast_radius.approval_required_count} (${approvalPct}%)`);
  console.log(`  Allowed:           ${result.blast_radius.allowed_count}`);
  console.log('');
  console.log('Affected Scope');
  console.log('--------------');
  console.log(`  Agents:   ${result.blast_radius.affected_agents.length}`);
  console.log(`  Tools:    ${result.blast_radius.affected_tools.length}`);
  console.log(`  Domains:  ${result.blast_radius.affected_domains.length}`);
  console.log('');
  console.log('Security Findings');
  console.log('-----------------');
  console.log(`  Canary triggers:  ${result.blast_radius.canary_matches}`);
  console.log(`  Secret exposures: ${result.blast_radius.secret_matches}`);
}

async function runStatus(): Promise<void> {
  console.log('PhaseOne10841 Gatekeeper Status');
  console.log('================================');
  console.log('');

  try {
    const res = await fetch(`${GATEWAY_URL}/v1/phaseone/gatekeeper/status`, {
      headers: { Accept: 'application/json' },
    });

    if (!res.ok) {
      console.error(`Failed to fetch status: ${res.status}`);
      // Fall back to local status
      const status = getRateCapStatus();
      console.log('Rate Cap Configuration (local)');
      console.log('------------------------------');
      console.log(JSON.stringify(status, null, 2));
      return;
    }

    const data = await res.json();
    console.log(JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Failed to connect to gateway:', err instanceof Error ? err.message : err);
    console.log('');
    console.log('Local rate-cap status:');
    const status = getRateCapStatus();
    console.log(JSON.stringify(status, null, 2));
  }
}

async function main(): Promise<void> {
  const args = parseArgs();

  switch (args.command) {
    case 'simulate':
      await runSimulate(args);
      break;
    case 'blast-radius':
      await runBlastRadius(args);
      break;
    case 'status':
      await runStatus();
      break;
    case 'help':
    case '--help':
    case '-h':
    default:
      printHelp();
  }
}

main().catch((err) => {
  console.error('Gatekeeper CLI error:', err);
  process.exit(1);
});
