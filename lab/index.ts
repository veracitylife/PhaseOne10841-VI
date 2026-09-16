/**
 * PhaseOne10841 defensive lab harness entrypoint.
 * Runs inert stubs + detector monitor. No exploitation.
 */

import { runLabDetectorMonitor } from './monitor.js';
import { listInbox } from './stubs/fake-email.js';
import { listPages } from './stubs/fake-web.js';
import { listFakeMcpTools } from './stubs/fake-mcp.js';
import { retrieve } from './stubs/fake-rag.js';
import { INJECTION_FIXTURES, BENIGN_SAMPLES } from './fixtures/injection-markers.js';

export function runLabHarness() {
  const report = runLabDetectorMonitor();
  return {
    stubs: {
      email_messages: listInbox({ includeFixtures: true }).length,
      web_pages: listPages().length,
      mcp_tools: listFakeMcpTools(),
      rag_chunks_with_fixtures: retrieve('fixture', { includeFixtures: true }).length,
    },
    fixtures: {
      benign: BENIGN_SAMPLES.length,
      injection: INJECTION_FIXTURES.length,
    },
    monitor: report,
  };
}

const isMain =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  (process.argv[1].endsWith('lab/index.ts') || process.argv[1].endsWith('lab/index.js'));

if (isMain) {
  const result = runLabHarness();
  console.log(JSON.stringify(result, null, 2));
  if (!result.monitor.all_fixtures_detected || result.monitor.benign_false_positives > 0) {
    process.exitCode = 1;
  }
}

export { runLabDetectorMonitor } from './monitor.js';
export * from './fixtures/injection-markers.js';
