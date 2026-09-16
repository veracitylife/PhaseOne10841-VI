/**
 * Inert fake-MCP stub — returns tool results for scanner tests.
 * Not a real MCP server; no privilege escalation.
 */

import { BENIGN_SAMPLES, INJECTION_FIXTURES, FIXTURE_LABEL } from '../fixtures/injection-markers.js';

export interface FakeMcpResult {
  server: string;
  tool: string;
  content: string;
  fixture?: boolean;
}

export function callFakeMcp(
  tool: string,
  opts?: { includeFixture?: boolean }
): FakeMcpResult {
  if (opts?.includeFixture && tool === 'get_untrusted_blob') {
    return {
      server: 'lab-fake-mcp',
      tool,
      content: INJECTION_FIXTURES.find((f) => f.channel === 'mcp')!.text,
      fixture: true,
    };
  }
  return {
    server: 'lab-fake-mcp',
    tool,
    content: `[${FIXTURE_LABEL}-benign] ${BENIGN_SAMPLES[0].text}`,
    fixture: false,
  };
}

export function listFakeMcpTools(): string[] {
  return ['echo', 'get_untrusted_blob', 'list_resources'];
}
