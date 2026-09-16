/**
 * Lab monitor — asserts detectors fire when TEST fixtures are consumed.
 * Defensive verification only; does not perform attacks.
 */

import { detectPromptInjection, scanPromptInjection } from '../shared/src/prompt-injection.js';
import { BENIGN_SAMPLES, INJECTION_FIXTURES } from './fixtures/injection-markers.js';
import { listInbox } from './stubs/fake-email.js';
import { fetchPage } from './stubs/fake-web.js';
import { callFakeMcp } from './stubs/fake-mcp.js';
import { retrieve } from './stubs/fake-rag.js';

export interface DetectorAssertion {
  fixture_id: string;
  channel: string;
  expected_rules: string[];
  matched_rules: string[];
  passed: boolean;
  blocked_in_block_mode: boolean;
}

export interface LabMonitorReport {
  benign_false_positives: number;
  fixture_hits: DetectorAssertion[];
  all_fixtures_detected: boolean;
  lab_detector_hit_count: number;
  summary: string;
}

export function runLabDetectorMonitor(): LabMonitorReport {
  let benignFp = 0;
  for (const b of BENIGN_SAMPLES) {
    const hits = detectPromptInjection(b.text);
    if (hits.length > 0) benignFp++;
  }

  const assertions: DetectorAssertion[] = [];

  // Consume fixtures via stubs (as an agent integration would)
  const emailFix = listInbox({ includeFixtures: true }).find((m) => m.fixture);
  const webFix = fetchPage('https://lab.phaseone.test/fixture/injection-web', { allowFixtures: true });
  const mcpFix = callFakeMcp('get_untrusted_blob', { includeFixture: true });
  const ragFix = retrieve('fixture injection test', { includeFixtures: true }).find((c) => c.fixture);

  const consumed: Array<{ id: string; channel: string; text: string; expected: string[] }> = [];
  for (const f of INJECTION_FIXTURES) {
    let text = f.text;
    if (f.channel === 'email' && emailFix) text = emailFix.body;
    if (f.channel === 'web' && webFix && f.id === 'fixture.ignore_previous') text = webFix.body;
    if (f.channel === 'web' && f.id === 'fixture.hidden_markers') {
      const hidden = fetchPage('https://lab.phaseone.test/fixture/hidden-markers', { allowFixtures: true });
      if (hidden) text = hidden.body;
    }
    if (f.channel === 'mcp' && mcpFix.fixture) text = mcpFix.content;
    if (f.channel === 'rag' && ragFix) text = ragFix.text;
    consumed.push({ id: f.id, channel: f.channel, text, expected: f.expected_rules });
  }

  for (const c of consumed) {
    const hits = detectPromptInjection(c.text);
    const matched = hits.map((h) => h.rule);
    const passed = c.expected.some((r) => matched.includes(r));
    const scan = scanPromptInjection(c.text, {
      source: 'untrusted',
      blockMode: true,
      minBlockSeverity: 'medium',
    });
    assertions.push({
      fixture_id: c.id,
      channel: c.channel,
      expected_rules: c.expected,
      matched_rules: matched,
      passed,
      blocked_in_block_mode: scan.shouldBlock,
    });
  }

  const allDetected = assertions.every((a) => a.passed);
  const hitCount = assertions.filter((a) => a.passed).length;

  return {
    benign_false_positives: benignFp,
    fixture_hits: assertions,
    all_fixtures_detected: allDetected,
    lab_detector_hit_count: hitCount,
    summary: allDetected
      ? `OK: ${hitCount}/${assertions.length} fixtures detected; benign FP=${benignFp}`
      : `FAIL: some fixtures missed; benign FP=${benignFp}`,
  };
}
