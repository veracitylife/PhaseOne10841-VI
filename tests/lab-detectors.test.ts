import { describe, it, expect } from 'vitest';
import { runLabDetectorMonitor, runLabHarness } from '../lab/index.js';
import { detectPromptInjection } from '../shared/src/prompt-injection.js';
import { INJECTION_FIXTURES, BENIGN_SAMPLES } from '../lab/fixtures/injection-markers.js';
import { listInbox } from '../lab/stubs/fake-email.js';
import { fetchPage } from '../lab/stubs/fake-web.js';
import { callFakeMcp } from '../lab/stubs/fake-mcp.js';
import { retrieve } from '../lab/stubs/fake-rag.js';

describe('lab detector fixtures', () => {
  it('marks all injection fixtures clearly', () => {
    for (const f of INJECTION_FIXTURES) {
      expect(f.text).toMatch(/PHASEONE_TEST/);
      expect(f.expected_rules.length).toBeGreaterThan(0);
    }
  });

  it('benign samples do not trip detectors', () => {
    for (const b of BENIGN_SAMPLES) {
      expect(detectPromptInjection(b.text)).toHaveLength(0);
    }
  });

  it('stubs return fixture content when requested', () => {
    expect(listInbox({ includeFixtures: true }).some((m) => m.fixture)).toBe(true);
    expect(fetchPage('https://lab.phaseone.test/fixture/injection-web', { allowFixtures: true })?.fixture).toBe(
      true
    );
    expect(callFakeMcp('get_untrusted_blob', { includeFixture: true }).fixture).toBe(true);
    expect(retrieve('fixture', { includeFixtures: true }).some((c) => c.fixture)).toBe(true);
  });

  it('monitor asserts detectors fire on all fixtures', () => {
    const report = runLabDetectorMonitor();
    expect(report.benign_false_positives).toBe(0);
    expect(report.all_fixtures_detected).toBe(true);
    expect(report.lab_detector_hit_count).toBe(INJECTION_FIXTURES.length);
    for (const hit of report.fixture_hits) {
      expect(hit.passed).toBe(true);
      expect(hit.blocked_in_block_mode).toBe(true);
    }
  });

  it('lab harness aggregates stubs + monitor', () => {
    const result = runLabHarness();
    expect(result.monitor.all_fixtures_detected).toBe(true);
    expect(result.fixtures.injection).toBeGreaterThan(0);
    expect(result.stubs.mcp_tools).toContain('get_untrusted_blob');
  });
});
