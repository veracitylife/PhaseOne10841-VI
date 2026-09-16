import { describe, it, expect, beforeAll } from 'vitest';
import { loadPolicy } from '../policy/src/engine.js';
import { analyzePermissions, formatReportText } from '../gateway/src/permissions.js';

beforeAll(() => {
  loadPolicy();
});

describe('tool permission analyzer', () => {
  it('builds capability matrix from default policy', () => {
    const report = analyzePermissions({ agent_id: 'agent-default' });
    expect(report.matrix.length).toBe(9);
    const granted = report.matrix.filter((m) => m.granted).map((m) => m.capability);
    expect(granted).toContain('filesystem_read');
    expect(granted).toContain('shell');
    expect(granted).toContain('network');
    expect(granted).toContain('mcp');
    expect(granted).toContain('spawn');
  });

  it('flags excessive agency combinations', () => {
    const report = analyzePermissions({ agent_id: 'agent-default' });
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain('excessive.shell_network');
    expect(ids).toContain('excessive.full_agency_triangle');
    expect(report.summary.finding_count).toBeGreaterThan(0);
  });

  it('formats a text report', () => {
    const text = formatReportText(analyzePermissions({ agent_id: 'cli-test' }));
    expect(text).toContain('Capability matrix');
    expect(text).toContain('Findings');
  });

  it('respects declared tools overlay', () => {
    const report = analyzePermissions({
      agent_id: 'narrow',
      declared_tools: ['read_file'],
      capabilities: { email: true },
    });
    expect(report.matrix.find((m) => m.capability === 'email')?.granted).toBe(true);
  });
});
