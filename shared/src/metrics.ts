/**
 * Prometheus-style in-process metrics for PhaseOne10841 gateway.
 * DEFENSIVE observability only.
 */

type CounterMap = Map<string, number>;

const counters: CounterMap = new Map();

function key(name: string, labels?: Record<string, string>): string {
  if (!labels || !Object.keys(labels).length) return name;
  const parts = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`)
    .join(',');
  return `${name}{${parts}}`;
}

export function incCounter(name: string, labels?: Record<string, string>, by = 1): void {
  const k = key(name, labels);
  counters.set(k, (counters.get(k) ?? 0) + by);
}

export function getCounter(name: string, labels?: Record<string, string>): number {
  return counters.get(key(name, labels)) ?? 0;
}

export function resetMetrics(): void {
  counters.clear();
}

/** Convenience helpers used across gateway paths */
export const Metrics = {
  block: (reason = 'policy') => incCounter('phaseone_blocks_total', { reason }),
  injection: (outcome: 'detected' | 'blocked') =>
    incCounter('phaseone_injections_total', { outcome }),
  canary: () => incCounter('phaseone_canaries_total'),
  approval: (status: 'requested' | 'approved' | 'denied' | 'expired') =>
    incCounter('phaseone_approvals_total', { status }),
  a2a: (action: 'allow' | 'deny' | 'quarantine') =>
    incCounter('phaseone_a2a_total', { action }),
  alert: (outcome: 'sent' | 'failed') => incCounter('phaseone_alerts_total', { outcome }),
  ruleHit: (ruleId: string) => incCounter('phaseone_rule_hits_total', { rule: ruleId }),
  audit: (action: string) => incCounter('phaseone_audit_actions_total', { action }),
};

export function renderPrometheus(): string {
  const lines: string[] = [
    '# HELP phaseone_blocks_total Policy/enforcement blocks',
    '# TYPE phaseone_blocks_total counter',
    '# HELP phaseone_injections_total Prompt-injection detections/blocks',
    '# TYPE phaseone_injections_total counter',
    '# HELP phaseone_canaries_total Canary marker triggers',
    '# TYPE phaseone_canaries_total counter',
    '# HELP phaseone_approvals_total Human approval lifecycle',
    '# TYPE phaseone_approvals_total counter',
    '# HELP phaseone_a2a_total Agent-to-agent firewall decisions',
    '# TYPE phaseone_a2a_total counter',
    '# HELP phaseone_alerts_total Alert webhook deliveries',
    '# TYPE phaseone_alerts_total counter',
    '# HELP phaseone_rule_hits_total Detection rule hits',
    '# TYPE phaseone_rule_hits_total counter',
    '# HELP phaseone_audit_actions_total Admin audit log actions',
    '# TYPE phaseone_audit_actions_total counter',
  ];

  // Always emit zero baselines for unlabeled convenience scrapes
  const baselines = [
    'phaseone_blocks_total',
    'phaseone_canaries_total',
  ];
  for (const b of baselines) {
    if (![...counters.keys()].some((k) => k === b || k.startsWith(b + '{'))) {
      lines.push(`${b} 0`);
    }
  }

  for (const [k, v] of [...counters.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`${k} ${v}`);
  }
  lines.push(`# PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com`);
  return lines.join('\n') + '\n';
}
