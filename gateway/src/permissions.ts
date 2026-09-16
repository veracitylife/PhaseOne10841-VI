/**
 * Tool Permission Analyzer — DEFENSIVE capability matrix + excessive-agency flags.
 * Reports what an agent/policy config can do; does not grant privileges.
 */

import type { PolicyConfig } from '../../policy/src/types.js';
import { getPolicy, loadPolicy } from '../../policy/src/engine.js';

export type Capability =
  | 'filesystem_read'
  | 'filesystem_write'
  | 'shell'
  | 'network'
  | 'github'
  | 'email'
  | 'db'
  | 'mcp'
  | 'spawn';

export interface CapabilityEntry {
  capability: Capability;
  granted: boolean;
  tools: string[];
  notes: string[];
}

export interface PermissionFinding {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  detail: string;
  capabilities: Capability[];
}

export interface PermissionReport {
  agent_id: string;
  policy_name: string;
  policy_version: string;
  matrix: CapabilityEntry[];
  findings: PermissionFinding[];
  summary: {
    granted_count: number;
    finding_count: number;
    max_severity: PermissionFinding['severity'] | null;
  };
}

/** Optional agent overlay (declared intents / extra tools) */
export interface AgentPermissionConfig {
  agent_id: string;
  /** Extra tools this agent claims beyond policy allowlist intersection */
  declared_tools?: string[];
  /** Explicit capability grants (for analysis of proposed configs) */
  capabilities?: Partial<Record<Capability, boolean>>;
  labels?: string[];
}

const TOOL_CAPABILITY_MAP: Record<string, Capability[]> = {
  read_file: ['filesystem_read'],
  list_files: ['filesystem_read'],
  write_file: ['filesystem_write'],
  delete_file: ['filesystem_write'],
  run_shell: ['shell'],
  http_request: ['network'],
  fetch: ['network'],
  web_search: ['network'],
  mcp_call: ['mcp'],
  spawn_agent: ['spawn'],
  force_push: ['github'],
  send_email_blast: ['email'],
  drop_database: ['db'],
};

const GITHUB_HINTS = /github|gh_|git\s+push|force_push|pull_request/i;
const EMAIL_HINTS = /email|smtp|send_mail|mail_blast/i;
const DB_HINTS = /database|sql|drop_|postgres|mysql|mongo/i;

function allowedTools(policy: PolicyConfig, agent?: AgentPermissionConfig): string[] {
  const base =
    policy.tools.mode === 'allowlist'
      ? policy.tools.allow.filter((t) => !policy.tools.deny.includes(t))
      : [...policy.tools.allow];
  const declared = agent?.declared_tools ?? [];
  return Array.from(new Set([...base, ...declared]));
}

function buildMatrix(policy: PolicyConfig, agent?: AgentPermissionConfig): CapabilityEntry[] {
  const tools = allowedTools(policy, agent);
  const byCap = new Map<Capability, CapabilityEntry>();

  const ensure = (cap: Capability): CapabilityEntry => {
    let e = byCap.get(cap);
    if (!e) {
      e = { capability: cap, granted: false, tools: [], notes: [] };
      byCap.set(cap, e);
    }
    return e;
  };

  for (const cap of [
    'filesystem_read',
    'filesystem_write',
    'shell',
    'network',
    'github',
    'email',
    'db',
    'mcp',
    'spawn',
  ] as Capability[]) {
    ensure(cap);
  }

  for (const tool of tools) {
    const caps = TOOL_CAPABILITY_MAP[tool] ?? [];
    for (const cap of caps) {
      const e = ensure(cap);
      e.granted = true;
      if (!e.tools.includes(tool)) e.tools.push(tool);
    }
    if (GITHUB_HINTS.test(tool)) {
      const e = ensure('github');
      e.granted = true;
      if (!e.tools.includes(tool)) e.tools.push(tool);
    }
    if (EMAIL_HINTS.test(tool)) {
      const e = ensure('email');
      e.granted = true;
      if (!e.tools.includes(tool)) e.tools.push(tool);
    }
    if (DB_HINTS.test(tool)) {
      const e = ensure('db');
      e.granted = true;
      if (!e.tools.includes(tool)) e.tools.push(tool);
    }
  }

  // Shell deny-by-default still grants shell capability if run_shell is allowed
  const shell = ensure('shell');
  if (shell.granted && policy.shell.mode === 'deny_by_default') {
    shell.notes.push('shell is deny-by-default with allow_patterns');
  }

  const fsRead = ensure('filesystem_read');
  if (fsRead.granted) {
    fsRead.notes.push(`allowed_roots: ${policy.filesystem.allowed_roots.join(', ')}`);
  }

  const mcp = ensure('mcp');
  if (mcp.granted && policy.mcp.mode === 'allowlist') {
    mcp.notes.push(`allow_servers: ${policy.mcp.allow_servers.join(', ')}`);
  }

  const spawn = ensure('spawn');
  if (spawn.granted) {
    spawn.notes.push(`max_depth=${policy.agent_spawn.max_depth}`);
  }

  // Agent overlay explicit grants
  if (agent?.capabilities) {
    for (const [cap, granted] of Object.entries(agent.capabilities) as Array<[Capability, boolean]>) {
      const e = ensure(cap);
      if (granted) {
        e.granted = true;
        e.notes.push('explicit agent capability grant');
      }
    }
  }

  return Array.from(byCap.values());
}

function analyzeFindings(matrix: CapabilityEntry[], policy: PolicyConfig): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const granted = new Set(matrix.filter((m) => m.granted).map((m) => m.capability));

  const has = (...caps: Capability[]) => caps.every((c) => granted.has(c));

  if (has('shell', 'network')) {
    findings.push({
      id: 'excessive.shell_network',
      severity: 'high',
      title: 'Shell + network agency',
      detail:
        'Agent can run shell and reach the network — classic excessive agency combination. Prefer separate agents or stricter shell allow_patterns.',
      capabilities: ['shell', 'network'],
    });
  }

  if (has('filesystem_write', 'network')) {
    findings.push({
      id: 'excessive.fs_write_network',
      severity: 'high',
      title: 'Filesystem write + network',
      detail:
        'Write access combined with egress enables staging + exfiltration paths. Constrain roots and domain allowlist.',
      capabilities: ['filesystem_write', 'network'],
    });
  }

  if (has('shell', 'filesystem_write', 'network')) {
    findings.push({
      id: 'excessive.full_agency_triangle',
      severity: 'critical',
      title: 'Full agency triangle (shell + FS write + network)',
      detail:
        'Highest excessive-agency risk: execute, persist, and egress. Split capabilities across agents with least privilege.',
      capabilities: ['shell', 'filesystem_write', 'network'],
    });
  }

  if (has('spawn', 'shell')) {
    findings.push({
      id: 'excessive.spawn_shell',
      severity: 'high',
      title: 'Spawn + shell',
      detail: 'Child agents inheriting shell amplify blast radius. Cap spawn depth and strip shell from children.',
      capabilities: ['spawn', 'shell'],
    });
  }

  if (has('mcp', 'network') && policy.mcp.allow_servers.length > 4) {
    findings.push({
      id: 'excessive.broad_mcp',
      severity: 'medium',
      title: 'Broad MCP server allowlist',
      detail: `MCP allowlist has ${policy.mcp.allow_servers.length} servers with network tools present.`,
      capabilities: ['mcp', 'network'],
    });
  }

  if (has('email') && has('filesystem_read')) {
    findings.push({
      id: 'excessive.email_read',
      severity: 'medium',
      title: 'Email + filesystem read',
      detail: 'Read + email can be used for data exfiltration via outbound messages. Require approval for blast tools.',
      capabilities: ['email', 'filesystem_read'],
    });
  }

  if (has('db') && has('network')) {
    findings.push({
      id: 'excessive.db_network',
      severity: 'high',
      title: 'Database + network',
      detail: 'DB mutation tools with network egress increase data-exfil risk. Keep destructive DB tools on approval queue.',
      capabilities: ['db', 'network'],
    });
  }

  if (has('github') && has('shell')) {
    findings.push({
      id: 'excessive.github_shell',
      severity: 'medium',
      title: 'GitHub + shell',
      detail: 'Force-push / repo tools plus shell expand supply-chain blast radius. Keep force_push on approval.',
      capabilities: ['github', 'shell'],
    });
  }

  if (policy.shell.mode !== 'deny_by_default' && granted.has('shell')) {
    findings.push({
      id: 'config.shell_not_deny_default',
      severity: 'critical',
      title: 'Shell not deny-by-default',
      detail: 'Shell mode should be deny_by_default for agent workloads.',
      capabilities: ['shell'],
    });
  }

  return findings;
}

export function analyzePermissions(
  agent?: AgentPermissionConfig,
  policy?: PolicyConfig
): PermissionReport {
  const p = policy ?? getPolicy();
  const matrix = buildMatrix(p, agent);
  const findings = analyzeFindings(matrix, p);
  const rank = { low: 1, medium: 2, high: 3, critical: 4 } as const;
  let maxSeverity: PermissionFinding['severity'] | null = null;
  for (const f of findings) {
    if (!maxSeverity || rank[f.severity] > rank[maxSeverity]) maxSeverity = f.severity;
  }
  return {
    agent_id: agent?.agent_id ?? 'policy-default',
    policy_name: p.name,
    policy_version: p.version,
    matrix,
    findings,
    summary: {
      granted_count: matrix.filter((m) => m.granted).length,
      finding_count: findings.length,
      max_severity: maxSeverity,
    },
  };
}

/** CLI entry: npx tsx gateway/src/permissions.ts [agent-id] */
export function formatReportText(report: PermissionReport): string {
  const lines: string[] = [];
  lines.push(`Permission report — agent=${report.agent_id} policy=${report.policy_name}@${report.policy_version}`);
  lines.push('Capability matrix:');
  for (const m of report.matrix) {
    lines.push(
      `  [${m.granted ? 'X' : ' '}] ${m.capability.padEnd(18)} tools=${m.tools.join(',') || '-'} ${m.notes.join('; ')}`
    );
  }
  lines.push(`Findings (${report.findings.length}):`);
  for (const f of report.findings) {
    lines.push(`  (${f.severity}) ${f.id}: ${f.title}`);
    lines.push(`           ${f.detail}`);
  }
  return lines.join('\n');
}

// Allow CLI: tsx gateway/src/permissions.ts
const isMain =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  (process.argv[1].endsWith('permissions.ts') || process.argv[1].endsWith('permissions.js'));

if (isMain) {
  loadPolicy();
  const agentId = process.argv[2] ?? 'policy-default';
  const report = analyzePermissions({ agent_id: agentId });
  console.log(formatReportText(report));
  console.log(JSON.stringify({ summary: report.summary, finding_ids: report.findings.map((f) => f.id) }, null, 2));
}
