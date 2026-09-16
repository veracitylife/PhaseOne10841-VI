import { readFileSync } from 'node:fs';
import { dirname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import type { PolicyCheckContext, PolicyDecision } from '../../shared/src/types.js';
import {
  detectSecrets,
  detectSecretsInValue,
  collectEgressText,
  OUTBOUND_TOOL_NAMES,
} from '../../shared/src/secrets.js';
import { matchCanaries } from '../../canaries/src/detector.js';
import type { PolicyConfig } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

let cachedPolicy: PolicyConfig | null = null;

export function loadPolicy(path?: string): PolicyConfig {
  const policyPath =
    path ??
    process.env.PHASEONE_POLICY_PATH ??
    join(__dirname, '..', 'default-policy.yaml');
  const raw = readFileSync(policyPath, 'utf8');
  cachedPolicy = YAML.parse(raw) as PolicyConfig;
  return cachedPolicy;
}

export function getPolicy(): PolicyConfig {
  if (!cachedPolicy) return loadPolicy();
  return cachedPolicy;
}

function hostFromUrlOrDomain(input?: string): string | null {
  if (!input) return null;
  try {
    if (input.includes('://')) {
      return new URL(input).hostname.toLowerCase();
    }
    return input.split('/')[0].split(':')[0].toLowerCase();
  } catch {
    return input.toLowerCase();
  }
}

function globToRegExp(glob: string): RegExp {
  // Minimal ** / * glob → RegExp (path separators normalized to /)
  const escaped = glob
    .replace(/\\/g, '/')
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '<<<DS>>>')
    .replace(/\*/g, '[^/]*')
    .replace(/<<<DS>>>/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

function isPathBlocked(filePath: string, policy: PolicyConfig): { blocked: boolean; reason?: string } {
  const normalized = normalize(filePath).replace(/\\/g, '/');
  const base = normalized.split('/').pop() ?? normalized;

  for (const pattern of policy.filesystem.blocked_paths) {
    const re = globToRegExp(pattern);
    if (re.test(normalized) || re.test(base) || re.test(`/${base}`)) {
      return { blocked: true, reason: `filesystem path blocked by pattern: ${pattern}` };
    }
    // Common credential filenames
    if (
      base === '.env' ||
      base.startsWith('.env.') ||
      base === 'id_rsa' ||
      base === 'id_ed25519' ||
      base === 'credentials' ||
      base === 'credentials.json'
    ) {
      return { blocked: true, reason: `credential file access denied: ${base}` };
    }
  }

  // Path must be under an allowed root (if absolute or starts with known root)
  const roots = policy.filesystem.allowed_roots.map((r) =>
    r.startsWith('.') || !r.startsWith('/') ? r.replace(/\\/g, '/') : normalize(r).replace(/\\/g, '/')
  );

  const absish = normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized);
  if (absish) {
    const underRoot = roots.some((root) => {
      if (root.startsWith('.') || !root.startsWith('/')) {
        // relative roots — also check resolved contains
        return normalized.includes(root.replace(/^\.\//, ''));
      }
      const resolvedRoot = normalize(root).replace(/\\/g, '/');
      return normalized === resolvedRoot || normalized.startsWith(resolvedRoot + '/');
    });
    if (!underRoot) {
      return { blocked: true, reason: `path outside allowed roots: ${normalized}` };
    }
  }

  // Block .ssh directory traversal
  if (normalized.includes('/.ssh/') || normalized.endsWith('/.ssh') || normalized.includes('/.aws/')) {
    return { blocked: true, reason: 'credential directory access denied' };
  }

  return { blocked: false };
}

function isDestructive(
  ctx: PolicyCheckContext,
  policy: PolicyConfig
): { destructive: boolean; reason?: string } {
  const haystacks: string[] = [];
  if (ctx.toolName) haystacks.push(ctx.toolName);
  if (ctx.shellCommand) haystacks.push(ctx.shellCommand);
  if (ctx.actionHint) haystacks.push(ctx.actionHint);
  if (ctx.path) haystacks.push(ctx.path);
  if (ctx.toolArgs) haystacks.push(JSON.stringify(ctx.toolArgs));

  if (ctx.toolName && policy.destructive.tools.includes(ctx.toolName)) {
    return { destructive: true, reason: `destructive tool requires approval: ${ctx.toolName}` };
  }

  for (const pattern of policy.destructive.patterns) {
    const normalized = pattern.replace(/^\(\?i\)/, '');
    const re = new RegExp(normalized, 'i');
    for (const h of haystacks) {
      if (re.test(h)) {
        return { destructive: true, reason: `destructive action matched pattern, approval required` };
      }
    }
  }
  return { destructive: false };
}

/**
 * Evaluate a policy check context. Order:
 * 1) canary / secret egress
 * 2) tool allow/deny
 * 3) domain allowlist
 * 4) HTTP method
 * 5) filesystem
 * 6) shell
 * 7) MCP
 * 8) agent spawn limits
 * 9) destructive → require_approval
 */
export function evaluatePolicy(ctx: PolicyCheckContext, policy?: PolicyConfig): PolicyDecision {
  const p = policy ?? getPolicy();
  const matchedCanaries: string[] = [];
  const matchedSecrets: string[] = [];

  const egressText = [
    ctx.egressBody,
    typeof ctx.toolArgs === 'string' ? ctx.toolArgs : JSON.stringify(ctx.toolArgs ?? ''),
    ctx.shellCommand,
    ctx.url,
    ctx.path,
  ]
    .filter(Boolean)
    .join('\n');

  const canaries = matchCanaries(egressText);
  if (canaries.length > 0) {
    matchedCanaries.push(...canaries.map((c) => c.name));
    if (p.canary.block_on_detect) {
      return {
        action: 'deny',
        reason: `canary credential detected in egress/args: ${matchedCanaries.join(', ')}`,
        ruleId: 'canary.block',
        matchedCanaries,
      };
    }
  }

  // Deep scan tool args / HTTP bodies for secret shapes (Phase 3)
  const deepSecrets = detectSecretsInValue(ctx.toolArgs);
  const flatSecrets = detectSecrets(egressText);
  const secrets = [...flatSecrets];
  for (const s of deepSecrets) {
    if (!secrets.some((x) => x.type === s.type && x.preview === s.preview)) secrets.push(s);
  }
  if (secrets.length > 0) {
    matchedSecrets.push(...secrets.map((s) => s.type));
    const blockOnArgs = p.secret_egress.block_on_tool_args !== false;
    const isOutbound =
      !!ctx.domain ||
      !!ctx.url ||
      !!ctx.egressBody ||
      (ctx.toolName ? OUTBOUND_TOOL_NAMES.has(ctx.toolName) : false);
    if (p.secret_egress.block && (isOutbound || (blockOnArgs && ctx.toolName))) {
      return {
        action: 'deny',
        reason: `secret egress blocked: ${matchedSecrets.join(', ')}`,
        ruleId: 'secret.egress',
        matchedSecrets,
        matchedCanaries,
      };
    }
  }

  // Tool checks
  if (ctx.toolName) {
    if (p.tools.deny.includes(ctx.toolName)) {
      return { action: 'deny', reason: `tool denied: ${ctx.toolName}`, ruleId: 'tools.deny', matchedCanaries, matchedSecrets };
    }
    if (p.tools.mode === 'allowlist' && !p.tools.allow.includes(ctx.toolName)) {
      return { action: 'deny', reason: `tool not in allowlist: ${ctx.toolName}`, ruleId: 'tools.allowlist', matchedCanaries, matchedSecrets };
    }
  }

  // Domain default-deny allowlist
  const host = hostFromUrlOrDomain(ctx.domain ?? ctx.url);
  if (host && (ctx.toolName === 'http_request' || ctx.toolName === 'fetch' || ctx.url || ctx.domain)) {
    if (p.domains.deny.some((d) => host === d || host.endsWith('.' + d))) {
      return { action: 'deny', reason: `domain denied: ${host}`, ruleId: 'domains.deny', matchedCanaries, matchedSecrets };
    }
    if (p.domains.mode === 'allowlist') {
      const allowed = p.domains.allow.some((d) => host === d || host.endsWith('.' + d));
      if (!allowed) {
        return {
          action: 'deny',
          reason: `domain not in allowlist (default-deny): ${host}`,
          ruleId: 'domains.allowlist',
          matchedCanaries,
          matchedSecrets,
        };
      }
    }
  }

  // HTTP method limits
  if (ctx.method) {
    const method = ctx.method.toUpperCase();
    if (p.http.denied_methods.map((m) => m.toUpperCase()).includes(method)) {
      return { action: 'deny', reason: `HTTP method denied: ${method}`, ruleId: 'http.method.deny', matchedCanaries, matchedSecrets };
    }
    if (!p.http.allowed_methods.map((m) => m.toUpperCase()).includes(method)) {
      return { action: 'deny', reason: `HTTP method not allowed: ${method}`, ruleId: 'http.method.allow', matchedCanaries, matchedSecrets };
    }
  }

  // Filesystem path limits
  if (ctx.path || (ctx.toolName && ['read_file', 'write_file', 'list_files', 'delete_file'].includes(ctx.toolName))) {
    const filePath =
      ctx.path ??
      (typeof ctx.toolArgs === 'object' && ctx.toolArgs && 'path' in (ctx.toolArgs as object)
        ? String((ctx.toolArgs as { path: string }).path)
        : null);
    if (filePath) {
      const check = isPathBlocked(filePath, p);
      if (check.blocked) {
        return { action: 'deny', reason: check.reason!, ruleId: 'filesystem.block', matchedCanaries, matchedSecrets };
      }
    }
  }

  // Shell monitoring — deny by default with allow_patterns
  if (ctx.shellCommand || ctx.toolName === 'run_shell') {
    const cmd =
      ctx.shellCommand ??
      (typeof ctx.toolArgs === 'object' && ctx.toolArgs && 'command' in (ctx.toolArgs as object)
        ? String((ctx.toolArgs as { command: string }).command)
        : '');
    if (!cmd) {
      return { action: 'deny', reason: 'empty shell command', ruleId: 'shell.empty', matchedCanaries, matchedSecrets };
    }
    for (const pat of p.shell.deny_patterns) {
      if (new RegExp(pat, 'i').test(cmd)) {
        return { action: 'deny', reason: `shell command matched deny pattern`, ruleId: 'shell.deny_pattern', matchedCanaries, matchedSecrets };
      }
    }
    if (p.shell.mode === 'deny_by_default') {
      const allowed = p.shell.allow_patterns.some((pat) => new RegExp(pat, 'i').test(cmd.trim()));
      if (!allowed) {
        return {
          action: 'deny',
          reason: `arbitrary shell blocked (deny-by-default): ${cmd.slice(0, 80)}`,
          ruleId: 'shell.deny_by_default',
          matchedCanaries,
          matchedSecrets,
        };
      }
    }
  }

  // MCP allowlist — server + tool end-to-end (Phase 3)
  if (ctx.mcpServer || ctx.mcpTool || ctx.toolName === 'mcp_call') {
    const args = (typeof ctx.toolArgs === 'object' && ctx.toolArgs ? ctx.toolArgs : {}) as Record<string, unknown>;
    const server =
      ctx.mcpServer ??
      (typeof args.server === 'string' ? args.server : typeof args.mcp_server === 'string' ? args.mcp_server : null);
    const mcpTool =
      ctx.mcpTool ??
      (typeof args.tool === 'string'
        ? args.tool
        : typeof args.name === 'string'
          ? args.name
          : typeof args.mcp_tool === 'string'
            ? args.mcp_tool
            : null);

    if (!server) {
      return {
        action: 'deny',
        reason: 'MCP call missing server name',
        ruleId: 'mcp.server.required',
        matchedCanaries,
        matchedSecrets,
      };
    }

    if (p.mcp.mode === 'allowlist' && !p.mcp.allow_servers.includes(server)) {
      return {
        action: 'deny',
        reason: `MCP server not allowlisted: ${server}`,
        ruleId: 'mcp.allowlist',
        matchedCanaries,
        matchedSecrets,
      };
    }


    if (mcpTool && p.mcp.deny_tools?.includes(mcpTool)) {
      return {
        action: 'deny',
        reason: `MCP tool denied: ${mcpTool}`,
        ruleId: 'mcp.tool.deny',
        matchedCanaries,
        matchedSecrets,
      };
    }

    // Non-empty allow_tools → enforce; empty → all tools on allowed servers OK
    if (mcpTool && p.mcp.allow_tools.length > 0 && !p.mcp.allow_tools.includes(mcpTool)) {
      return {
        action: 'deny',
        reason: `MCP tool not allowlisted: ${mcpTool}`,
        ruleId: 'mcp.tool.allowlist',
        matchedCanaries,
        matchedSecrets,
      };
    }

    // mcp_call with allow_tools configured but no tool name → deny (cannot verify)
    if (!mcpTool && p.mcp.allow_tools.length > 0) {
      return {
        action: 'deny',
        reason: 'MCP call missing tool name while tool allowlist is enforced',
        ruleId: 'mcp.tool.required',
        matchedCanaries,
        matchedSecrets,
      };
    }
  }

  // Agent spawn limits
  if (ctx.toolName === 'spawn_agent' || ctx.spawnDepth !== undefined) {
    const depth = ctx.spawnDepth ?? 0;
    if (depth >= p.agent_spawn.max_depth) {
      return {
        action: 'deny',
        reason: `agent spawn depth limit exceeded (${depth} >= ${p.agent_spawn.max_depth})`,
        ruleId: 'agent_spawn.depth',
        matchedCanaries,
        matchedSecrets,
      };
    }
  }

  // Destructive → approval queue
  const dest = isDestructive(ctx, p);
  if (dest.destructive) {
    return {
      action: 'require_approval',
      reason: dest.reason!,
      ruleId: 'destructive.approval',
      matchedCanaries,
      matchedSecrets,
      requireApproval: true,
      risk: 'high',
    };
  }

  return {
    action: 'allow',
    reason: 'passed policy checks',
    ruleId: 'default.allow',
    matchedCanaries,
    matchedSecrets,
  };
}

/** Convenience: evaluate tool call from OpenAI-style function call */
export function evaluateToolCall(
  agentId: string,
  sessionId: string,
  name: string,
  args: unknown
): PolicyDecision {
  const a = (args ?? {}) as Record<string, unknown>;
  const mcpServer =
    typeof a.server === 'string'
      ? a.server
      : typeof a.mcp_server === 'string'
        ? a.mcp_server
        : undefined;
  const mcpTool =
    typeof a.tool === 'string'
      ? a.tool
      : typeof a.name === 'string' && name === 'mcp_call'
        ? a.name
        : typeof a.mcp_tool === 'string'
          ? a.mcp_tool
          : undefined;
  const bodyText =
    typeof a.body === 'string'
      ? a.body
      : a.body != null
        ? collectEgressText(a.body)
        : collectEgressText(args);
  const headersText = a.headers != null ? collectEgressText(a.headers) : '';
  return evaluatePolicy({
    agentId,
    sessionId,
    toolName: name,
    toolArgs: args,
    domain: typeof a.url === 'string' ? a.url : typeof a.domain === 'string' ? a.domain : undefined,
    url: typeof a.url === 'string' ? a.url : undefined,
    method: typeof a.method === 'string' ? a.method : undefined,
    path: typeof a.path === 'string' ? a.path : undefined,
    shellCommand: typeof a.command === 'string' ? a.command : undefined,
    mcpServer,
    mcpTool,
    egressBody: [bodyText, headersText].filter(Boolean).join('\n'),
    spawnDepth: typeof a.depth === 'number' ? a.depth : undefined,
    actionHint: name,
  });
}

// silence unused import lint for resolve/sep in some builds
void resolve;
void sep;
