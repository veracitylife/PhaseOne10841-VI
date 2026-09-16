/**
 * Claude-style tool proxy adapter — enforce tools via PhaseOne before execution.
 * Works with Anthropic's tool_use format and MCP tool calls.
 * DEFENSIVE ONLY. No Anthropic SDK dependency required.
 * 
 * PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com
 */

export interface ClaudeToolProxyConfig {
  enforceUrl: string;
  scanUrl: string;
  mcpAllowlistUrl: string;
  approvalsUrl: string;
  notes: string[];
}

export interface ToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface ToolResultBlock {
  type: 'tool_result';
  tool_use_id: string;
  content: string;
  is_error?: boolean;
}

export interface EnforceResult {
  allowed: boolean;
  pending_approval?: boolean;
  approval_id?: string;
  reason?: string;
  expires_at?: string;
}

export interface ScanResult {
  safe: boolean;
  injection_score?: number;
  canary_detected?: boolean;
  secrets_detected?: boolean;
  warnings?: string[];
}

export interface ApprovalStatus {
  id: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  resolved_by?: string;
  resolved_at?: string;
}

/**
 * Generate config for Claude-style tool proxy through PhaseOne.
 * 
 * @example
 * ```ts
 * import Anthropic from '@anthropic-ai/sdk';
 * import { claudeToolProxyConfig, enforceToolUse, scanToolResult } from './adapters/claude-tool-proxy-stub';
 * 
 * const config = claudeToolProxyConfig('http://localhost:8080');
 * const anthropic = new Anthropic();
 * 
 * // After receiving tool_use from Claude
 * const enforceResult = await enforceToolUse(config, toolUseBlock, 'my-agent');
 * if (!enforceResult.allowed) {
 *   // Handle denial or approval flow
 * }
 * 
 * // After executing tool, scan result
 * const scanResult = await scanToolResult(config, toolOutput, 'shell-output');
 * if (!scanResult.safe) {
 *   // Handle potential injection in tool output
 * }
 * ```
 */
export function claudeToolProxyConfig(gatewayUrl = 'http://localhost:8080'): ClaudeToolProxyConfig {
  const base = gatewayUrl.replace(/\/$/, '');
  return {
    enforceUrl: `${base}/v1/phaseone/tools/enforce`,
    scanUrl: `${base}/v1/phaseone/scan/untrusted`,
    mcpAllowlistUrl: `${base}/v1/phaseone/mcp/allowlist`,
    approvalsUrl: `${base}/v1/phaseone/approvals`,
    notes: [
      'Before executing a tool_use block, POST name+arguments to enforceUrl',
      'If allowed=false and pending_approval, poll approvals or wait_for_approval',
      'Scan tool results / MCP payloads via scanUrl as untrusted content',
      'MCP calls are checked against allowlist; use mcpAllowlistUrl to query',
      'PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com',
    ],
  };
}

/**
 * Enforce a tool_use block through PhaseOne before execution.
 * Call this when Claude returns a tool_use content block.
 * 
 * @example
 * ```ts
 * const toolUse = response.content.find(c => c.type === 'tool_use');
 * if (toolUse) {
 *   const result = await enforceToolUse(config, toolUse, 'my-claude-agent');
 *   if (!result.allowed) {
 *     if (result.pending_approval) {
 *       // Wait for human approval
 *       const status = await pollApproval(config, result.approval_id);
 *       if (status.status !== 'approved') {
 *         return { type: 'tool_result', tool_use_id: toolUse.id, content: 'Denied by security policy', is_error: true };
 *       }
 *     } else {
 *       return { type: 'tool_result', tool_use_id: toolUse.id, content: `Denied: ${result.reason}`, is_error: true };
 *     }
 *   }
 *   // Proceed with tool execution
 * }
 * ```
 */
export async function enforceToolUse(
  config: ClaudeToolProxyConfig,
  toolUse: ToolUseBlock,
  agentId: string,
  waitForApproval = false
): Promise<EnforceResult> {
  const res = await fetch(config.enforceUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agent_id: agentId,
      tool_name: toolUse.name,
      arguments: toolUse.input,
      tool_use_id: toolUse.id,
      wait_for_approval: waitForApproval,
    }),
  });
  return res.json() as Promise<EnforceResult>;
}

/**
 * Scan tool result content for injection attempts, canaries, and secrets.
 * Call this before including tool output in the next Claude message.
 * 
 * @example
 * ```ts
 * const shellOutput = await runCommand(toolUse.input.command);
 * const scanResult = await scanToolResult(config, shellOutput, 'shell-command');
 * if (!scanResult.safe) {
 *   console.warn('Potential security issue in tool output:', scanResult.warnings);
 *   // Optionally redact or block the output
 * }
 * ```
 */
export async function scanToolResult(
  config: ClaudeToolProxyConfig,
  content: string,
  source: string,
  agentId?: string
): Promise<ScanResult> {
  const res = await fetch(config.scanUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      content,
      source,
      agent_id: agentId,
    }),
  });
  return res.json() as Promise<ScanResult>;
}

/**
 * Poll for approval status when a tool requires human approval.
 * 
 * @example
 * ```ts
 * const status = await pollApproval(config, enforceResult.approval_id);
 * if (status.status === 'approved') {
 *   // Proceed with tool execution
 * } else if (status.status === 'denied') {
 *   // Return error to Claude
 * } else if (status.status === 'pending') {
 *   // Keep polling or timeout
 * }
 * ```
 */
export async function pollApproval(
  config: ClaudeToolProxyConfig,
  approvalId: string
): Promise<ApprovalStatus> {
  const res = await fetch(`${config.approvalsUrl}/${approvalId}`);
  return res.json() as Promise<ApprovalStatus>;
}

/**
 * Wait for approval with polling and timeout.
 */
export async function waitForApproval(
  config: ClaudeToolProxyConfig,
  approvalId: string,
  timeoutMs = 120000,
  pollIntervalMs = 2000
): Promise<ApprovalStatus> {
  const startTime = Date.now();
  while (Date.now() - startTime < timeoutMs) {
    const status = await pollApproval(config, approvalId);
    if (status.status !== 'pending') {
      return status;
    }
    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }
  return { id: approvalId, status: 'expired' };
}

/**
 * Create a safe tool result block, scanning content first.
 */
export async function createSafeToolResult(
  config: ClaudeToolProxyConfig,
  toolUseId: string,
  content: string,
  source: string,
  agentId?: string
): Promise<ToolResultBlock> {
  const scanResult = await scanToolResult(config, content, source, agentId);
  
  if (!scanResult.safe) {
    const warnings = scanResult.warnings?.join(', ') ?? 'Security check failed';
    return {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content: `[PhaseOne Security Warning: ${warnings}]\n\n${content}`,
      is_error: false,
    };
  }
  
  return {
    type: 'tool_result',
    tool_use_id: toolUseId,
    content,
    is_error: false,
  };
}

/**
 * TypeScript example for integrating with Anthropic Claude SDK.
 */
export const CLAUDE_TYPESCRIPT_EXAMPLE = `
// Claude + PhaseOne10841 Integration Example
// Veracity Integrity LLC · https://VeracityIntegrity.com
// DEFENSIVE ONLY — no exploit tooling

import Anthropic from '@anthropic-ai/sdk';
import {
  claudeToolProxyConfig,
  enforceToolUse,
  createSafeToolResult,
  waitForApproval,
  type ToolUseBlock,
} from './adapters/claude-tool-proxy-stub';

const AGENT_ID = 'my-claude-agent';
const config = claudeToolProxyConfig('http://localhost:8080');
const anthropic = new Anthropic();

async function handleToolUse(toolUse: ToolUseBlock): Promise<string> {
  // Step 1: Enforce tool call through PhaseOne
  const enforceResult = await enforceToolUse(config, toolUse, AGENT_ID);
  
  if (!enforceResult.allowed) {
    if (enforceResult.pending_approval && enforceResult.approval_id) {
      console.log('Waiting for human approval...');
      const status = await waitForApproval(config, enforceResult.approval_id);
      if (status.status !== 'approved') {
        throw new Error(\`Tool denied: \${status.status}\`);
      }
    } else {
      throw new Error(\`Tool denied by policy: \${enforceResult.reason}\`);
    }
  }

  // Step 2: Execute the tool (implement your tool logic here)
  const toolOutput = await executeToolLocally(toolUse);
  
  // Step 3: Scan output before returning to Claude
  const safeResult = await createSafeToolResult(
    config,
    toolUse.id,
    toolOutput,
    \`tool:\${toolUse.name}\`,
    AGENT_ID
  );
  
  return safeResult.content;
}

async function executeToolLocally(toolUse: ToolUseBlock): Promise<string> {
  // Implement your tool execution logic here
  switch (toolUse.name) {
    case 'read_file':
      // return fs.readFileSync(toolUse.input.path, 'utf8');
    case 'run_shell':
      // return execSync(toolUse.input.command).toString();
    default:
      throw new Error(\`Unknown tool: \${toolUse.name}\`);
  }
}
`.trim();

export const claudeToolProxyHint = claudeToolProxyConfig;
