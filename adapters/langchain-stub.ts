/**
 * LangChain adapter — routes LangChain agents through PhaseOne gateway.
 * Does not import LangChain (optional peer). DEFENSIVE ONLY.
 * 
 * PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com
 */

export interface LangChainPhaseOneConfig {
  baseURL: string;
  model: string;
  headers: Record<string, string>;
  enforceToolUrl: string;
  scanUntrustedUrl: string;
  notes: string[];
}

export interface ToolEnforceResult {
  allowed: boolean;
  pending_approval?: boolean;
  approval_id?: string;
  reason?: string;
}

export interface ScanResult {
  safe: boolean;
  injection_score?: number;
  canary_detected?: boolean;
  secrets_detected?: boolean;
  warnings?: string[];
}

/**
 * Generate config for pointing LangChain ChatOpenAI at PhaseOne gateway.
 * 
 * @example
 * ```ts
 * import { ChatOpenAI } from '@langchain/openai';
 * import { langchainPhaseOneConfig } from './adapters/langchain-stub';
 * 
 * const config = langchainPhaseOneConfig('http://localhost:8080', 'my-langchain-agent');
 * const llm = new ChatOpenAI({
 *   configuration: { baseURL: config.baseURL },
 *   apiKey: 'unused-for-mock',
 *   model: config.model,
 *   modelKwargs: { headers: config.headers },
 * });
 * ```
 */
export function langchainPhaseOneConfig(
  gatewayUrl = 'http://localhost:8080',
  agentId = 'langchain-agent',
  sessionId?: string
): LangChainPhaseOneConfig {
  const base = gatewayUrl.replace(/\/$/, '');
  return {
    baseURL: `${base}/v1`,
    model: 'phaseone-mock',
    headers: {
      'X-PhaseOne-Agent-Id': agentId,
      'X-PhaseOne-Session-Id': sessionId ?? crypto.randomUUID(),
    },
    enforceToolUrl: `${base}/v1/phaseone/tools/enforce`,
    scanUntrustedUrl: `${base}/v1/phaseone/scan/untrusted`,
    notes: [
      'Use ChatOpenAI configuration.baseURL = gateway /v1',
      'Wrap tool calls with POST /v1/phaseone/tools/enforce before side effects',
      'Scan retrieved context with POST /v1/phaseone/scan/untrusted',
      'Product: PhaseOne10841 by Veracity Integrity LLC',
    ],
  };
}

/**
 * Enforce a tool call through PhaseOne before execution.
 * Call this BEFORE allowing the LangChain agent to execute any side-effecting tool.
 * 
 * @example
 * ```ts
 * const result = await enforceToolCall(config.enforceToolUrl, {
 *   agent_id: 'my-agent',
 *   tool_name: 'run_shell',
 *   arguments: { command: 'ls -la' },
 * });
 * if (!result.allowed) {
 *   if (result.pending_approval) {
 *     console.log('Awaiting human approval:', result.approval_id);
 *   } else {
 *     throw new Error(`Tool denied: ${result.reason}`);
 *   }
 * }
 * ```
 */
export async function enforceToolCall(
  enforceUrl: string,
  payload: {
    agent_id: string;
    tool_name: string;
    arguments: Record<string, unknown>;
    wait_for_approval?: boolean;
  }
): Promise<ToolEnforceResult> {
  const res = await fetch(enforceUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json() as ToolEnforceResult;
  return data;
}

/**
 * Scan untrusted content (RAG results, tool output) for injection attempts, canaries, secrets.
 * 
 * @example
 * ```ts
 * const scanResult = await scanUntrusted(config.scanUntrustedUrl, {
 *   content: ragDocumentText,
 *   source: 'rag-retrieval',
 * });
 * if (!scanResult.safe) {
 *   console.warn('Potential injection detected, score:', scanResult.injection_score);
 * }
 * ```
 */
export async function scanUntrusted(
  scanUrl: string,
  payload: {
    content: string;
    source?: string;
    agent_id?: string;
  }
): Promise<ScanResult> {
  const res = await fetch(scanUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json() as ScanResult;
  return data;
}

/**
 * Create a tool wrapper that enforces policy before execution.
 * Use this to wrap LangChain tools that have side effects.
 * 
 * @example
 * ```ts
 * import { DynamicTool } from '@langchain/core/tools';
 * 
 * const config = langchainPhaseOneConfig();
 * const unsafeShellTool = new DynamicTool({
 *   name: 'run_shell',
 *   func: async (command) => execSync(command).toString(),
 * });
 * 
 * const safeShellTool = createEnforcedTool(unsafeShellTool, config);
 * ```
 */
export function createToolEnforceWrapper(
  config: LangChainPhaseOneConfig,
  toolName: string,
  originalFunc: (input: string) => Promise<string>
): (input: string) => Promise<string> {
  return async (input: string) => {
    const enforceResult = await enforceToolCall(config.enforceToolUrl, {
      agent_id: config.headers['X-PhaseOne-Agent-Id'],
      tool_name: toolName,
      arguments: { input },
      wait_for_approval: false,
    });

    if (!enforceResult.allowed) {
      if (enforceResult.pending_approval) {
        throw new Error(`Tool ${toolName} requires human approval (id: ${enforceResult.approval_id})`);
      }
      throw new Error(`Tool ${toolName} denied by policy: ${enforceResult.reason}`);
    }

    return originalFunc(input);
  };
}

export const langchainPhaseOneHint = langchainPhaseOneConfig;
