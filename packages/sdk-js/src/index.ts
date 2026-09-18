/**
 * @phaseone/client — PhaseOne10841 TypeScript/JavaScript SDK
 * Defensive Agent Security Gateway client library.
 * 
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 * DEFENSIVE ONLY — no exploit tooling.
 */

export interface PhaseOneConfig {
  /** Gateway base URL (default: http://localhost:8080) */
  baseUrl?: string;
  /** Agent identifier */
  agentId?: string;
  /** Session identifier (auto-generated if not provided) */
  sessionId?: string;
  /** API key for upstream provider (if applicable) */
  apiKey?: string;
  /** Request timeout in ms (default: 30000) */
  timeout?: number;
  /** Additional default headers */
  headers?: Record<string, string>;
}

export interface EnforceOptions {
  /** Tool name to check */
  toolName: string;
  /** Tool arguments */
  arguments?: unknown;
  /** Wait for approval if required */
  waitForApproval?: boolean;
  /** Override session ID */
  sessionId?: string;
}

export interface EnforceResult {
  allowed: boolean;
  pendingApproval?: boolean;
  approvalId?: string;
  decision: {
    action: 'allow' | 'deny' | 'require_approval';
    reason: string;
    ruleId?: string;
    matchedCanaries?: string[];
    matchedSecrets?: string[];
  };
  error?: { message: string; code: string };
}

export interface ScanOptions {
  /** Text to scan for injection */
  text: string;
  /** Source classification */
  source?: 'user' | 'system' | 'untrusted';
  /** Channel identifier */
  channel?: string;
  /** Override session ID */
  sessionId?: string;
}

export interface ScanResult {
  blocked: boolean;
  scan: {
    hits: Array<{ ruleId: string; match: string; severity: string }>;
    blockedRules: string[];
  };
  policy: {
    mode: string;
    blockEnabled: boolean;
  };
  sessionId: string;
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | unknown;
  name?: string;
  tool_calls?: unknown[];
  tool_call_id?: string;
}

export interface ChatCompletionOptions {
  messages: ChatMessage[];
  model?: string;
  /** Pre-check tool calls through enforce */
  toolCalls?: Array<{ name: string; arguments: unknown }>;
  /** Additional OpenAI-compatible parameters */
  [key: string]: unknown;
}

export interface ChatCompletionResult {
  id: string;
  object: 'chat.completion';
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: ChatMessage;
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  phaseone?: {
    session_id: string;
    agent_id: string;
    upstream: string;
    gateway: string;
  };
}

export interface EventOptions {
  eventType: string;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  toolName?: string;
  toolArgs?: unknown;
  destination?: string;
  result?: unknown;
  metadata?: Record<string, unknown>;
  sessionId?: string;
}

function generateSessionId(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * PhaseOne10841 client for agent security integration.
 * 
 * @example
 * ```typescript
 * import { PhaseOneClient } from '@phaseone/client';
 * 
 * const client = new PhaseOneClient({
 *   baseUrl: 'http://localhost:8080',
 *   agentId: 'my-agent',
 * });
 * 
 * // Pre-check a tool call
 * const result = await client.enforce({
 *   toolName: 'http_request',
 *   arguments: { url: 'https://api.example.com' },
 * });
 * 
 * if (!result.allowed) {
 *   console.log('Tool blocked:', result.decision.reason);
 * }
 * ```
 */
export class PhaseOneClient {
  private baseUrl: string;
  private agentId: string;
  private sessionId: string;
  private apiKey: string;
  private timeout: number;
  private headers: Record<string, string>;

  constructor(config: PhaseOneConfig = {}) {
    this.baseUrl = (config.baseUrl ?? process.env.PHASEONE_GATEWAY_URL ?? 'http://localhost:8080').replace(/\/$/, '');
    this.agentId = config.agentId ?? process.env.PHASEONE_AGENT_ID ?? 'agent-default';
    this.sessionId = config.sessionId ?? generateSessionId();
    this.apiKey = config.apiKey ?? process.env.OPENAI_API_KEY ?? '';
    this.timeout = config.timeout ?? 30000;
    this.headers = config.headers ?? {};
  }

  /**
   * Get current session ID
   */
  getSessionId(): string {
    return this.sessionId;
  }

  /**
   * Get current agent ID
   */
  getAgentId(): string {
    return this.agentId;
  }

  /**
   * Set agent ID for subsequent requests
   */
  setAgentId(agentId: string): void {
    this.agentId = agentId;
  }

  /**
   * Create a new session
   */
  newSession(): string {
    this.sessionId = generateSessionId();
    return this.sessionId;
  }

  private async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-PhaseOne-Agent-Id': this.agentId,
      'X-PhaseOne-Session-Id': this.sessionId,
      ...this.headers,
      ...(options.headers as Record<string, string> ?? {}),
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      signal: AbortSignal.timeout(this.timeout),
    });

    const data = await response.json() as T;
    
    if (!response.ok) {
      const error = data as { error?: { message?: string; code?: string } };
      throw new PhaseOneError(
        error.error?.message ?? `Request failed: ${response.status}`,
        error.error?.code ?? 'REQUEST_FAILED',
        response.status
      );
    }

    return data;
  }

  /**
   * Check if a tool call is allowed by policy
   * 
   * @example
   * ```typescript
   * const result = await client.enforce({
   *   toolName: 'run_shell',
   *   arguments: { command: 'ls -la' },
   * });
   * 
   * if (!result.allowed) {
   *   if (result.pendingApproval) {
   *     console.log('Waiting for approval:', result.approvalId);
   *   } else {
   *     console.log('Tool denied:', result.decision.reason);
   *   }
   * }
   * ```
   */
  async enforce(options: EnforceOptions): Promise<EnforceResult> {
    return this.request<EnforceResult>('/v1/phaseone/tools/enforce', {
      method: 'POST',
      body: JSON.stringify({
        agent_id: this.agentId,
        session_id: options.sessionId ?? this.sessionId,
        tool_name: options.toolName,
        arguments: options.arguments,
        wait_for_approval: options.waitForApproval,
      }),
    });
  }

  /**
   * Scan text for prompt injection or other threats
   * 
   * @example
   * ```typescript
   * const result = await client.scan({
   *   text: userInput,
   *   source: 'untrusted',
   * });
   * 
   * if (result.blocked) {
   *   console.log('Injection detected:', result.scan.blockedRules);
   * }
   * ```
   */
  async scan(options: ScanOptions): Promise<ScanResult> {
    return this.request<ScanResult>('/v1/phaseone/scan/injection', {
      method: 'POST',
      body: JSON.stringify({
        agent_id: this.agentId,
        session_id: options.sessionId ?? this.sessionId,
        text: options.text,
        source: options.source ?? 'untrusted',
        channel: options.channel,
      }),
    });
  }

  /**
   * Scan untrusted content (tool results, RAG context, MCP payloads)
   */
  async scanUntrusted(content: unknown, channel = 'untrusted'): Promise<EnforceResult> {
    return this.request<EnforceResult>('/v1/phaseone/scan/untrusted', {
      method: 'POST',
      body: JSON.stringify({
        agent_id: this.agentId,
        session_id: this.sessionId,
        content,
        channel,
      }),
    });
  }

  /**
   * Send a chat completion request through the PhaseOne gateway
   * 
   * @example
   * ```typescript
   * const response = await client.chat({
   *   messages: [
   *     { role: 'user', content: 'Hello!' }
   *   ],
   *   model: 'gpt-4',
   * });
   * 
   * console.log(response.choices[0].message.content);
   * ```
   */
  async chat(options: ChatCompletionOptions): Promise<ChatCompletionResult> {
    // Pre-check tool calls if provided
    if (options.toolCalls?.length) {
      for (const tool of options.toolCalls) {
        const result = await this.enforce({
          toolName: tool.name,
          arguments: tool.arguments,
        });
        if (!result.allowed) {
          throw new PhaseOneError(
            `Tool ${tool.name} blocked: ${result.decision.reason}`,
            result.decision.ruleId ?? 'TOOL_BLOCKED',
            403
          );
        }
      }
    }

    return this.request<ChatCompletionResult>('/v1/chat/completions', {
      method: 'POST',
      body: JSON.stringify({
        ...options,
        phaseone_tool_calls: options.toolCalls,
      }),
    });
  }

  /**
   * Record an event to the PhaseOne event store
   */
  async recordEvent(options: EventOptions): Promise<{ id: string }> {
    return this.request<{ id: string }>('/v1/phaseone/events', {
      method: 'POST',
      body: JSON.stringify({
        session_id: options.sessionId ?? this.sessionId,
        agent_id: this.agentId,
        event_type: options.eventType,
        severity: options.severity ?? 'info',
        tool_name: options.toolName,
        tool_args: options.toolArgs,
        destination: options.destination,
        result: options.result,
        metadata: options.metadata,
      }),
    });
  }

  /**
   * Get gateway health status
   */
  async health(): Promise<{
    status: string;
    service: string;
    version: string;
    upstream: string;
    db: boolean;
  }> {
    return this.request('/health');
  }

  /**
   * Get OpenAI-compatible client configuration
   * Use with OpenAI SDK or compatible libraries.
   * 
   * @example
   * ```typescript
   * import OpenAI from 'openai';
   * 
   * const client = new PhaseOneClient({ agentId: 'my-agent' });
   * const openai = new OpenAI(client.getOpenAIConfig());
   * 
   * const response = await openai.chat.completions.create({
   *   model: 'gpt-4',
   *   messages: [{ role: 'user', content: 'Hello!' }],
   * });
   * ```
   */
  getOpenAIConfig(): {
    baseURL: string;
    apiKey: string;
    defaultHeaders: Record<string, string>;
  } {
    return {
      baseURL: `${this.baseUrl}/v1`,
      apiKey: this.apiKey || 'phaseone-unused',
      defaultHeaders: {
        'X-PhaseOne-Agent-Id': this.agentId,
        'X-PhaseOne-Session-Id': this.sessionId,
        ...this.headers,
      },
    };
  }
}

/**
 * PhaseOne error class
 */
export class PhaseOneError extends Error {
  code: string;
  status: number;

  constructor(message: string, code: string, status: number) {
    super(message);
    this.name = 'PhaseOneError';
    this.code = code;
    this.status = status;
  }
}

/**
 * Create a PhaseOne client with default configuration
 */
export function createClient(config?: PhaseOneConfig): PhaseOneClient {
  return new PhaseOneClient(config);
}

/**
 * Helper to wrap tool execution with PhaseOne enforcement
 * 
 * @example
 * ```typescript
 * const safeExecute = withEnforcement(client);
 * 
 * const result = await safeExecute('http_request', { url: '...' }, async (args) => {
 *   return fetch(args.url);
 * });
 * ```
 */
export function withEnforcement(client: PhaseOneClient) {
  return async function<T, A>(
    toolName: string,
    args: A,
    execute: (args: A) => Promise<T>
  ): Promise<T> {
    const result = await client.enforce({ toolName, arguments: args });
    
    if (!result.allowed) {
      throw new PhaseOneError(
        `Tool ${toolName} blocked: ${result.decision.reason}`,
        result.decision.ruleId ?? 'TOOL_BLOCKED',
        403
      );
    }

    return execute(args);
  };
}

export default PhaseOneClient;
