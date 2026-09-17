/**
 * PhaseOne10841 Gatekeeper LLM Advisor
 * Optional LLM integration for advisory suggestions — DEFENSIVE ONLY.
 * 
 * Primary: OpenRouter (openrouter/auto)
 * Fallback: Ollama (webserver at Tailscale or localhost)
 * 
 * LLM advises only; playbooks decide mutations. Human confirmation unchanged.
 * 
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

export type LLMProvider = 'openrouter' | 'ollama' | 'none';

export interface GatekeeperLLMConfig {
  enabled: boolean;
  primary: LLMProvider;
  fallback: LLMProvider;
  openrouter: {
    apiKey: string;
    baseUrl: string;
    model: string;
  };
  ollama: {
    baseUrl: string;
    model: string;
  };
  timeoutMs: number;
  maxTokens: number;
}

export interface AdvisorRequest {
  context: string;
  event_summary: string;
  playbook_matches?: string[];
  question?: string;
}

export interface AdvisorResponse {
  ok: boolean;
  provider: LLMProvider | 'none';
  suggestion?: string;
  reasoning?: string;
  fallback_used: boolean;
  error?: string;
  latency_ms?: number;
}

interface ChatCompletionMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface ChatCompletionResponse {
  choices?: Array<{
    message?: {
      content?: string;
    };
  }>;
  error?: {
    message?: string;
  };
}

export function loadGatekeeperLLMConfig(): GatekeeperLLMConfig {
  const openrouterKey = process.env.OPENROUTER_API_KEY ?? '';
  const enabled = openrouterKey.length > 0 || 
    (process.env.PHASEONE_GATEKEEPER_LLM_ENABLED ?? 'false').toLowerCase() === 'true';

  return {
    enabled,
    primary: (process.env.PHASEONE_GATEKEEPER_LLM_PRIMARY ?? 'openrouter') as LLMProvider,
    fallback: (process.env.PHASEONE_GATEKEEPER_LLM_FALLBACK ?? 'ollama') as LLMProvider,
    openrouter: {
      apiKey: openrouterKey,
      baseUrl: process.env.PHASEONE_GATEKEEPER_OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1',
      model: process.env.PHASEONE_GATEKEEPER_OPENROUTER_MODEL ?? 'openrouter/auto',
    },
    ollama: {
      baseUrl: process.env.PHASEONE_GATEKEEPER_OLLAMA_BASE_URL ?? 
        (process.env.OLLAMA_WEBSERVER_URL ?? 'http://100.124.238.112:11434/v1'),
      model: process.env.PHASEONE_GATEKEEPER_OLLAMA_MODEL ?? 'unrestricted:latest',
    },
    timeoutMs: Number(process.env.PHASEONE_GATEKEEPER_LLM_TIMEOUT_MS ?? 30000),
    maxTokens: Number(process.env.PHASEONE_GATEKEEPER_LLM_MAX_TOKENS ?? 512),
  };
}

export function describeConfig(cfg?: GatekeeperLLMConfig): Record<string, unknown> {
  const config = cfg ?? loadGatekeeperLLMConfig();
  return {
    enabled: config.enabled,
    primary: config.primary,
    fallback: config.fallback,
    openrouter: {
      configured: config.openrouter.apiKey.length > 0,
      base_url: config.openrouter.baseUrl,
      model: config.openrouter.model,
    },
    ollama: {
      base_url: config.ollama.baseUrl,
      model: config.ollama.model,
    },
    timeout_ms: config.timeoutMs,
    max_tokens: config.maxTokens,
  };
}

function buildSystemPrompt(): string {
  return `You are a defensive security advisor for PhaseOne10841, an Agent EDR / security gateway.
Your role is ADVISORY ONLY — you suggest responses to security events but do NOT execute actions.
All decisions are made by deterministic YAML playbooks or human admins.

Guidelines:
- Focus on defensive recommendations only
- Never suggest offensive actions, exploits, or attack simulations
- Recommend containment, monitoring, or escalation to human review
- Be concise and actionable
- Respect that high-impact actions require human confirmation

Product: PhaseOne10841 by Veracity Integrity LLC
Site: https://VeracityIntegrity.com`;
}

function buildUserPrompt(request: AdvisorRequest): string {
  let prompt = `Security Event Summary:\n${request.event_summary}\n\nContext:\n${request.context}`;
  
  if (request.playbook_matches?.length) {
    prompt += `\n\nMatched Playbooks: ${request.playbook_matches.join(', ')}`;
  }
  
  if (request.question) {
    prompt += `\n\nSpecific Question: ${request.question}`;
  } else {
    prompt += '\n\nProvide a brief advisory recommendation for this security event.';
  }
  
  return prompt;
}

async function callChatCompletion(
  baseUrl: string,
  model: string,
  messages: ChatCompletionMessage[],
  apiKey: string | null,
  timeoutMs: number,
  maxTokens: number,
  fetchImpl: typeof fetch = fetch
): Promise<{ ok: boolean; content?: string; error?: string }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
    headers['HTTP-Referer'] = 'https://VeracityIntegrity.com';
    headers['X-Title'] = 'PhaseOne10841 Gatekeeper';
  }

  try {
    const response = await fetchImpl(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model,
        messages,
        max_tokens: maxTokens,
        temperature: 0.3,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'unknown error');
      return { ok: false, error: `HTTP ${response.status}: ${errorText.slice(0, 200)}` };
    }

    const data = await response.json() as ChatCompletionResponse;

    if (data.error?.message) {
      return { ok: false, error: data.error.message };
    }

    const content = data.choices?.[0]?.message?.content;
    if (!content || content.trim().length === 0) {
      return { ok: false, error: 'empty response from model' };
    }

    return { ok: true, content: content.trim() };
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof Error) {
      if (err.name === 'AbortError') {
        return { ok: false, error: `timeout after ${timeoutMs}ms` };
      }
      return { ok: false, error: err.message };
    }
    return { ok: false, error: 'unknown error' };
  }
}

export async function completeAdvisorPrompt(
  request: AdvisorRequest,
  cfg?: GatekeeperLLMConfig,
  fetchImpl: typeof fetch = fetch
): Promise<AdvisorResponse> {
  const config = cfg ?? loadGatekeeperLLMConfig();
  const startTime = Date.now();

  if (!config.enabled) {
    return {
      ok: false,
      provider: 'none',
      fallback_used: false,
      error: 'LLM advisor not enabled',
      latency_ms: Date.now() - startTime,
    };
  }

  const messages: ChatCompletionMessage[] = [
    { role: 'system', content: buildSystemPrompt() },
    { role: 'user', content: buildUserPrompt(request) },
  ];

  if (config.primary === 'openrouter' && config.openrouter.apiKey) {
    const primaryResult = await callChatCompletion(
      config.openrouter.baseUrl,
      config.openrouter.model,
      messages,
      config.openrouter.apiKey,
      config.timeoutMs,
      config.maxTokens,
      fetchImpl
    );

    if (primaryResult.ok && primaryResult.content) {
      return {
        ok: true,
        provider: 'openrouter',
        suggestion: primaryResult.content,
        fallback_used: false,
        latency_ms: Date.now() - startTime,
      };
    }

    console.warn(`[PhaseOne Gatekeeper LLM] OpenRouter failed: ${primaryResult.error}, trying fallback`);

    if (config.fallback === 'ollama') {
      const fallbackResult = await callChatCompletion(
        config.ollama.baseUrl,
        config.ollama.model,
        messages,
        null,
        config.timeoutMs,
        config.maxTokens,
        fetchImpl
      );

      if (fallbackResult.ok && fallbackResult.content) {
        return {
          ok: true,
          provider: 'ollama',
          suggestion: fallbackResult.content,
          fallback_used: true,
          latency_ms: Date.now() - startTime,
        };
      }

      return {
        ok: false,
        provider: 'none',
        fallback_used: true,
        error: `primary (openrouter): ${primaryResult.error}; fallback (ollama): ${fallbackResult.error}`,
        latency_ms: Date.now() - startTime,
      };
    }

    return {
      ok: false,
      provider: 'none',
      fallback_used: false,
      error: primaryResult.error,
      latency_ms: Date.now() - startTime,
    };
  }

  if (config.primary === 'ollama' || (config.primary === 'openrouter' && !config.openrouter.apiKey)) {
    const ollamaUrl = config.primary === 'ollama' ? config.ollama.baseUrl : config.ollama.baseUrl;
    const ollamaModel = config.primary === 'ollama' ? config.ollama.model : config.ollama.model;

    const result = await callChatCompletion(
      ollamaUrl,
      ollamaModel,
      messages,
      null,
      config.timeoutMs,
      config.maxTokens,
      fetchImpl
    );

    if (result.ok && result.content) {
      return {
        ok: true,
        provider: 'ollama',
        suggestion: result.content,
        fallback_used: config.primary === 'openrouter',
        latency_ms: Date.now() - startTime,
      };
    }

    return {
      ok: false,
      provider: 'none',
      fallback_used: config.primary === 'openrouter',
      error: result.error,
      latency_ms: Date.now() - startTime,
    };
  }

  return {
    ok: false,
    provider: 'none',
    fallback_used: false,
    error: 'no LLM provider configured',
    latency_ms: Date.now() - startTime,
  };
}

export async function checkLLMHealth(
  cfg?: GatekeeperLLMConfig,
  fetchImpl: typeof fetch = fetch
): Promise<{
  openrouter: { ok: boolean; error?: string; latency_ms?: number };
  ollama: { ok: boolean; error?: string; latency_ms?: number };
  recommended_provider: LLMProvider;
}> {
  const config = cfg ?? loadGatekeeperLLMConfig();

  const testRequest: AdvisorRequest = {
    context: 'Health check',
    event_summary: 'Test event for LLM health check',
    question: 'Respond with "OK" to confirm you are operational.',
  };

  const messages: ChatCompletionMessage[] = [
    { role: 'system', content: 'Respond with exactly "OK" to health checks.' },
    { role: 'user', content: 'Health check. Respond with "OK".' },
  ];

  const openrouterResult: { ok: boolean; error?: string; latency_ms?: number } = { ok: false };
  const ollamaResult: { ok: boolean; error?: string; latency_ms?: number } = { ok: false };

  if (config.openrouter.apiKey) {
    const start = Date.now();
    const result = await callChatCompletion(
      config.openrouter.baseUrl,
      config.openrouter.model,
      messages,
      config.openrouter.apiKey,
      Math.min(config.timeoutMs, 15000),
      64,
      fetchImpl
    );
    openrouterResult.latency_ms = Date.now() - start;
    openrouterResult.ok = result.ok;
    openrouterResult.error = result.error;
  } else {
    openrouterResult.error = 'OPENROUTER_API_KEY not configured';
  }

  const ollamaStart = Date.now();
  const ollamaCheck = await callChatCompletion(
    config.ollama.baseUrl,
    config.ollama.model,
    messages,
    null,
    Math.min(config.timeoutMs, 15000),
    64,
    fetchImpl
  );
  ollamaResult.latency_ms = Date.now() - ollamaStart;
  ollamaResult.ok = ollamaCheck.ok;
  ollamaResult.error = ollamaCheck.error;

  let recommended: LLMProvider = 'none';
  if (openrouterResult.ok) {
    recommended = 'openrouter';
  } else if (ollamaResult.ok) {
    recommended = 'ollama';
  }

  return {
    openrouter: openrouterResult,
    ollama: ollamaResult,
    recommended_provider: recommended,
  };
}

export function formatAdvisorSuggestion(response: AdvisorResponse): string {
  if (!response.ok) {
    return `[Advisor unavailable: ${response.error}]`;
  }

  const providerNote = response.fallback_used 
    ? ` (via fallback ${response.provider})`
    : ` (via ${response.provider})`;

  return `${response.suggestion}${providerNote}`;
}
