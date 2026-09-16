/**
 * OpenAI-compatible client helper — points SDKs at PhaseOne gateway.
 * DEFENSIVE integration only.
 */

export interface PhaseOneOpenAIOptions {
  gatewayUrl?: string;
  agentId?: string;
  sessionId?: string;
  apiKey?: string;
}

export function phaseOneOpenAIConfig(opts: PhaseOneOpenAIOptions = {}): {
  baseURL: string;
  apiKey: string;
  defaultHeaders: Record<string, string>;
} {
  const gateway = (opts.gatewayUrl ?? process.env.PHASEONE_GATEWAY_URL ?? 'http://localhost:8080').replace(
    /\/$/,
    ''
  );
  return {
    baseURL: `${gateway}/v1`,
    apiKey: opts.apiKey ?? process.env.OPENAI_API_KEY ?? 'phaseone-unused',
    defaultHeaders: {
      'X-PhaseOne-Agent-Id': opts.agentId ?? process.env.PHASEONE_AGENT_ID ?? 'agent-default',
      'X-PhaseOne-Session-Id': opts.sessionId ?? crypto.randomUUID(),
    },
  };
}

export function describeOpenAIIntegration(): string {
  return [
    'PhaseOne10841 OpenAI-compatible adapter',
    'Set OpenAI baseURL to {GATEWAY}/v1 and pass X-PhaseOne-Agent-Id / X-PhaseOne-Session-Id.',
    'Veracity Integrity LLC · https://VeracityIntegrity.com',
  ].join('\n');
}
