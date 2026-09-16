export type UpstreamProvider = 'openai' | 'ollama' | 'openrouter' | 'mock';

export interface GatewayConfig {
  port: number;
  upstream: UpstreamProvider;
  openaiBaseUrl: string;
  openaiApiKey: string;
  ollamaBaseUrl: string;
  openrouterBaseUrl: string;
  openrouterApiKey: string;
  databaseUrl: string;
  policyPath?: string;
  siemWebhookUrl?: string;
  productVersion: string;
}

export function loadConfig(): GatewayConfig {
  const upstream = (process.env.UPSTREAM_PROVIDER ?? 'mock') as UpstreamProvider;
  return {
    port: Number(process.env.GATEWAY_PORT ?? 8080),
    upstream,
    openaiBaseUrl: process.env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1',
    openaiApiKey: process.env.OPENAI_API_KEY ?? '',
    ollamaBaseUrl: process.env.OLLAMA_BASE_URL ?? 'http://host.docker.internal:11434/v1',
    openrouterBaseUrl: process.env.OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1',
    openrouterApiKey: process.env.OPENROUTER_API_KEY ?? '',
    databaseUrl: process.env.DATABASE_URL ?? 'postgres://phaseone:phaseone@localhost:5432/phaseone',
    policyPath: process.env.PHASEONE_POLICY_PATH,
    siemWebhookUrl: process.env.PHASEONE_SIEM_WEBHOOK_URL ?? process.env.SIEM_WEBHOOK_URL,
    productVersion: '0.3.0',
  };
}

export function resolveUpstream(cfg: GatewayConfig): { baseUrl: string; apiKey: string; label: string } {
  switch (cfg.upstream) {
    case 'openai':
      return { baseUrl: cfg.openaiBaseUrl, apiKey: cfg.openaiApiKey, label: 'openai' };
    case 'ollama':
      return { baseUrl: cfg.ollamaBaseUrl, apiKey: 'ollama', label: 'ollama' };
    case 'openrouter':
      return { baseUrl: cfg.openrouterBaseUrl, apiKey: cfg.openrouterApiKey, label: 'openrouter' };
    case 'mock':
    default:
      return { baseUrl: 'mock://local', apiKey: '', label: 'mock' };
  }
}
