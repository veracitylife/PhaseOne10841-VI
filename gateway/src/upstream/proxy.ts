import { mockChatCompletion } from './mock.js';
import type { GatewayConfig } from '../config.js';
import { resolveUpstream } from '../config.js';

export async function forwardChatCompletions(
  cfg: GatewayConfig,
  body: Record<string, unknown>
): Promise<{ status: number; data: unknown }> {
  const upstream = resolveUpstream(cfg);
  if (upstream.label === 'mock') {
    return { status: 200, data: mockChatCompletion(body as Parameters<typeof mockChatCompletion>[0]) };
  }

  const url = `${upstream.baseUrl.replace(/\/$/, '')}/chat/completions`;
  const headers: Record<string, string> = {
    'content-type': 'application/json',
  };
  if (upstream.apiKey) {
    headers.authorization = `Bearer ${upstream.apiKey}`;
  }
  if (upstream.label === 'openrouter') {
    headers['HTTP-Referer'] = process.env.OPENROUTER_REFERER ?? 'https://phaseone10841.me';
    headers['X-Title'] = 'PhaseOne10841 Gateway';
  }

  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ error: 'invalid upstream JSON' }));
  return { status: res.status, data };
}
