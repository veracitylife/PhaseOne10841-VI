/** Inert mock upstream for local demos without external API keys. */

export interface ChatMessage {
  role: string;
  content?: string | null;
  tool_calls?: unknown[];
}

export function mockChatCompletion(body: {
  model?: string;
  messages?: ChatMessage[];
  tools?: unknown[];
}): Record<string, unknown> {
  const last = [...(body.messages ?? [])].reverse().find((m) => m.role === 'user');
  const userText = typeof last?.content === 'string' ? last.content : JSON.stringify(last?.content ?? '');
  const content = `[phaseone-mock] Echo (policy gateway passed). You said: ${userText.slice(0, 500)}`;

  return {
    id: `chatcmpl-phaseone-${Date.now()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: body.model ?? 'phaseone-mock',
    choices: [
      {
        index: 0,
        message: { role: 'assistant', content },
        finish_reason: 'stop',
      },
    ],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    phaseone: { upstream: 'mock' },
  };
}
