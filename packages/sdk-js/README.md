# @phaseone/client

**PhaseOne10841 TypeScript/JavaScript Client SDK**

Defensive Agent Security Gateway client library for LLM agents and AI applications.

A product of [Veracity Integrity LLC](https://VeracityIntegrity.com)

---

## Installation

```bash
npm install @phaseone/client
# or
yarn add @phaseone/client
# or
pnpm add @phaseone/client
```

## Quick Start

```typescript
import { PhaseOneClient } from '@phaseone/client';

// Create a client
const client = new PhaseOneClient({
  baseUrl: 'http://localhost:8080',
  agentId: 'my-agent',
});

// Pre-check a tool call
const result = await client.enforce({
  toolName: 'http_request',
  arguments: { url: 'https://api.example.com/data' },
});

if (!result.allowed) {
  console.log('Tool blocked:', result.decision.reason);
  return;
}

// Proceed with the tool call...
```

## Features

- **Tool Enforcement** - Pre-check tool calls against policy before execution
- **Injection Scanning** - Scan text for prompt injection attacks
- **Chat Proxy** - Route OpenAI-compatible requests through the gateway
- **Event Recording** - Log events for audit and analysis
- **OpenAI SDK Integration** - Get config for use with OpenAI SDK

## Configuration

```typescript
const client = new PhaseOneClient({
  // Gateway URL (default: http://localhost:8080)
  baseUrl: 'http://localhost:8080',
  
  // Agent identifier
  agentId: 'my-agent',
  
  // Session ID (auto-generated if not provided)
  sessionId: 'optional-session-id',
  
  // API key for upstream provider
  apiKey: process.env.OPENAI_API_KEY,
  
  // Request timeout in ms (default: 30000)
  timeout: 30000,
  
  // Additional headers
  headers: {
    'X-Custom-Header': 'value',
  },
});
```

### Environment Variables

The client reads these environment variables as defaults:

- `PHASEONE_GATEWAY_URL` - Gateway base URL
- `PHASEONE_AGENT_ID` - Agent identifier
- `OPENAI_API_KEY` - API key for upstream provider

## API Reference

### enforce(options)

Pre-check a tool call against policy.

```typescript
const result = await client.enforce({
  toolName: 'run_shell',
  arguments: { command: 'ls -la' },
  waitForApproval: false, // Wait for human approval if required
});

if (result.allowed) {
  // Safe to execute
} else if (result.pendingApproval) {
  // Waiting for human approval
  console.log('Approval ID:', result.approvalId);
} else {
  // Denied by policy
  console.log('Reason:', result.decision.reason);
}
```

### scan(options)

Scan text for prompt injection.

```typescript
const result = await client.scan({
  text: userInput,
  source: 'untrusted', // 'user' | 'system' | 'untrusted'
  channel: 'chat-input',
});

if (result.blocked) {
  console.log('Injection detected:', result.scan.blockedRules);
}
```

### scanUntrusted(content, channel)

Scan tool results, RAG context, or MCP payloads.

```typescript
const result = await client.scanUntrusted(
  toolResult,
  'mcp_response'
);

if (!result.allowed) {
  console.log('Untrusted content blocked');
}
```

### chat(options)

Send chat completion through the gateway.

```typescript
const response = await client.chat({
  messages: [
    { role: 'system', content: 'You are a helpful assistant.' },
    { role: 'user', content: 'Hello!' },
  ],
  model: 'gpt-4',
  // Pre-check tool calls
  toolCalls: [
    { name: 'search', arguments: { query: 'weather' } },
  ],
});

console.log(response.choices[0].message.content);
```

### recordEvent(options)

Record an event for audit.

```typescript
await client.recordEvent({
  eventType: 'custom.action',
  severity: 'info',
  toolName: 'my_tool',
  toolArgs: { key: 'value' },
  metadata: { custom: 'data' },
});
```

### getOpenAIConfig()

Get configuration for OpenAI SDK.

```typescript
import OpenAI from 'openai';

const client = new PhaseOneClient({ agentId: 'my-agent' });
const openai = new OpenAI(client.getOpenAIConfig());

const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello!' }],
});
```

## Helpers

### withEnforcement(client)

Wrap tool execution with automatic enforcement.

```typescript
import { withEnforcement } from '@phaseone/client';

const safeExecute = withEnforcement(client);

// Automatically checks policy before execution
const result = await safeExecute(
  'http_request',
  { url: 'https://api.example.com' },
  async (args) => {
    const res = await fetch(args.url);
    return res.json();
  }
);
```

## Error Handling

```typescript
import { PhaseOneError } from '@phaseone/client';

try {
  await client.enforce({ toolName: 'dangerous_tool' });
} catch (err) {
  if (err instanceof PhaseOneError) {
    console.log('PhaseOne error:', err.message);
    console.log('Code:', err.code);
    console.log('Status:', err.status);
  }
}
```

## Framework Integration

### LangChain

```typescript
import { PhaseOneClient } from '@phaseone/client';
import { ChatOpenAI } from '@langchain/openai';

const client = new PhaseOneClient({ agentId: 'langchain-agent' });
const config = client.getOpenAIConfig();

const model = new ChatOpenAI({
  configuration: {
    baseURL: config.baseURL,
    defaultHeaders: config.defaultHeaders,
  },
});
```

### CrewAI / Other Frameworks

Use `getOpenAIConfig()` to get the base URL and headers, then configure your framework's OpenAI client accordingly.

## License

MIT — Veracity Integrity LLC · https://VeracityIntegrity.com

DEFENSIVE ONLY — PhaseOne10841 is a defensive security gateway.
