# PhaseOne10841 JavaScript/TypeScript SDK

**@phaseone/client** — TypeScript/JavaScript client for the Defensive Agent Security Gateway.

**Veracity Integrity LLC** · https://VeracityIntegrity.com  
PhaseOne10841 v0.1.1

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

const client = new PhaseOneClient({
  baseUrl: 'http://localhost:8080',
  agentId: 'my-agent',
});

// Pre-check a tool call before execution
const result = await client.enforce({
  toolName: 'http_request',
  arguments: { url: 'https://api.example.com' },
});

if (result.allowed) {
  // Safe to execute the tool
  const response = await fetch('https://api.example.com');
} else {
  console.log('Tool blocked:', result.decision.reason);
}
```

---

## Configuration

### Constructor Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | `string` | `http://localhost:8080` | PhaseOne gateway URL |
| `agentId` | `string` | `agent-default` | Agent identifier |
| `sessionId` | `string` | Auto-generated UUID | Session identifier |
| `apiKey` | `string` | `OPENAI_API_KEY` env | API key for upstream |
| `timeout` | `number` | `30000` | Request timeout (ms) |
| `headers` | `Record<string, string>` | `{}` | Additional headers |

### Environment Variables

The SDK reads these environment variables as fallbacks:

- `PHASEONE_GATEWAY_URL` - Gateway base URL
- `PHASEONE_AGENT_ID` - Agent identifier
- `OPENAI_API_KEY` - API key for upstream provider

---

## Core Methods

### enforce(options)

Pre-check a tool call against policy before execution.

```typescript
interface EnforceOptions {
  toolName: string;
  arguments?: unknown;
  waitForApproval?: boolean;
  sessionId?: string;
}

const result = await client.enforce({
  toolName: 'run_shell',
  arguments: { command: 'ls -la' },
  waitForApproval: false,
});

if (result.allowed) {
  // Execute the tool
} else if (result.pendingApproval) {
  // Poll for approval
  console.log('Approval ID:', result.approvalId);
} else {
  // Denied
  console.log('Blocked by:', result.decision.ruleId);
}
```

### scan(options)

Scan text for prompt injection attacks.

```typescript
interface ScanOptions {
  text: string;
  source?: 'user' | 'system' | 'untrusted';
  channel?: string;
  sessionId?: string;
}

const result = await client.scan({
  text: userInput,
  source: 'untrusted',
  channel: 'chat-input',
});

if (result.blocked) {
  console.log('Injection detected:', result.scan.blockedRules);
}
```

### scanUntrusted(content, channel)

Scan tool results, RAG context, or MCP payloads.

```typescript
const toolResult = await executeTool();
const scanResult = await client.scanUntrusted(toolResult, 'tool_response');

if (!scanResult.allowed) {
  // Don't use this result
}
```

### chat(options)

Send OpenAI-compatible chat completions through the gateway.

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

Record events for audit and analysis.

```typescript
await client.recordEvent({
  eventType: 'custom.action',
  severity: 'info',
  toolName: 'my_tool',
  toolArgs: { key: 'value' },
  metadata: { context: 'additional data' },
});
```

### health()

Check gateway health status.

```typescript
const status = await client.health();
console.log('Gateway status:', status.status);
console.log('Upstream:', status.upstream);
```

---

## Session Management

```typescript
// Get current session ID
const sessionId = client.getSessionId();

// Create new session
const newSessionId = client.newSession();

// Get/set agent ID
const agentId = client.getAgentId();
client.setAgentId('new-agent');
```

---

## OpenAI SDK Integration

Use PhaseOne as a proxy for the OpenAI SDK:

```typescript
import OpenAI from 'openai';
import { PhaseOneClient } from '@phaseone/client';

const phaseone = new PhaseOneClient({ agentId: 'my-agent' });
const openai = new OpenAI(phaseone.getOpenAIConfig());

// All requests now go through PhaseOne gateway
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello!' }],
});
```

---

## Helper Functions

### withEnforcement(client)

Wrap tool execution with automatic policy enforcement.

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

### createClient(config)

Factory function for creating clients.

```typescript
import { createClient } from '@phaseone/client';

const client = createClient({
  agentId: 'my-agent',
  baseUrl: 'http://gateway.example.com',
});
```

---

## Error Handling

```typescript
import { PhaseOneError } from '@phaseone/client';

try {
  await client.enforce({ toolName: 'dangerous' });
} catch (err) {
  if (err instanceof PhaseOneError) {
    console.log('Error:', err.message);
    console.log('Code:', err.code);
    console.log('Status:', err.status);
  }
}
```

---

## Framework Integration

### LangChain

```typescript
import { ChatOpenAI } from '@langchain/openai';
import { PhaseOneClient } from '@phaseone/client';

const phaseone = new PhaseOneClient({ agentId: 'langchain-agent' });
const config = phaseone.getOpenAIConfig();

const model = new ChatOpenAI({
  configuration: {
    baseURL: config.baseURL,
    defaultHeaders: config.defaultHeaders,
  },
});
```

### CrewAI

Configure your CrewAI OpenAI client with `getOpenAIConfig()` values.

---

## TypeScript Types

```typescript
import type {
  PhaseOneConfig,
  EnforceOptions,
  EnforceResult,
  ScanOptions,
  ScanResult,
  ChatMessage,
  ChatCompletionOptions,
  ChatCompletionResult,
  EventOptions,
} from '@phaseone/client';
```

---

## Best Practices

1. **Always enforce before executing** — Check policy before running tools
2. **Scan untrusted content** — Validate tool results and RAG context
3. **Use meaningful agent IDs** — Helps with audit and debugging
4. **Handle approval flow** — Support pending approvals in destructive actions
5. **Record custom events** — Audit significant actions for compliance

---

**DEFENSIVE ONLY** — PhaseOne10841 is a defensive security gateway.  
Contact Veracity Integrity LLC via https://VeracityIntegrity.com for support.
