# PhaseOne10841 Framework Adapters

**Defensive integration stubs** — point agent frameworks at the PhaseOne gateway instead of calling upstream LLMs or tools directly.

Product: [PhaseOne10841](https://phaseone10841.me) by [Veracity Integrity LLC](https://VeracityIntegrity.com)

> No offensive tooling. These adapters only document how to route traffic through the gateway for policy enforcement, recording, and detection.

## OpenAI-compatible (supported)

Any OpenAI SDK client can target the gateway:

```ts
import OpenAI from 'openai';

const client = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: 'unused-for-mock',
  defaultHeaders: {
    'X-PhaseOne-Agent-Id': 'my-agent',
    'X-PhaseOne-Session-Id': crypto.randomUUID(),
  },
});
```

See also `examples/sample-client.ts` and `adapters/openai-compatible.ts`.

## LangChain (stub)

Point `ChatOpenAI` / OpenAI-compatible chat models at the gateway base URL:

```ts
// Conceptual — install @langchain/openai in your app, not in phaseone-core
import { ChatOpenAI } from '@langchain/openai';

const llm = new ChatOpenAI({
  configuration: { baseURL: 'http://localhost:8080/v1' },
  apiKey: 'unused-for-mock',
  model: 'phaseone-mock',
});
```

For tools: wrap tool execution with `POST /v1/phaseone/tools/enforce` before side effects.

Thin helper: `adapters/langchain-stub.ts`.

## CrewAI (stub)

Configure the LLM provider base URL to `http://localhost:8080/v1` (OpenAI-compatible).  
Register each crew agent id via `X-PhaseOne-Agent-Id`. Use A2A firewall (`POST /v1/phaseone/a2a/message`) when agents message each other.

Thin helper: `adapters/crewai-stub.ts`.

## Claude-style tool proxy (stub)

If your stack speaks Anthropic Messages API natively, use a thin translation layer in your app that:

1. Maps messages → OpenAI chat format (or call PhaseOne enforce hooks separately)
2. Sends tool use proposals to `POST /v1/phaseone/tools/enforce`
3. Scans tool results with `POST /v1/phaseone/scan/untrusted`

Thin helper: `adapters/claude-tool-proxy-stub.ts`.

## Env

| Variable | Purpose |
|----------|---------|
| `PHASEONE_GATEWAY_URL` | Default `http://localhost:8080` |
| `PHASEONE_AGENT_ID` | Default agent id header |
