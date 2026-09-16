# PhaseOne10841 Framework Adapters

**Defensive integration stubs** — point agent frameworks at the PhaseOne gateway instead of calling upstream LLMs or tools directly.

Product: [PhaseOne10841](https://phaseone10841.me) by [Veracity Integrity LLC](https://VeracityIntegrity.com)

> No offensive tooling. These adapters only document how to route traffic through the gateway for policy enforcement, recording, and detection.

## Quick start — point any OpenAI client through PhaseOne

After `docker compose up`:

```bash
# Gateway OpenAI-compatible base
export OPENAI_BASE_URL=http://localhost:8080/v1
export OPENAI_API_KEY=unused-for-mock
```

### OpenAI Node SDK (copy-paste)

```ts
import OpenAI from 'openai';

const client = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: 'unused-for-mock', // mock upstream ignores; real keys only needed if UPSTREAM_PROVIDER=openai
  defaultHeaders: {
    'X-PhaseOne-Agent-Id': 'my-agent',
    'X-PhaseOne-Session-Id': crypto.randomUUID(),
  },
});

const completion = await client.chat.completions.create({
  model: 'phaseone-mock',
  messages: [{ role: 'user', content: 'Hello via PhaseOne' }],
});
console.log(completion.choices[0]?.message);
```

### curl (copy-paste)

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'X-PhaseOne-Agent-Id: my-agent' \
  -H "X-PhaseOne-Session-Id: $(uuidgen || cat /proc/sys/kernel/random/uuid)" \
  -d '{
    "model": "phaseone-mock",
    "messages": [{"role":"user","content":"Hello via PhaseOne"}]
  }'
```

### Python openai package (copy-paste)

```python
from openai import OpenAI
import uuid

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="unused-for-mock",
    default_headers={
        "X-PhaseOne-Agent-Id": "my-agent",
        "X-PhaseOne-Session-Id": str(uuid.uuid4()),
    },
)
print(client.chat.completions.create(
    model="phaseone-mock",
    messages=[{"role": "user", "content": "Hello via PhaseOne"}],
))
```

Helper: `adapters/openai-compatible.ts` → `phaseOneOpenAIConfig()`.

Also see `examples/sample-client.ts`.

## Tool enforcement hook (any framework)

Before performing a side-effecting tool, ask the gateway:

```bash
curl -s http://localhost:8080/v1/phaseone/tools/enforce \
  -H 'content-type: application/json' \
  -d '{
    "agent_id": "my-agent",
    "tool_name": "run_shell",
    "arguments": {"command": "ls -la"},
    "wait_for_approval": false
  }'
```

Only proceed when `"allowed": true`. Destructive tools may return `202` with `pending_approval`.

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

```python
# Conceptual CrewAI / LiteLLM-style base URL override
# openai_api_base = "http://localhost:8080/v1"
# headers: X-PhaseOne-Agent-Id per crew agent
```

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
| `UPSTREAM_PROVIDER` | Gateway-side: `mock` \| `openai` \| `ollama` \| `openrouter` |

## OpenAPI

Full gateway + admin surface: [`docs/openapi.yaml`](../docs/openapi.yaml)
