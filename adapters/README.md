# PhaseOne10841 Framework Adapters

**Defensive integration adapters** — route agent frameworks through the PhaseOne gateway for policy enforcement, recording, and detection.

Product: [PhaseOne10841](https://phaseone10841.me) by [Veracity Integrity LLC](https://VeracityIntegrity.com)

> **DEFENSIVE ONLY.** No offensive tooling. These adapters document how to integrate agent frameworks with PhaseOne security controls.

---

## Table of Contents

- [Quick Start](#quick-start)
- [OpenAI-Compatible](#openai-compatible-recommended)
- [LangChain](#langchain)
- [CrewAI](#crewai)
- [Claude / Anthropic](#claude--anthropic)
- [Tool Enforcement Hook](#tool-enforcement-hook)
- [Scanning Untrusted Content](#scanning-untrusted-content)
- [A2A Firewall](#a2a-firewall)
- [Environment Variables](#environment-variables)

---

## Quick Start

After `docker compose up`:

```bash
# Gateway OpenAI-compatible base
export OPENAI_BASE_URL=http://localhost:8080/v1
export OPENAI_API_KEY=unused-for-mock
```

All adapters follow the same pattern:
1. Point LLM calls at the PhaseOne gateway (`/v1`)
2. Wrap tool calls with `/v1/phaseone/tools/enforce`
3. Scan untrusted content with `/v1/phaseone/scan/untrusted`
4. Route agent-to-agent messages through `/v1/phaseone/a2a/message`

---

## OpenAI-Compatible (Recommended)

The simplest integration — any OpenAI SDK client works.

### TypeScript / Node.js

```ts
import OpenAI from 'openai';
import { phaseOneOpenAIConfig } from './adapters/openai-compatible';

// Using the helper
const config = phaseOneOpenAIConfig({ agentId: 'my-agent' });
const client = new OpenAI(config);

// Or manual config
const client = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: 'unused-for-mock',
  defaultHeaders: {
    'X-PhaseOne-Agent-Id': 'my-agent',
    'X-PhaseOne-Session-Id': crypto.randomUUID(),
  },
});

const completion = await client.chat.completions.create({
  model: 'phaseone-mock',
  messages: [{ role: 'user', content: 'Hello via PhaseOne' }],
});
```

### Python

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

response = client.chat.completions.create(
    model="phaseone-mock",
    messages=[{"role": "user", "content": "Hello via PhaseOne"}],
)
print(response.choices[0].message.content)
```

### curl

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-PhaseOne-Agent-Id: my-agent' \
  -H "X-PhaseOne-Session-Id: $(uuidgen || cat /proc/sys/kernel/random/uuid)" \
  -d '{
    "model": "phaseone-mock",
    "messages": [{"role":"user","content":"Hello via PhaseOne"}]
  }'
```

**Helper:** `adapters/openai-compatible.ts` → `phaseOneOpenAIConfig()`

---

## LangChain

Route LangChain agents through PhaseOne with tool enforcement.

### TypeScript Integration

```ts
import { ChatOpenAI } from '@langchain/openai';
import { 
  langchainPhaseOneConfig, 
  enforceToolCall,
  scanUntrusted,
  createToolEnforceWrapper 
} from './adapters/langchain-stub';

// Get configuration
const config = langchainPhaseOneConfig('http://localhost:8080', 'langchain-agent');

// Create LLM pointed at PhaseOne
const llm = new ChatOpenAI({
  configuration: { baseURL: config.baseURL },
  apiKey: 'unused-for-mock',
  model: config.model,
});

// Wrap a tool with enforcement
const safeShellTool = createToolEnforceWrapper(config, 'run_shell', originalShellFunc);

// Or manually enforce before tool execution
const result = await enforceToolCall(config.enforceToolUrl, {
  agent_id: 'langchain-agent',
  tool_name: 'run_shell',
  arguments: { command: 'ls -la' },
});

if (!result.allowed) {
  if (result.pending_approval) {
    console.log('Awaiting human approval:', result.approval_id);
  } else {
    throw new Error(`Tool denied: ${result.reason}`);
  }
}

// Scan RAG retrieval results
const scanResult = await scanUntrusted(config.scanUntrustedUrl, {
  content: retrievedDocument,
  source: 'rag-vector-store',
});

if (!scanResult.safe) {
  console.warn('Potential injection detected:', scanResult.injection_score);
}
```

### Python Integration

```python
from langchain_openai import ChatOpenAI
import requests
import uuid

PHASEONE_GATEWAY = "http://localhost:8080"
AGENT_ID = "langchain-agent"
SESSION_ID = str(uuid.uuid4())

llm = ChatOpenAI(
    base_url=f"{PHASEONE_GATEWAY}/v1",
    api_key="unused-for-mock",
    model="phaseone-mock",
    default_headers={
        "X-PhaseOne-Agent-Id": AGENT_ID,
        "X-PhaseOne-Session-Id": SESSION_ID,
    }
)

def enforce_tool(tool_name: str, arguments: dict) -> dict:
    """Check if tool call is allowed by PhaseOne policy."""
    response = requests.post(
        f"{PHASEONE_GATEWAY}/v1/phaseone/tools/enforce",
        json={
            "agent_id": AGENT_ID,
            "tool_name": tool_name,
            "arguments": arguments,
        }
    )
    return response.json()
```

**Helper:** `adapters/langchain-stub.ts`

---

## CrewAI

Route CrewAI agents through PhaseOne with A2A firewall support.

### Python Integration

```python
from crewai import Agent, Crew, Task
from langchain_openai import ChatOpenAI
import os
import uuid
import requests

PHASEONE_GATEWAY = os.getenv("PHASEONE_GATEWAY_URL", "http://localhost:8080")
SESSION_ID = str(uuid.uuid4())

def create_phaseone_llm(agent_id: str) -> ChatOpenAI:
    """Create a ChatOpenAI instance routed through PhaseOne."""
    return ChatOpenAI(
        base_url=f"{PHASEONE_GATEWAY}/v1",
        api_key=os.getenv("OPENAI_API_KEY", "phaseone-unused"),
        model=os.getenv("PHASEONE_MODEL", "phaseone-mock"),
        default_headers={
            "X-PhaseOne-Agent-Id": agent_id,
            "X-PhaseOne-Session-Id": SESSION_ID,
        }
    )

def send_a2a_message(source_id: str, target_id: str, message: str) -> dict:
    """Route inter-agent messages through PhaseOne A2A firewall."""
    response = requests.post(
        f"{PHASEONE_GATEWAY}/v1/phaseone/a2a/message",
        json={
            "source_agent_id": source_id,
            "target_agent_id": target_id,
            "message": message,
        }
    )
    return response.json()

# Create crew agents with distinct IDs
researcher = Agent(
    role='Senior Researcher',
    goal='Find accurate information',
    llm=create_phaseone_llm("crewai-researcher"),
)

writer = Agent(
    role='Technical Writer', 
    goal='Create clear documentation',
    llm=create_phaseone_llm("crewai-writer"),
)

# A2A messages between agents are monitored
result = send_a2a_message("crewai-researcher", "crewai-writer", "Here are my findings...")
if not result.get("allowed"):
    print(f"A2A message blocked: {result.get('reason')}")
```

### TypeScript Helper

```ts
import { crewaiPhaseOneConfig, sendA2AMessage, enforceToolCall } from './adapters/crewai-stub';

const config = crewaiPhaseOneConfig('http://localhost:8080');

// Route A2A message
const result = await sendA2AMessage(config.a2a_endpoint, {
  source_agent_id: 'crewai-researcher',
  target_agent_id: 'crewai-writer',
  message: 'Research complete, here are my findings...',
});

// Enforce tool call
const enforceResult = await enforceToolCall(config.tool_enforce_endpoint, {
  agent_id: 'crewai-researcher',
  tool_name: 'web_search',
  arguments: { query: 'AI safety research' },
});
```

**Helper:** `adapters/crewai-stub.ts`

---

## Claude / Anthropic

Integrate Claude's tool_use format with PhaseOne enforcement.

### TypeScript Integration

```ts
import Anthropic from '@anthropic-ai/sdk';
import {
  claudeToolProxyConfig,
  enforceToolUse,
  createSafeToolResult,
  waitForApproval,
} from './adapters/claude-tool-proxy-stub';

const AGENT_ID = 'my-claude-agent';
const config = claudeToolProxyConfig('http://localhost:8080');
const anthropic = new Anthropic();

async function handleToolUse(toolUse: { type: 'tool_use'; id: string; name: string; input: any }) {
  // Step 1: Enforce tool call through PhaseOne
  const enforceResult = await enforceToolUse(config, toolUse, AGENT_ID);
  
  if (!enforceResult.allowed) {
    if (enforceResult.pending_approval && enforceResult.approval_id) {
      // Wait for human approval
      const status = await waitForApproval(config, enforceResult.approval_id);
      if (status.status !== 'approved') {
        return { type: 'tool_result', tool_use_id: toolUse.id, content: 'Denied by policy', is_error: true };
      }
    } else {
      return { type: 'tool_result', tool_use_id: toolUse.id, content: `Denied: ${enforceResult.reason}`, is_error: true };
    }
  }

  // Step 2: Execute the tool
  const output = await executeToolLocally(toolUse);
  
  // Step 3: Scan and return result
  return await createSafeToolResult(config, toolUse.id, output, `tool:${toolUse.name}`, AGENT_ID);
}
```

### Python Integration

```python
import anthropic
import requests

PHASEONE_GATEWAY = "http://localhost:8080"
AGENT_ID = "claude-agent"

def enforce_tool_use(tool_use: dict) -> dict:
    """Enforce a Claude tool_use block through PhaseOne."""
    response = requests.post(
        f"{PHASEONE_GATEWAY}/v1/phaseone/tools/enforce",
        json={
            "agent_id": AGENT_ID,
            "tool_name": tool_use["name"],
            "arguments": tool_use["input"],
            "tool_use_id": tool_use["id"],
        }
    )
    return response.json()

def scan_tool_result(content: str, source: str) -> dict:
    """Scan tool output for injection, canaries, secrets."""
    response = requests.post(
        f"{PHASEONE_GATEWAY}/v1/phaseone/scan/untrusted",
        json={"content": content, "source": source, "agent_id": AGENT_ID}
    )
    return response.json()

client = anthropic.Anthropic()

# After receiving tool_use from Claude
for block in response.content:
    if block.type == "tool_use":
        result = enforce_tool_use({"id": block.id, "name": block.name, "input": block.input})
        if not result.get("allowed"):
            # Handle denial
            pass
```

**Helper:** `adapters/claude-tool-proxy-stub.ts`

---

## Tool Enforcement Hook

Before executing any side-effecting tool, check with PhaseOne:

```bash
curl -s http://localhost:8080/v1/phaseone/tools/enforce \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "my-agent",
    "tool_name": "run_shell",
    "arguments": {"command": "ls -la"},
    "wait_for_approval": false
  }'
```

**Responses:**

| Response | Meaning |
|----------|---------|
| `{"allowed": true}` | Proceed with execution |
| `{"allowed": false, "reason": "..."}` | Tool denied by policy |
| `{"allowed": false, "pending_approval": true, "approval_id": "..."}` | Awaiting human approval |

For destructive tools (configured in policy), wait for approval:
- Poll `GET /v1/phaseone/approvals/{id}` for status
- Or set `wait_for_approval: true` (blocks until approved/denied/timeout)

---

## Scanning Untrusted Content

Scan RAG results, tool outputs, MCP responses for threats:

```bash
curl -s http://localhost:8080/v1/phaseone/scan/untrusted \
  -H 'Content-Type: application/json' \
  -d '{
    "content": "Retrieved document text...",
    "source": "rag-vector-store",
    "agent_id": "my-agent"
  }'
```

**Response:**

```json
{
  "safe": false,
  "injection_score": 0.85,
  "canary_detected": false,
  "secrets_detected": false,
  "warnings": ["High injection likelihood detected"]
}
```

---

## A2A Firewall

Route agent-to-agent messages through PhaseOne for trust-level enforcement:

```bash
curl -s http://localhost:8080/v1/phaseone/a2a/message \
  -H 'Content-Type: application/json' \
  -d '{
    "source_agent_id": "agent-research",
    "target_agent_id": "agent-writer",
    "message": "Here are my findings...",
    "metadata": {"task": "research-handoff"}
  }'
```

Trust levels are configured per source agent in the dashboard.

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PHASEONE_GATEWAY_URL` | Gateway base URL | `http://localhost:8080` |
| `PHASEONE_AGENT_ID` | Default agent ID header | `agent-default` |
| `UPSTREAM_PROVIDER` | Gateway upstream: `mock` \| `openai` \| `ollama` \| `openrouter` | `mock` |
| `OPENAI_API_KEY` | API key for upstream (when `UPSTREAM_PROVIDER=openai`) | - |

---

## Adapter Status

| Framework | Status | Helper File |
|-----------|--------|-------------|
| OpenAI SDK | **Works** | `openai-compatible.ts` |
| LangChain | **Works** (helper + examples) | `langchain-stub.ts` |
| CrewAI | **Works** (helper + examples) | `crewai-stub.ts` |
| Claude/Anthropic | **Works** (helper + examples) | `claude-tool-proxy-stub.ts` |

---

## OpenAPI

Full gateway + admin surface: [`docs/openapi.yaml`](../docs/openapi.yaml)

---

**Veracity Integrity LLC** · https://VeracityIntegrity.com

DEFENSIVE ONLY — no exploit tooling.
