# PhaseOne10841 Python SDK

**phaseone-client** — Python client for the Defensive Agent Security Gateway.

**Veracity Integrity LLC** · https://VeracityIntegrity.com  
PhaseOne10841 v0.8.0

---

## Installation

```bash
pip install phaseone-client
# or
poetry add phaseone-client
# or
uv add phaseone-client
```

## Quick Start

```python
from phaseone_client import PhaseOneClient

client = PhaseOneClient(
    base_url="http://localhost:8080",
    agent_id="my-agent",
)

# Pre-check a tool call before execution
result = client.enforce(
    tool_name="http_request",
    arguments={"url": "https://api.example.com"},
)

if result.allowed:
    # Safe to execute the tool
    import requests
    response = requests.get("https://api.example.com")
else:
    print(f"Tool blocked: {result.decision.reason}")
```

---

## Configuration

### Constructor Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `base_url` | `str` | `http://localhost:8080` | PhaseOne gateway URL |
| `agent_id` | `str` | `agent-default` | Agent identifier |
| `session_id` | `str` | Auto-generated UUID | Session identifier |
| `api_key` | `str` | `OPENAI_API_KEY` env | API key for upstream |
| `timeout` | `float` | `30.0` | Request timeout (seconds) |
| `headers` | `Dict[str, str]` | `{}` | Additional headers |

### Environment Variables

The SDK reads these environment variables as fallbacks:

- `PHASEONE_GATEWAY_URL` - Gateway base URL
- `PHASEONE_AGENT_ID` - Agent identifier
- `OPENAI_API_KEY` - API key for upstream provider

---

## Core Methods

### enforce(tool_name, arguments, wait_for_approval, session_id)

Pre-check a tool call against policy before execution.

```python
result = client.enforce(
    tool_name="run_shell",
    arguments={"command": "ls -la"},
    wait_for_approval=False,
)

if result.allowed:
    # Execute the tool
    pass
elif result.pending_approval:
    # Poll for approval
    print(f"Approval ID: {result.approval_id}")
else:
    # Denied
    print(f"Blocked by: {result.decision.rule_id}")
```

### scan(text, source, channel, session_id)

Scan text for prompt injection attacks.

```python
result = client.scan(
    text=user_input,
    source="untrusted",
    channel="chat-input",
)

if result.blocked:
    print(f"Injection detected: {result.blocked_rules}")
```

### scan_untrusted(content, channel)

Scan tool results, RAG context, or MCP payloads.

```python
tool_result = execute_tool()
scan_result = client.scan_untrusted(tool_result, "tool_response")

if not scan_result.allowed:
    # Don't use this result
    pass
```

### chat(messages, model, tool_calls, **kwargs)

Send OpenAI-compatible chat completions through the gateway.

```python
response = client.chat(
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Hello!"},
    ],
    model="gpt-4",
    # Pre-check tool calls
    tool_calls=[
        {"name": "search", "arguments": {"query": "weather"}},
    ],
)

print(response.choices[0].message.content)
```

### record_event(...)

Record events for audit and analysis.

```python
client.record_event(
    event_type="custom.action",
    severity="info",
    tool_name="my_tool",
    tool_args={"key": "value"},
    metadata={"context": "additional data"},
)
```

### health()

Check gateway health status.

```python
status = client.health()
print(f"Gateway status: {status['status']}")
print(f"Upstream: {status['upstream']}")
```

---

## Session Management

```python
# Get current session ID
session_id = client.get_session_id()

# Create new session
new_session_id = client.new_session()

# Get/set agent ID
agent_id = client.get_agent_id()
client.set_agent_id("new-agent")
```

---

## Context Manager

Use the client as a context manager for automatic cleanup:

```python
with PhaseOneClient(agent_id="my-agent") as client:
    result = client.enforce(tool_name="read_file")
    # Client is automatically closed when done
```

---

## OpenAI SDK Integration

Use PhaseOne as a proxy for the OpenAI SDK:

```python
from openai import OpenAI
from phaseone_client import PhaseOneClient

phaseone = PhaseOneClient(agent_id="my-agent")
config = phaseone.get_openai_config()

openai = OpenAI(
    base_url=config["base_url"],
    api_key=config["api_key"],
    default_headers=config["default_headers"],
)

# All requests now go through PhaseOne gateway
response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

---

## Helper Functions

### with_enforcement(client)

Wrap tool execution with automatic policy enforcement.

```python
from phaseone_client import with_enforcement

safe_execute = with_enforcement(client)

# Automatically checks policy before execution
result = safe_execute(
    "http_request",
    {"url": "https://api.example.com"},
    lambda args: requests.get(args["url"]).json(),
)
```

### create_client(...)

Factory function for creating clients.

```python
from phaseone_client import create_client

client = create_client(
    agent_id="my-agent",
    base_url="http://gateway.example.com",
)
```

---

## Error Handling

```python
from phaseone_client import PhaseOneError

try:
    client.enforce(tool_name="dangerous")
except PhaseOneError as err:
    print(f"Error: {err}")
    print(f"Code: {err.code}")
    print(f"Status: {err.status}")
```

---

## Framework Integration

### LangChain

```python
from langchain_openai import ChatOpenAI
from phaseone_client import PhaseOneClient

phaseone = PhaseOneClient(agent_id="langchain-agent")
config = phaseone.get_openai_config()

model = ChatOpenAI(
    base_url=config["base_url"],
    api_key=config["api_key"],
    default_headers=config["default_headers"],
)
```

### CrewAI

Configure your CrewAI OpenAI client with `get_openai_config()` values.

---

## Data Classes

### EnforceResult

```python
@dataclass
class EnforceResult:
    allowed: bool
    pending_approval: bool = False
    approval_id: Optional[str] = None
    decision: Optional[Decision] = None
    error: Optional[Dict[str, Any]] = None
```

### ScanResult

```python
@dataclass
class ScanResult:
    blocked: bool
    hits: List[ScanHit]
    blocked_rules: List[str]
    policy_mode: str
    block_enabled: bool
    session_id: str
```

### ChatCompletionResult

```python
@dataclass
class ChatCompletionResult:
    id: str
    object: str
    created: int
    model: str
    choices: List[ChatCompletionChoice]
    usage: Optional[Dict[str, int]] = None
    phaseone: Optional[Dict[str, str]] = None
```

---

## Best Practices

1. **Always enforce before executing** — Check policy before running tools
2. **Scan untrusted content** — Validate tool results and RAG context
3. **Use meaningful agent IDs** — Helps with audit and debugging
4. **Handle approval flow** — Support pending approvals in destructive actions
5. **Record custom events** — Audit significant actions for compliance
6. **Use context managers** — Ensures proper cleanup

---

**DEFENSIVE ONLY** — PhaseOne10841 is a defensive security gateway.  
Contact Veracity Integrity LLC via https://VeracityIntegrity.com for support.
