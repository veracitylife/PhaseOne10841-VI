# phaseone-client

**PhaseOne10841 Python Client SDK**

Defensive Agent Security Gateway client library for LLM agents and AI applications.

A product of [Veracity Integrity LLC](https://VeracityIntegrity.com)

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

# Create a client
client = PhaseOneClient(
    base_url="http://localhost:8080",
    agent_id="my-agent",
)

# Pre-check a tool call
result = client.enforce(
    tool_name="http_request",
    arguments={"url": "https://api.example.com/data"},
)

if not result.allowed:
    print(f"Tool blocked: {result.decision.reason}")
else:
    # Proceed with the tool call...
    pass
```

## Features

- **Tool Enforcement** - Pre-check tool calls against policy before execution
- **Injection Scanning** - Scan text for prompt injection attacks
- **Chat Proxy** - Route OpenAI-compatible requests through the gateway
- **Event Recording** - Log events for audit and analysis
- **OpenAI SDK Integration** - Get config for use with OpenAI SDK

## Configuration

```python
client = PhaseOneClient(
    # Gateway URL (default: http://localhost:8080)
    base_url="http://localhost:8080",
    
    # Agent identifier
    agent_id="my-agent",
    
    # Session ID (auto-generated if not provided)
    session_id="optional-session-id",
    
    # API key for upstream provider
    api_key=os.environ.get("OPENAI_API_KEY"),
    
    # Request timeout in seconds (default: 30)
    timeout=30.0,
    
    # Additional headers
    headers={"X-Custom-Header": "value"},
)
```

### Environment Variables

The client reads these environment variables as defaults:

- `PHASEONE_GATEWAY_URL` - Gateway base URL
- `PHASEONE_AGENT_ID` - Agent identifier
- `OPENAI_API_KEY` - API key for upstream provider

## API Reference

### enforce(tool_name, arguments, wait_for_approval, session_id)

Pre-check a tool call against policy.

```python
result = client.enforce(
    tool_name="run_shell",
    arguments={"command": "ls -la"},
    wait_for_approval=False,  # Wait for human approval if required
)

if result.allowed:
    # Safe to execute
    pass
elif result.pending_approval:
    # Waiting for human approval
    print(f"Approval ID: {result.approval_id}")
else:
    # Denied by policy
    print(f"Reason: {result.decision.reason}")
```

### scan(text, source, channel, session_id)

Scan text for prompt injection.

```python
result = client.scan(
    text=user_input,
    source="untrusted",  # "user" | "system" | "untrusted"
    channel="chat-input",
)

if result.blocked:
    print(f"Injection detected: {result.blocked_rules}")
```

### scan_untrusted(content, channel)

Scan tool results, RAG context, or MCP payloads.

```python
result = client.scan_untrusted(
    content=tool_result,
    channel="mcp_response",
)

if not result.allowed:
    print("Untrusted content blocked")
```

### chat(messages, model, tool_calls, **kwargs)

Send chat completion through the gateway.

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

### record_event(event_type, severity, ...)

Record an event for audit.

```python
client.record_event(
    event_type="custom.action",
    severity="info",
    tool_name="my_tool",
    tool_args={"key": "value"},
    metadata={"custom": "data"},
)
```

### get_openai_config()

Get configuration for OpenAI SDK.

```python
from openai import OpenAI

config = client.get_openai_config()
openai = OpenAI(
    base_url=config["base_url"],
    api_key=config["api_key"],
    default_headers=config["default_headers"],
)

response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

## Helpers

### with_enforcement(client)

Wrap tool execution with automatic enforcement.

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

## Error Handling

```python
from phaseone_client import PhaseOneError

try:
    client.enforce(tool_name="dangerous_tool")
except PhaseOneError as err:
    print(f"PhaseOne error: {err}")
    print(f"Code: {err.code}")
    print(f"Status: {err.status}")
```

## Context Manager

The client can be used as a context manager:

```python
with PhaseOneClient(agent_id="my-agent") as client:
    result = client.enforce(tool_name="read_file")
    # Client is automatically closed when done
```

## Framework Integration

### LangChain

```python
from phaseone_client import PhaseOneClient
from langchain_openai import ChatOpenAI

client = PhaseOneClient(agent_id="langchain-agent")
config = client.get_openai_config()

model = ChatOpenAI(
    base_url=config["base_url"],
    api_key=config["api_key"],
    default_headers=config["default_headers"],
)
```

### CrewAI / Other Frameworks

Use `get_openai_config()` to get the base URL and headers, then configure your framework's OpenAI client accordingly.

## License

MIT — Veracity Integrity LLC · https://VeracityIntegrity.com

DEFENSIVE ONLY — PhaseOne10841 is a defensive security gateway.
