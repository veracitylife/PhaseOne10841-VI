"""
PhaseOne10841 Python Client

Veracity Integrity LLC · https://VeracityIntegrity.com
DEFENSIVE ONLY.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

import httpx

T = TypeVar("T")


@dataclass
class Decision:
    """Policy decision result."""

    action: str
    reason: str
    rule_id: Optional[str] = None
    matched_canaries: List[str] = field(default_factory=list)
    matched_secrets: List[str] = field(default_factory=list)


@dataclass
class EnforceResult:
    """Result of tool enforcement check."""

    allowed: bool
    pending_approval: bool = False
    approval_id: Optional[str] = None
    decision: Optional[Decision] = None
    error: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnforceResult":
        decision_data = data.get("decision", {})
        decision = Decision(
            action=decision_data.get("action", "unknown"),
            reason=decision_data.get("reason", ""),
            rule_id=decision_data.get("ruleId"),
            matched_canaries=decision_data.get("matchedCanaries", []),
            matched_secrets=decision_data.get("matchedSecrets", []),
        )
        return cls(
            allowed=data.get("allowed", False),
            pending_approval=data.get("pending_approval", False)
            or data.get("pendingApproval", False),
            approval_id=data.get("approval_id") or data.get("approvalId"),
            decision=decision,
            error=data.get("error"),
        )


@dataclass
class ScanHit:
    """Injection scan hit."""

    rule_id: str
    match: str
    severity: str


@dataclass
class ScanResult:
    """Result of injection scan."""

    blocked: bool
    hits: List[ScanHit]
    blocked_rules: List[str]
    policy_mode: str
    block_enabled: bool
    session_id: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        scan = data.get("scan", {})
        policy = data.get("policy", {})
        hits = [
            ScanHit(
                rule_id=h.get("ruleId", ""),
                match=h.get("match", ""),
                severity=h.get("severity", ""),
            )
            for h in scan.get("hits", [])
        ]
        return cls(
            blocked=data.get("blocked", False),
            hits=hits,
            blocked_rules=scan.get("blockedRules", []),
            policy_mode=policy.get("mode", ""),
            block_enabled=policy.get("blockEnabled", False),
            session_id=data.get("session_id", ""),
        )


@dataclass
class ChatMessage:
    """Chat message."""

    role: str
    content: Union[str, Any]
    name: Optional[str] = None
    tool_calls: Optional[List[Any]] = None
    tool_call_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            result["name"] = self.name
        if self.tool_calls:
            result["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id
        return result


@dataclass
class ChatCompletionChoice:
    """Chat completion choice."""

    index: int
    message: ChatMessage
    finish_reason: str


@dataclass
class ChatCompletionResult:
    """Result of chat completion."""

    id: str
    object: str
    created: int
    model: str
    choices: List[ChatCompletionChoice]
    usage: Optional[Dict[str, int]] = None
    phaseone: Optional[Dict[str, str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChatCompletionResult":
        choices = []
        for c in data.get("choices", []):
            msg = c.get("message", {})
            message = ChatMessage(
                role=msg.get("role", ""),
                content=msg.get("content", ""),
                name=msg.get("name"),
                tool_calls=msg.get("tool_calls"),
                tool_call_id=msg.get("tool_call_id"),
            )
            choices.append(
                ChatCompletionChoice(
                    index=c.get("index", 0),
                    message=message,
                    finish_reason=c.get("finish_reason", ""),
                )
            )
        return cls(
            id=data.get("id", ""),
            object=data.get("object", ""),
            created=data.get("created", 0),
            model=data.get("model", ""),
            choices=choices,
            usage=data.get("usage"),
            phaseone=data.get("phaseone"),
        )


class PhaseOneError(Exception):
    """PhaseOne API error."""

    def __init__(self, message: str, code: str = "UNKNOWN", status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status


class PhaseOneClient:
    """
    PhaseOne10841 client for agent security integration.

    Args:
        base_url: Gateway base URL (default: http://localhost:8080)
        agent_id: Agent identifier
        session_id: Session identifier (auto-generated if not provided)
        api_key: API key for upstream provider
        timeout: Request timeout in seconds (default: 30)
        headers: Additional default headers

    Example:
        >>> client = PhaseOneClient(agent_id="my-agent")
        >>> result = client.enforce(tool_name="http_request", arguments={"url": "https://api.example.com"})
        >>> if not result.allowed:
        ...     print(f"Tool blocked: {result.decision.reason}")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.base_url = (
            base_url
            or os.environ.get("PHASEONE_GATEWAY_URL", "http://localhost:8080")
        ).rstrip("/")
        self.agent_id = (
            agent_id or os.environ.get("PHASEONE_AGENT_ID") or "agent-default"
        )
        self.session_id = session_id or str(uuid.uuid4())
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or ""
        self.timeout = timeout
        self.extra_headers = headers or {}
        self._client = httpx.Client(timeout=timeout)

    def __enter__(self) -> "PhaseOneClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self._client.close()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def get_session_id(self) -> str:
        """Get current session ID."""
        return self.session_id

    def get_agent_id(self) -> str:
        """Get current agent ID."""
        return self.agent_id

    def set_agent_id(self, agent_id: str) -> None:
        """Set agent ID for subsequent requests."""
        self.agent_id = agent_id

    def new_session(self) -> str:
        """Create a new session and return the ID."""
        self.session_id = str(uuid.uuid4())
        return self.session_id

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-PhaseOne-Agent-Id": self.agent_id,
            "X-PhaseOne-Session-Id": self.session_id,
            **self.extra_headers,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(
        self, method: str, path: str, json: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        response = self._client.request(
            method, url, json=json, headers=self._headers()
        )
        data = response.json()

        if not response.is_success:
            error = data.get("error", {})
            raise PhaseOneError(
                error.get("message", f"Request failed: {response.status_code}"),
                error.get("code", "REQUEST_FAILED"),
                response.status_code,
            )

        return data

    def enforce(
        self,
        tool_name: str,
        arguments: Optional[Any] = None,
        wait_for_approval: bool = False,
        session_id: Optional[str] = None,
    ) -> EnforceResult:
        """
        Check if a tool call is allowed by policy.

        Args:
            tool_name: Name of the tool to check
            arguments: Tool arguments
            wait_for_approval: Wait for human approval if required
            session_id: Override session ID

        Returns:
            EnforceResult with allowed status and decision details

        Example:
            >>> result = client.enforce("run_shell", {"command": "ls -la"})
            >>> if result.allowed:
            ...     # Safe to execute
            ... elif result.pending_approval:
            ...     print(f"Waiting for approval: {result.approval_id}")
            ... else:
            ...     print(f"Denied: {result.decision.reason}")
        """
        data = self._request(
            "POST",
            "/v1/phaseone/tools/enforce",
            json={
                "agent_id": self.agent_id,
                "session_id": session_id or self.session_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "wait_for_approval": wait_for_approval,
            },
        )
        return EnforceResult.from_dict(data)

    def scan(
        self,
        text: str,
        source: str = "untrusted",
        channel: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan text for prompt injection.

        Args:
            text: Text to scan
            source: Source classification ('user', 'system', 'untrusted')
            channel: Channel identifier
            session_id: Override session ID

        Returns:
            ScanResult with blocked status and hit details

        Example:
            >>> result = client.scan(user_input, source="untrusted")
            >>> if result.blocked:
            ...     print(f"Injection detected: {result.blocked_rules}")
        """
        data = self._request(
            "POST",
            "/v1/phaseone/scan/injection",
            json={
                "agent_id": self.agent_id,
                "session_id": session_id or self.session_id,
                "text": text,
                "source": source,
                "channel": channel,
            },
        )
        return ScanResult.from_dict(data)

    def scan_untrusted(
        self, content: Any, channel: str = "untrusted"
    ) -> EnforceResult:
        """
        Scan untrusted content (tool results, RAG context, MCP payloads).

        Args:
            content: Content to scan
            channel: Channel identifier

        Returns:
            EnforceResult with allowed status
        """
        data = self._request(
            "POST",
            "/v1/phaseone/scan/untrusted",
            json={
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "content": content,
                "channel": channel,
            },
        )
        return EnforceResult.from_dict(data)

    def chat(
        self,
        messages: List[Union[Dict[str, Any], ChatMessage]],
        model: str = "gpt-4",
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> ChatCompletionResult:
        """
        Send a chat completion request through the PhaseOne gateway.

        Args:
            messages: List of chat messages
            model: Model name
            tool_calls: Pre-check tool calls before request
            **kwargs: Additional OpenAI-compatible parameters

        Returns:
            ChatCompletionResult

        Example:
            >>> result = client.chat([
            ...     {"role": "user", "content": "Hello!"}
            ... ])
            >>> print(result.choices[0].message.content)
        """
        # Pre-check tool calls if provided
        if tool_calls:
            for tool in tool_calls:
                result = self.enforce(
                    tool_name=tool["name"], arguments=tool.get("arguments")
                )
                if not result.allowed:
                    raise PhaseOneError(
                        f"Tool {tool['name']} blocked: {result.decision.reason if result.decision else 'unknown'}",
                        result.decision.rule_id if result.decision else "TOOL_BLOCKED",
                        403,
                    )

        # Convert ChatMessage objects to dicts
        msg_list = [
            m.to_dict() if isinstance(m, ChatMessage) else m for m in messages
        ]

        data = self._request(
            "POST",
            "/v1/chat/completions",
            json={
                "messages": msg_list,
                "model": model,
                "phaseone_tool_calls": tool_calls,
                **kwargs,
            },
        )
        return ChatCompletionResult.from_dict(data)

    def record_event(
        self,
        event_type: str,
        severity: str = "info",
        tool_name: Optional[str] = None,
        tool_args: Optional[Any] = None,
        destination: Optional[str] = None,
        result: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Record an event to the PhaseOne event store.

        Args:
            event_type: Type of event
            severity: Event severity ('info', 'low', 'medium', 'high', 'critical')
            tool_name: Tool name if applicable
            tool_args: Tool arguments
            destination: Target destination
            result: Result data
            metadata: Additional metadata
            session_id: Override session ID

        Returns:
            Dict with event ID
        """
        return self._request(
            "POST",
            "/v1/phaseone/events",
            json={
                "session_id": session_id or self.session_id,
                "agent_id": self.agent_id,
                "event_type": event_type,
                "severity": severity,
                "tool_name": tool_name,
                "tool_args": tool_args,
                "destination": destination,
                "result": result,
                "metadata": metadata,
            },
        )

    def health(self) -> Dict[str, Any]:
        """Get gateway health status."""
        return self._request("GET", "/health")

    def get_openai_config(self) -> Dict[str, Any]:
        """
        Get configuration for OpenAI SDK.

        Returns:
            Dict with base_url, api_key, and default_headers

        Example:
            >>> from openai import OpenAI
            >>> config = client.get_openai_config()
            >>> openai = OpenAI(
            ...     base_url=config["base_url"],
            ...     api_key=config["api_key"],
            ...     default_headers=config["default_headers"],
            ... )
        """
        return {
            "base_url": f"{self.base_url}/v1",
            "api_key": self.api_key or "phaseone-unused",
            "default_headers": {
                "X-PhaseOne-Agent-Id": self.agent_id,
                "X-PhaseOne-Session-Id": self.session_id,
                **self.extra_headers,
            },
        }


def create_client(
    base_url: Optional[str] = None,
    agent_id: Optional[str] = None,
    **kwargs: Any,
) -> PhaseOneClient:
    """
    Create a PhaseOne client with default configuration.

    Args:
        base_url: Gateway base URL
        agent_id: Agent identifier
        **kwargs: Additional configuration

    Returns:
        PhaseOneClient instance
    """
    return PhaseOneClient(base_url=base_url, agent_id=agent_id, **kwargs)


def with_enforcement(
    client: PhaseOneClient,
) -> Callable[[str, T, Callable[[T], Any]], Any]:
    """
    Create a wrapper that enforces policy before executing tools.

    Args:
        client: PhaseOne client

    Returns:
        Wrapper function

    Example:
        >>> safe_execute = with_enforcement(client)
        >>> result = safe_execute("http_request", {"url": "..."}, lambda args: fetch(args["url"]))
    """

    def wrapper(
        tool_name: str, args: T, execute: Callable[[T], Any]
    ) -> Any:
        result = client.enforce(tool_name=tool_name, arguments=args)
        if not result.allowed:
            raise PhaseOneError(
                f"Tool {tool_name} blocked: {result.decision.reason if result.decision else 'unknown'}",
                result.decision.rule_id if result.decision else "TOOL_BLOCKED",
                403,
            )
        return execute(args)

    return wrapper
