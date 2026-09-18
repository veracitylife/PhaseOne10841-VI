"""
PhaseOne10841 Python Client SDK

Defensive Agent Security Gateway client library for LLM agents and AI applications.

Veracity Integrity LLC · https://VeracityIntegrity.com
DEFENSIVE ONLY — no exploit tooling.

Example:
    >>> from phaseone_client import PhaseOneClient
    >>> client = PhaseOneClient(agent_id="my-agent")
    >>> result = client.enforce(tool_name="http_request", arguments={"url": "https://api.example.com"})
    >>> if not result.allowed:
    ...     print(f"Tool blocked: {result.decision['reason']}")
"""

from .client import (
    PhaseOneClient,
    PhaseOneError,
    EnforceResult,
    ScanResult,
    ChatCompletionResult,
    create_client,
    with_enforcement,
)

__version__ = "0.8.0-pre"
__author__ = "Veracity Integrity LLC"
__license__ = "MIT"

__all__ = [
    "PhaseOneClient",
    "PhaseOneError",
    "EnforceResult",
    "ScanResult",
    "ChatCompletionResult",
    "create_client",
    "with_enforcement",
]
