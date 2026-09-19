"""
phaseone-client SDK tests
DEFENSIVE ONLY.
"""

import pytest
from unittest.mock import Mock, patch

from phaseone_client import (
    PhaseOneClient,
    PhaseOneError,
    create_client,
    with_enforcement,
    EnforceResult,
    ScanResult,
)


class TestPhaseOneClient:
    """Tests for PhaseOneClient."""

    def test_constructor_defaults(self):
        """Test client creation with defaults."""
        client = PhaseOneClient()
        assert client.get_agent_id() == "agent-default"
        assert client.get_session_id() is not None

    def test_constructor_custom_config(self):
        """Test client creation with custom config."""
        client = PhaseOneClient(
            base_url="http://gateway.example.com",
            agent_id="my-agent",
            session_id="my-session",
        )
        assert client.get_agent_id() == "my-agent"
        assert client.get_session_id() == "my-session"

    def test_strips_trailing_slash(self):
        """Test that trailing slash is stripped from base URL."""
        client = PhaseOneClient(base_url="http://localhost:8080/")
        config = client.get_openai_config()
        assert config["base_url"] == "http://localhost:8080/v1"

    def test_new_session(self):
        """Test session ID generation."""
        client = PhaseOneClient()
        old_session = client.get_session_id()
        new_session = client.new_session()
        assert new_session != old_session
        assert client.get_session_id() == new_session

    def test_set_agent_id(self):
        """Test setting agent ID."""
        client = PhaseOneClient()
        client.set_agent_id("new-agent")
        assert client.get_agent_id() == "new-agent"

    def test_context_manager(self):
        """Test client as context manager."""
        with PhaseOneClient() as client:
            assert client.get_agent_id() == "agent-default"

    def test_get_openai_config(self):
        """Test OpenAI config generation."""
        client = PhaseOneClient(
            base_url="http://gateway.example.com",
            agent_id="my-agent",
            api_key="sk-test",
        )
        config = client.get_openai_config()
        assert config["base_url"] == "http://gateway.example.com/v1"
        assert config["api_key"] == "sk-test"
        assert config["default_headers"]["X-PhaseOne-Agent-Id"] == "my-agent"

    def test_get_openai_config_default_api_key(self, monkeypatch):
        """Test default API key in OpenAI config."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        client = PhaseOneClient()
        config = client.get_openai_config()
        assert config["api_key"] == "phaseone-unused"


class TestEnforceResult:
    """Tests for EnforceResult."""

    def test_from_dict_allowed(self):
        """Test parsing allowed result."""
        data = {
            "allowed": True,
            "decision": {"action": "allow", "reason": "passed"},
        }
        result = EnforceResult.from_dict(data)
        assert result.allowed is True
        assert result.decision.action == "allow"

    def test_from_dict_denied(self):
        """Test parsing denied result."""
        data = {
            "allowed": False,
            "decision": {
                "action": "deny",
                "reason": "not allowed",
                "ruleId": "test.rule",
                "matchedCanaries": ["canary1"],
                "matchedSecrets": ["aws_key"],
            },
        }
        result = EnforceResult.from_dict(data)
        assert result.allowed is False
        assert result.decision.rule_id == "test.rule"
        assert result.decision.matched_canaries == ["canary1"]
        assert result.decision.matched_secrets == ["aws_key"]

    def test_from_dict_pending_approval(self):
        """Test parsing pending approval result."""
        data = {
            "allowed": False,
            "pending_approval": True,
            "approval_id": "approval-123",
            "decision": {"action": "require_approval", "reason": "destructive"},
        }
        result = EnforceResult.from_dict(data)
        assert result.pending_approval is True
        assert result.approval_id == "approval-123"


class TestScanResult:
    """Tests for ScanResult."""

    def test_from_dict_clean(self):
        """Test parsing clean scan result."""
        data = {
            "blocked": False,
            "scan": {"hits": [], "blockedRules": []},
            "policy": {"mode": "detect", "blockEnabled": False},
            "session_id": "session-123",
        }
        result = ScanResult.from_dict(data)
        assert result.blocked is False
        assert result.hits == []

    def test_from_dict_blocked(self):
        """Test parsing blocked scan result."""
        data = {
            "blocked": True,
            "scan": {
                "hits": [
                    {"ruleId": "injection.system", "match": "ignore", "severity": "high"}
                ],
                "blockedRules": ["injection.system"],
            },
            "policy": {"mode": "block", "blockEnabled": True},
            "session_id": "session-123",
        }
        result = ScanResult.from_dict(data)
        assert result.blocked is True
        assert len(result.hits) == 1
        assert result.hits[0].rule_id == "injection.system"
        assert result.blocked_rules == ["injection.system"]


class TestCreateClient:
    """Tests for create_client helper."""

    def test_creates_client(self):
        """Test helper creates client."""
        client = create_client(agent_id="test")
        assert isinstance(client, PhaseOneClient)
        assert client.get_agent_id() == "test"


class TestWithEnforcement:
    """Tests for with_enforcement helper."""

    def test_executes_when_allowed(self):
        """Test execution when allowed."""
        mock_client = Mock(spec=PhaseOneClient)
        mock_client.enforce.return_value = EnforceResult(
            allowed=True,
            decision=Mock(action="allow", reason="ok", rule_id=None),
        )

        safe_execute = with_enforcement(mock_client)
        result = safe_execute("read_file", {"path": "/test.txt"}, lambda args: "contents")

        assert result == "contents"
        mock_client.enforce.assert_called_once_with(
            tool_name="read_file", arguments={"path": "/test.txt"}
        )

    def test_raises_when_denied(self):
        """Test raises when denied."""
        mock_client = Mock(spec=PhaseOneClient)
        mock_client.enforce.return_value = EnforceResult(
            allowed=False,
            decision=Mock(action="deny", reason="not allowed", rule_id="test.deny"),
        )

        safe_execute = with_enforcement(mock_client)
        
        with pytest.raises(PhaseOneError) as exc_info:
            safe_execute("dangerous_tool", {}, lambda args: "should not run")
        
        assert "blocked" in str(exc_info.value)


class TestPhaseOneError:
    """Tests for PhaseOneError."""

    def test_error_attributes(self):
        """Test error has correct attributes."""
        error = PhaseOneError("Test error", "TEST_CODE", 403)
        assert str(error) == "Test error"
        assert error.code == "TEST_CODE"
        assert error.status == 403

    def test_error_defaults(self):
        """Test error default values."""
        error = PhaseOneError("Test error")
        assert error.code == "UNKNOWN"
        assert error.status == 0
