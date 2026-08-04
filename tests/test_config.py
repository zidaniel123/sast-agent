"""Config resolution, gateway URL normalization, and the MCP allowlist guard.

These are pure functions: no network, no API key, no model. Everything here runs
in CI.
"""

from __future__ import annotations

import pytest

from config import (
    APPROVED_TOOLS,
    Settings,
    _claude_code_base_url,
    assert_mcp_tools_allowed,
    mcp_servers,
)

GATEWAY_ENV_VARS = (
    "REQUESTY_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_BASE",
    "BASE_URL",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL",
)


@pytest.fixture
def clean_env(monkeypatch):
    """Remove every gateway variable so tests do not read the developer's .env."""
    for name in GATEWAY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class TestBaseUrl:
    def test_defaults_to_requesty_router(self):
        assert _claude_code_base_url(None) == "https://router.requesty.ai"
        assert _claude_code_base_url("") == "https://router.requesty.ai"

    def test_strips_trailing_v1_because_the_sdk_appends_its_own_path(self):
        assert _claude_code_base_url("https://gw.example.com/v1") == "https://gw.example.com"

    def test_strips_trailing_slash_before_checking_v1(self):
        assert _claude_code_base_url("https://gw.example.com/v1/") == "https://gw.example.com"

    def test_leaves_a_url_without_v1_alone(self):
        assert _claude_code_base_url("https://gw.example.com") == "https://gw.example.com"

    def test_does_not_strip_v1_from_the_middle_of_a_path(self):
        assert _claude_code_base_url("https://gw.example.com/v1/proxy") == "https://gw.example.com/v1/proxy"


class TestSettingsFromEnv:
    def test_api_key_precedence_requesty_first(self, clean_env):
        clean_env.setenv("REQUESTY_API_KEY", "rqsty-aaa")
        clean_env.setenv("OPENAI_API_KEY", "sk-bbb")
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-ccc")
        assert Settings.from_env().api_key == "rqsty-aaa"

    def test_api_key_falls_through_to_anthropic(self, clean_env):
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-ccc")
        assert Settings.from_env().api_key == "sk-ant-ccc"

    def test_api_key_is_none_when_nothing_is_set(self, clean_env):
        assert Settings.from_env().api_key is None

    def test_model_override_beats_the_environment(self, clean_env):
        clean_env.setenv("ANTHROPIC_MODEL", "from-env")
        assert Settings.from_env(model="from-flag").model == "from-flag"

    def test_turn_budgets_are_read_as_integers(self, clean_env):
        clean_env.setenv("ANALYST_MAX_TURNS", "7")
        assert Settings.from_env().analyst_max_turns == 7


class TestAgentEnv:
    def test_requesty_key_is_sent_as_an_auth_token(self):
        env = Settings(api_key="rqsty-secret", base_url="https://gw", model="m").agent_env()
        assert env["ANTHROPIC_AUTH_TOKEN"] == "rqsty-secret"
        assert env["ANTHROPIC_API_KEY"] == ""

    def test_other_keys_are_sent_as_an_api_key(self):
        env = Settings(api_key="sk-plain", base_url="https://gw", model="m").agent_env()
        assert env["ANTHROPIC_API_KEY"] == "sk-plain"
        assert "ANTHROPIC_AUTH_TOKEN" not in env

    def test_no_key_means_no_credential_in_the_child_environment(self):
        env = Settings(api_key=None, base_url="https://gw", model="m").agent_env()
        assert "ANTHROPIC_AUTH_TOKEN" not in env
        assert "ANTHROPIC_API_KEY" not in env


class TestMcpAllowlistGuard:
    def test_the_shipped_configuration_is_consistent(self):
        # Regression guard: every server in mcp_servers() must be allow-listed,
        # or its tools are silently unusable at run time.
        assert_mcp_tools_allowed(mcp_servers(), APPROVED_TOOLS)

    def test_a_server_missing_from_the_allowlist_is_fatal(self):
        with pytest.raises(SystemExit, match="ast-grep"):
            assert_mcp_tools_allowed(mcp_servers(), ("Read", "Grep"))

    def test_execution_and_network_tools_are_not_granted(self):
        # The agent reads untrusted source code; these must never be auto-approved.
        for forbidden in ("Bash", "WebFetch", "WebSearch", "Task", "Write", "Edit"):
            assert forbidden not in APPROVED_TOOLS

    def test_mcp_git_refs_are_pinnable(self, monkeypatch):
        monkeypatch.setenv("AST_GREP_MCP_REF", "v1.2.3")
        args = mcp_servers()["ast-grep"]["args"]
        assert args[1].endswith("@v1.2.3")

    def test_mcp_git_refs_are_unpinned_by_default(self, monkeypatch):
        monkeypatch.delenv("AST_GREP_MCP_REF", raising=False)
        args = mcp_servers()["ast-grep"]["args"]
        assert "@" not in args[1].removeprefix("git+https://")
