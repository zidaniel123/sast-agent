"""Centralized configuration for the SAST agent.

All runtime settings live in the frozen ``Settings`` dataclass, and the MCP
server definitions (ast-grep + xray) are defined in exactly one place so every
phase shares the same wiring.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from loguru import logger

load_dotenv()


# --------------------------------------------------------------------------- #
# LLM gateway base-url normalization
# --------------------------------------------------------------------------- #
def _claude_code_base_url(base_url: str | None) -> str:
    """Normalize a gateway base URL to what Claude Code expects.

    A Requesty-compatible gateway is the default. A trailing ``/v1`` is stripped
    because the SDK appends its own path segments.
    """
    if not base_url:
        return "https://router.requesty.ai"
    normalized = base_url.rstrip("/")
    if normalized.endswith("/v1"):
        return normalized[:-3]
    return normalized


# --------------------------------------------------------------------------- #
# MCP servers (defined ONCE, shared by every phase)
# --------------------------------------------------------------------------- #
def mcp_servers() -> dict[str, dict]:
    """Return the ast-grep + xray MCP server definitions.

    Both servers run via ``uvx`` straight from git, so ``uv`` must be installed
    on the host. See ``references/ast-grep-and-xray.md`` for details.
    """
    return {
        "ast-grep": {
            "command": "uvx",
            "args": [
                "--from",
                "git+https://github.com/ast-grep/ast-grep-mcp",
                "ast-grep-server",
            ],
            "client_session_timeout_seconds": 300,
        },
        "xray": {
            "command": "uvx",
            "args": [
                "--from",
                "git+https://github.com/srijanshukla18/xray",
                "xray-mcp",
            ],
            "client_session_timeout_seconds": 300,
        },
    }


# Tools each specialist agent is permitted to use.
APPROVED_TOOLS: tuple[str, ...] = (
    "Read",
    "Grep",
    "Bash",
    "KillShell",
    "BashOutput",
    "Fetch",
    "WebSearch",
    "ExitPlanMode",
    "SlashCommand",
    "WebFetch",
    "Task",
    "Glob",
    "TodoWrite",
    "Skill",
)


@dataclass(frozen=True)
class Settings:
    """Immutable runtime configuration for the SAST pipeline."""

    api_key: str | None
    base_url: str
    # NOTE: the default model id is gateway-specific. Override it with the
    # ANTHROPIC_MODEL env var (or --model) to match whatever your LLM gateway
    # exposes. It is intentionally replaceable and carries no special meaning.
    model: str
    recon_max_turns: int = 50
    analyst_max_turns: int = 150
    reporter_max_turns: int = 50
    approved_tools: tuple[str, ...] = APPROVED_TOOLS

    @classmethod
    def from_env(cls, model: str | None = None) -> "Settings":
        """Build settings from the environment.

        Accepts ``REQUESTY_API_KEY``, ``OPENAI_API_KEY`` or ``ANTHROPIC_API_KEY``
        for the key, and any of the common base-url vars for the gateway.
        """
        api_key = (
            os.getenv("REQUESTY_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
        )
        base_url = _claude_code_base_url(
            os.getenv("OPENAI_API_BASE")
            or os.getenv("BASE_URL")
            or os.getenv("ANTHROPIC_BASE_URL")
        )
        resolved_model = model or os.getenv("ANTHROPIC_MODEL", "openai/gpt-5")
        return cls(
            api_key=api_key,
            base_url=base_url,
            model=resolved_model,
            recon_max_turns=int(os.getenv("RECON_MAX_TURNS", "50")),
            analyst_max_turns=int(os.getenv("ANALYST_MAX_TURNS", "150")),
            reporter_max_turns=int(os.getenv("REPORTER_MAX_TURNS", "50")),
        )

    def agent_env(self) -> dict[str, str]:
        """Map settings onto the env vars the Claude Agent SDK reads.

        Preserves the Requesty integration behavior: a ``rqsty-`` key is passed
        as an auth token; any other key is passed as ``ANTHROPIC_API_KEY``.
        """
        env: dict[str, str] = {
            "CLAUDE_CODE_USE_BEDROCK": "0",
            "ANTHROPIC_BASE_URL": self.base_url,
            "ANTHROPIC_MODEL": self.model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": self.model,
        }

        if self.api_key and self.api_key.startswith("rqsty-"):
            env["ANTHROPIC_AUTH_TOKEN"] = self.api_key
            env["ANTHROPIC_API_KEY"] = ""
            logger.info("Configured Requesty via ANTHROPIC_AUTH_TOKEN")
        elif self.api_key:
            env["ANTHROPIC_API_KEY"] = self.api_key
            logger.info("Configured custom ANTHROPIC_API_KEY")

        logger.info(f"Gateway base URL: {self.base_url}, model: {self.model}")
        return env
