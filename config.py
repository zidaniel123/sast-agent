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
def _pinned(repo_url: str, ref_env_var: str) -> str:
    """Return ``git+<url>`` with an optional ``@<ref>`` pin from the environment.

    Both MCP servers are fetched and executed on the host by ``uvx``. Unpinned,
    that means running whatever is on the default branch at the moment of the
    run. Set the matching env var to a tag or commit SHA to freeze it — the same
    argument as committing a lockfile, applied to the tool servers.
    """
    ref = os.getenv(ref_env_var, "").strip()
    return f"git+{repo_url}@{ref}" if ref else f"git+{repo_url}"


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
                _pinned("https://github.com/ast-grep/ast-grep-mcp", "AST_GREP_MCP_REF"),
                "ast-grep-server",
            ],
        },
        "xray": {
            "command": "uvx",
            "args": [
                "--from",
                _pinned("https://github.com/srijanshukla18/xray", "XRAY_MCP_REF"),
                "xray-mcp",
            ],
        },
    }


def assert_mcp_tools_allowed(
    servers: dict[str, dict],
    approved: tuple[str, ...],
) -> None:
    """Fail fast if a configured MCP server has no matching allowlist entry.

    The SDK auto-approves only the tool names in ``allowed_tools``, and MCP tools
    are namespaced ``mcp__<server>__<tool>``. A server that is wired up but not
    allow-listed starts fine and then fails on every call, so the analysis
    silently degrades to plain file reading. This turns that into a startup error.
    """
    missing = [name for name in servers if f"mcp__{name}" not in approved]
    if missing:
        raise SystemExit(
            "MCP servers configured but not in APPROVED_TOOLS: "
            + ", ".join(sorted(missing))
            + ". Add the matching 'mcp__<server>' entries to config.APPROVED_TOOLS."
        )


# Tools each specialist agent is permitted to use.
#
# This list is the trust boundary. The agent reads untrusted source code, so a
# prompt-injection payload in a scanned file is reaching a tool-using model —
# everything granted here is something an attacker-controlled comment can try to
# invoke. Read-only local inspection plus the two analysis servers is enough to
# do static analysis; Bash, WebFetch, and WebSearch are deliberately absent so a
# scan cannot execute code or reach the network.
#
# MCP tools are addressed as ``mcp__<server>__<tool>``. Listing the bare
# ``mcp__<server>`` prefix auto-approves every tool that server exposes.
APPROVED_TOOLS: tuple[str, ...] = (
    "Read",
    "Grep",
    "Glob",
    "TodoWrite",
    "mcp__ast-grep",
    "mcp__xray",
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
    def from_env(cls, model: str | None = None) -> Settings:
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
