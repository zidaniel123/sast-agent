"""Autonomous SAST pipeline built on the Claude Agent SDK.

Runs three specialist agents in sequence over a local codebase:

    recon    -> map the attack surface (ast-grep + xray)
    analyst  -> deep vulnerability + taint analysis (ast-grep + xray)
    reporter -> emit a structured JSON findings report

Each phase loads its system prompt from a ``SKILL.md`` file (see ``skills/``)
and shares one MCP server definition (see ``config.py``).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import uuid
from datetime import datetime, timezone

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    TextBlock,
)
from loguru import logger

from config import Settings, mcp_servers
from skills import load_skill


def _render(template: str, **values: str) -> str:
    """Substitute ``{{name}}`` placeholders in a skill body.

    Double braces are used so that literal single braces in the skill text
    (JSON examples, code snippets) pass through untouched.
    """
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    return rendered


def _agent_options(settings: Settings, system_prompt: str, code_path: str, max_turns: int) -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        env=settings.agent_env(),
        max_turns=max_turns,
        allowed_tools=list(settings.approved_tools),
        permission_mode="default",
        system_prompt=system_prompt,
        cwd=code_path,
        mcp_servers=mcp_servers(),
    )


async def _run_phase(
    label: str,
    settings: Settings,
    system_prompt: str,
    code_path: str,
    max_turns: int,
    kickoff: str,
) -> str:
    """Run one specialist agent and collect its text output."""

    async def _kickoff_message():
        yield {
            "type": "user",
            "message": {"role": "user", "content": kickoff},
        }

    options = _agent_options(settings, system_prompt, code_path, max_turns)

    collected = ""
    async with ClaudeSDKClient(options) as client:
        await client.query(_kickoff_message())
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        collected += block.text + "\n"
                        logger.info(f"{label}: {block.text}")
    return collected


async def recon_activity(settings: Settings, code_path: str) -> str:
    """Reconnaissance agent: map the attack surface."""
    system_prompt = _render(load_skill("recon/SKILL.md"), code_path=code_path)
    return await _run_phase(
        "RECON",
        settings,
        system_prompt,
        code_path,
        settings.recon_max_turns,
        "You are authorized to perform reconnaissance analysis on the codebase.",
    )


async def analyst_activity(settings: Settings, code_path: str, recon_context: str) -> str:
    """Security analyst: deep vulnerability + taint analysis."""
    system_prompt = _render(
        load_skill("analyst/SKILL.md"),
        code_path=code_path,
        recon_context=recon_context,
    )
    return await _run_phase(
        "ANALYST",
        settings,
        system_prompt,
        code_path,
        settings.analyst_max_turns,
        "You are authorized to perform a security code analysis on the codebase and generate analysis results.",
    )


async def reporter_activity(settings: Settings, code_path: str, analysis_results: str) -> str:
    """Reporter: emit the structured JSON findings report."""
    system_prompt = _render(
        load_skill("reporter/SKILL.md"),
        code_path=code_path,
        analysis_results=analysis_results,
        report_timestamp=datetime.now(timezone.utc).isoformat(),
    )
    return await _run_phase(
        "REPORTER",
        settings,
        system_prompt,
        code_path,
        settings.reporter_max_turns,
        "You are authorized to generate a comprehensive security report from the analysis results.",
    )


def save_report_from_text(report_text: str, output_dir: str, run_id: str) -> str | None:
    """Extract the JSON object from reporter output and write ``{run_id}.json``."""
    start = report_text.find("{")
    end = report_text.rfind("}")
    if start == -1 or end == -1 or end < start:
        logger.warning("No JSON report found in reporter output")
        return None

    try:
        report_data = json.loads(report_text[start : end + 1])
    except json.JSONDecodeError as exc:
        logger.error(f"Failed to parse report JSON: {exc}")
        return None

    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{run_id}.json")
    with open(report_path, "w", encoding="utf-8") as report_file:
        json.dump(report_data, report_file, indent=2)

    finding_count = len(report_data.get("findings", []))
    logger.success(f"Report written to {report_path} ({finding_count} findings)")
    return report_path


async def run_sast_analysis(
    code_path: str,
    output_dir: str,
    run_id: str,
    settings: Settings,
) -> str | None:
    """Run the full three-phase SAST pipeline over ``code_path``."""
    logger.info("STARTING multi-pass source code analysis")

    logger.info("Phase 1: reconnaissance ...")
    recon_context = await recon_activity(settings, code_path)
    logger.info(f"Reconnaissance completed. Context length: {len(recon_context)} characters")

    logger.info("Phase 2: security analysis with reconnaissance context ...")
    analysis_results = await analyst_activity(settings, code_path, recon_context)
    logger.info(f"Security analysis completed. Results length: {len(analysis_results)} characters")

    logger.info("Phase 3: final report generation ...")
    report_results = await reporter_activity(settings, code_path, analysis_results)
    report_path = save_report_from_text(report_results, output_dir, run_id)
    logger.info("Final reporting completed")
    return report_path


def _print_summary(report_path: str | None, run_id: str) -> None:
    print()
    print("=" * 60)
    print(f"  SAST run {run_id}")
    if not report_path:
        print("  No report was produced. Check the logs above.")
        print("=" * 60)
        return

    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError):
        print(f"  Report saved to: {report_path}")
        print("=" * 60)
        return

    findings = report.get("findings", [])
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "unknown")).lower()
        counts[severity] = counts.get(severity, 0) + 1

    print(f"  Report: {report_path}")
    print(f"  Findings: {len(findings)}")
    for severity in ("critical", "high", "medium", "low", "informational"):
        if severity in counts:
            print(f"    - {severity}: {counts[severity]}")
    print("=" * 60)
    print("  Reminder: agent output must be validated by a human reviewer.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an autonomous SAST analysis over a local codebase.",
    )
    parser.add_argument("--path", required=True, help="Path to the codebase directory to analyze.")
    parser.add_argument("--output-dir", default="outputs", help="Directory for the JSON report (default: outputs/).")
    parser.add_argument("--model", default=None, help="Override the LLM model id (gateway-specific).")
    parser.add_argument("--run-id", default=None, help="Optional run id (defaults to a random UUID).")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    code_path = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(code_path):
        raise SystemExit(f"--path is not a directory: {code_path}")

    output_dir = os.path.abspath(os.path.expanduser(args.output_dir))
    run_id = args.run_id or str(uuid.uuid4())
    settings = Settings.from_env(model=args.model)

    logger.info(f"Run id: {run_id}")
    logger.info(f"Codebase: {code_path}")

    report_path = asyncio.run(run_sast_analysis(code_path, output_dir, run_id, settings))
    _print_summary(report_path, run_id)


if __name__ == "__main__":
    main()
