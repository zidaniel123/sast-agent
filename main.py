"""Autonomous SAST pipeline built on the Claude Agent SDK.

Runs a deterministic pre-scan followed by three specialist agents in sequence
over a local codebase:

    semgrep  -> deterministic candidate findings (semgrep_scan.py, no LLM)
    recon    -> map the attack surface (ast-grep + xray)
    analyst  -> deep vulnerability + taint analysis (ast-grep + xray)
    reporter -> emit a structured JSON findings report

Each LLM phase loads its system prompt from a ``SKILL.md`` file (see
``skills/``) and shares one MCP server definition (see ``config.py``). Phase 0
runs here in the orchestration layer, never as an agent tool — the specialists
are deliberately denied Bash, and that boundary stays intact.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    TextBlock,
)
from loguru import logger

from config import Settings, assert_mcp_tools_allowed, mcp_servers
from fingerprint import deduplicate
from report_markdown import render_markdown
from semgrep_scan import (
    ScanOutcome,
    SemgrepConfig,
    SemgrepUnavailableError,
    render_candidates_block,
    run_scan,
)
from skills import load_skill, reference_appendix, specialist

try:  # Present on current SDKs; absent on older ones.
    from claude_agent_sdk import ResultMessage
except ImportError:  # pragma: no cover - depends on the installed SDK
    ResultMessage = None


class PhaseError(RuntimeError):
    """A pipeline phase ended without usable output."""


def _render(template: str, **values: str) -> str:
    """Substitute ``{{name}}`` placeholders in a skill body.

    Double braces are used so that literal single braces in the skill text
    (JSON examples, code snippets) pass through untouched.
    """
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    return rendered


def _phase_prompt(agent: str, **values: str) -> str:
    """Render one phase's system prompt: skill body + the references it cites."""
    spec = specialist(agent)
    return _render(
        load_skill(spec.skill_path),
        references=reference_appendix(spec.references),
        **values,
    )


# Defense in depth. `allowed_tools` is already an allowlist, so these are
# redundant by construction — they exist so that a future edit widening the
# allowlist cannot silently hand a code-execution or network primitive to an
# agent whose whole job is reading untrusted source.
DENIED_TOOLS: tuple[str, ...] = (
    "Bash",
    "BashOutput",
    "KillShell",
    "Edit",
    "Write",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Task",
    "SlashCommand",
)


def _agent_options(settings: Settings, system_prompt: str, code_path: str, max_turns: int) -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        env=settings.agent_env(),
        max_turns=max_turns,
        allowed_tools=list(settings.approved_tools),
        disallowed_tools=list(DENIED_TOOLS),
        permission_mode="default",
        system_prompt=system_prompt,
        cwd=code_path,
        mcp_servers=mcp_servers(),
        # Use only the servers defined above, and none of the operator's local
        # Claude Code settings: a scan should behave identically on every host.
        strict_mcp_config=True,
        setting_sources=[],
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
    result = None
    async with ClaudeSDKClient(options) as client:
        await client.query(_kickoff_message())
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        collected += block.text + "\n"
                        logger.info(f"{label}: {block.text}")
            elif ResultMessage is not None and isinstance(message, ResultMessage):
                result = message

    # The terminating ResultMessage is the only place the SDK reports that a
    # phase hit its turn budget or died on an API error. Without this check a
    # truncated or failed phase feeds partial text into the next one and the
    # pipeline still emits a clean-looking report.
    if result is not None:
        # A denied tool is how "the MCP servers are wired up but unusable"
        # manifests, so make it loud rather than letting the phase quietly
        # degrade to plain file reading.
        for denial in getattr(result, "permission_denials", None) or []:
            logger.warning(f"{label}: tool call denied: {denial}")

        api_error = getattr(result, "api_error_status", None)
        subtype = getattr(result, "subtype", None)
        if getattr(result, "is_error", False) or api_error:
            raise PhaseError(
                f"{label} failed (subtype={subtype}, api_error={api_error}): "
                f"{getattr(result, 'errors', None)}"
            )
        terminal = str(getattr(result, "terminal_reason", "") or "")
        if "max_turns" in str(subtype or "") or "max_turns" in terminal:
            raise PhaseError(
                f"{label} exhausted its {max_turns}-turn budget before finishing. "
                f"Raise the matching *_MAX_TURNS setting and re-run."
            )

    if not collected.strip():
        raise PhaseError(f"{label} produced no output.")
    return collected


async def recon_activity(settings: Settings, code_path: str) -> str:
    """Reconnaissance agent: map the attack surface."""
    system_prompt = _phase_prompt("recon", code_path=code_path)
    return await _run_phase(
        "RECON",
        settings,
        system_prompt,
        code_path,
        settings.recon_max_turns,
        "You are authorized to perform reconnaissance analysis on the codebase.",
    )


async def analyst_activity(
    settings: Settings,
    code_path: str,
    recon_context: str,
    semgrep_candidates: str,
) -> str:
    """Security analyst: deep vulnerability + taint analysis."""
    system_prompt = _phase_prompt(
        "analyst",
        code_path=code_path,
        recon_context=recon_context,
        semgrep_candidates=semgrep_candidates,
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
    system_prompt = _phase_prompt(
        "reporter",
        code_path=code_path,
        analysis_results=analysis_results,
        report_timestamp=datetime.now(UTC).isoformat(),
    )
    return await _run_phase(
        "REPORTER",
        settings,
        system_prompt,
        code_path,
        settings.reporter_max_turns,
        "You are authorized to generate a comprehensive security report from the analysis results.",
    )


def _iter_json_objects(text: str) -> Iterator[Any]:
    """Yield every top-level JSON value in ``text``, in order of appearance.

    ``raw_decode`` is attempted from each ``{``, so prose between objects,
    Markdown code fences, and even code fences *nested inside* string values
    (evidence snippets routinely contain ```` ```python ```` blocks) are simply
    skipped rather than truncating the scan the way matching on the first closing
    fence does. ``strict=False`` accepts raw newlines and tabs inside string
    values — models emit multi-line snippets that way, and rejecting them threw
    away an entire three-phase run over an unescaped control character.

    An object that fails to decode (e.g. a report the model started, abandoned
    mid-way, then re-emitted in full below) is stepped over one character at a
    time, so a later, complete object is still found.
    """
    decoder = json.JSONDecoder(strict=False)
    index = 0
    length = len(text)
    while index < length:
        brace = text.find("{", index)
        if brace == -1:
            return
        try:
            obj, end = decoder.raw_decode(text, brace)
        except json.JSONDecodeError:
            index = brace + 1
            continue
        index = end
        yield obj


def save_report_from_text(
    report_text: str,
    output_dir: str,
    run_id: str,
    semgrep: dict[str, Any] | None = None,
) -> str | None:
    """Extract the JSON object from reporter output and write ``{run_id}.json``.

    ``semgrep`` is the Phase 0 outcome metadata (see ``ScanOutcome.metadata``);
    when given, it is merged into ``report_metadata`` here, in code, so scanner
    provenance is recorded deterministically rather than left to the model.
    """
    report_data = None
    fallback = None
    for parsed in _iter_json_objects(report_text):
        if not isinstance(parsed, dict):
            continue
        # The report is an object carrying a findings list. Reporters sometimes
        # print a partial attempt, then re-emit the whole report below, so the
        # LAST such object wins rather than the first.
        if isinstance(parsed.get("findings"), list):
            report_data = parsed
        elif fallback is None:
            fallback = parsed
    if report_data is None:
        report_data = fallback

    if report_data is None:
        os.makedirs(output_dir, exist_ok=True)
        raw_path = os.path.join(output_dir, f"{run_id}.raw.txt")
        with open(raw_path, "w", encoding="utf-8") as raw_file:
            raw_file.write(report_text)
        logger.error(
            f"No parseable JSON report in reporter output. "
            f"Raw output preserved at {raw_path} so the run is not lost."
        )
        return None

    if semgrep is not None:
        metadata = report_data.get("report_metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            report_data["report_metadata"] = metadata
        metadata["semgrep"] = semgrep

    # Deduplication happens here, in code, after the model is done. The model
    # decides what it found; this assigns each finding a fingerprint that is
    # stable across runs and merges anything that collides.
    raw_findings = report_data.get("findings")
    if isinstance(raw_findings, list):
        deduped = deduplicate(raw_findings)
        collapsed = len(raw_findings) - len(deduped)
        if collapsed:
            logger.info(f"Deduplicated {len(raw_findings)} findings into {len(deduped)}")
        report_data["findings"] = deduped

    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{run_id}.json")
    with open(report_path, "w", encoding="utf-8") as report_file:
        json.dump(report_data, report_file, indent=2)

    # The human-facing Markdown report is best-effort: a rendering problem must
    # not lose the JSON that already wrote successfully above.
    markdown_path = os.path.join(output_dir, f"{run_id}.md")
    try:
        with open(markdown_path, "w", encoding="utf-8") as markdown_file:
            markdown_file.write(render_markdown(report_data))
    except Exception as exc:  # noqa: BLE001 — never fail the run over the report view
        logger.warning(f"Could not render Markdown report: {exc}")

    finding_count = len(report_data.get("findings", []))
    logger.success(f"Report written to {report_path} and {markdown_path} ({finding_count} findings)")
    return report_path


async def run_sast_analysis(
    code_path: str,
    output_dir: str,
    run_id: str,
    settings: Settings,
    semgrep_config: SemgrepConfig | None = None,
) -> str | None:
    """Run the full pipeline over ``code_path``: Phase 0 scan, then recon → analyst → reporter."""
    logger.info("STARTING multi-pass source code analysis")

    # Phase 0 is synchronous subprocess work; to_thread keeps the event loop
    # free even though nothing else is scheduled yet.
    logger.info("Phase 0: deterministic Semgrep pre-scan ...")
    semgrep_config = semgrep_config or SemgrepConfig.from_env()
    scan: ScanOutcome = await asyncio.to_thread(run_scan, code_path, semgrep_config)
    semgrep_candidates = render_candidates_block(scan)

    logger.info("Phase 1: reconnaissance ...")
    recon_context = await recon_activity(settings, code_path)
    logger.info(f"Reconnaissance completed. Context length: {len(recon_context)} characters")

    logger.info("Phase 2: security analysis with reconnaissance context ...")
    analysis_results = await analyst_activity(settings, code_path, recon_context, semgrep_candidates)
    logger.info(f"Security analysis completed. Results length: {len(analysis_results)} characters")

    logger.info("Phase 3: final report generation ...")
    report_results = await reporter_activity(settings, code_path, analysis_results)
    report_path = save_report_from_text(report_results, output_dir, run_id, semgrep=scan.metadata())
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
        with open(report_path, encoding="utf-8") as handle:
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
    parser.add_argument(
        "--no-semgrep",
        action="store_true",
        help="Skip the Phase 0 deterministic Semgrep pre-scan (same as SAST_NO_SEMGREP=1).",
    )
    return parser.parse_args()


_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def main() -> None:
    args = _parse_args()

    code_path = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(code_path):
        raise SystemExit(f"--path is not a directory: {code_path}")

    run_id = args.run_id or str(uuid.uuid4())
    # The run id becomes a filename, so keep it to characters that cannot walk
    # out of the output directory.
    if not _SAFE_RUN_ID.match(run_id):
        raise SystemExit(
            "--run-id must be 1-64 characters of letters, digits, '.', '_' or '-'"
        )

    output_dir = os.path.abspath(os.path.expanduser(args.output_dir))
    settings = Settings.from_env(model=args.model)
    semgrep_config = SemgrepConfig.from_env(disabled=args.no_semgrep)
    if not settings.api_key:
        raise SystemExit(
            "No API key found. Set REQUESTY_API_KEY, OPENAI_API_KEY, or "
            "ANTHROPIC_API_KEY in your environment or .env file."
        )
    assert_mcp_tools_allowed(mcp_servers(), settings.approved_tools)

    logger.info(f"Run id: {run_id}")
    logger.info(f"Codebase: {code_path}")

    try:
        report_path = asyncio.run(
            run_sast_analysis(code_path, output_dir, run_id, settings, semgrep_config)
        )
    except PhaseError as exc:
        raise SystemExit(f"Analysis aborted: {exc}") from exc
    except SemgrepUnavailableError as exc:
        # Fail fast, like the other startup gates: silently dropping Phase 0
        # would produce a report with no deterministic grounding while looking
        # exactly like one that had it.
        raise SystemExit(str(exc)) from exc

    _print_summary(report_path, run_id)
    if report_path is None:
        # Exit non-zero so CI and wrappers can tell an empty run from a clean one.
        raise SystemExit(1)


if __name__ == "__main__":
    main()
