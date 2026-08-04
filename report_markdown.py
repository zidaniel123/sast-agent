"""Render the SAST JSON report as a human-facing Markdown document.

The JSON report is the machine artifact (diffable, dedup-keyed, ingestible). This
renders the same data as the report a reviewer actually reads: severity-sorted,
with an executive summary, and — per finding — reproduction steps, code evidence,
impact, and a concrete remediation with a corrected-code example and references.

Every field is treated as optional. The reporter is a language model; a missing
or oddly-typed key must degrade to a placeholder, never raise, because the
Markdown is written right after a run that already succeeded.
"""

from __future__ import annotations

from typing import Any

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_SEVERITY_LABELS = ("critical", "high", "medium", "low", "informational")


def _str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text or fallback


def _lang_from_path(path: str) -> str:
    """Map a file extension to a Markdown code-fence language hint."""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return {
        "py": "python", "js": "javascript", "ts": "typescript", "tsx": "tsx",
        "jsx": "jsx", "go": "go", "rb": "ruby", "java": "java", "php": "php",
        "rs": "rust", "c": "c", "h": "c", "cpp": "cpp", "cs": "csharp",
        "sql": "sql", "sh": "bash", "yaml": "yaml", "yml": "yaml", "json": "json",
    }.get(ext, "")


def _severity_rank(finding: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(_str(finding.get("severity")).lower(), 9)


def _fence(code: str, lang: str = "") -> list[str]:
    """A code fence that will not be broken by fences inside ``code``.

    Evidence snippets can themselves contain triple-backtick blocks, so the
    outer fence uses whatever backtick run is longer than any run inside.
    """
    longest = 0
    run = 0
    for char in code:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    ticks = "`" * max(3, longest + 1)
    return [f"{ticks}{lang}", code.rstrip("\n"), ticks]


def _finding_section(index: int, finding: dict[str, Any]) -> list[str]:
    severity = _str(finding.get("severity"), "unknown").lower()
    title = _str(finding.get("vulnerability"), "Untitled finding")
    fid = _str(finding.get("finding_id"))
    heading = f"### {index}. {title}"
    lines = [heading, ""]

    meta = [
        f"- **Severity:** {severity}",
        f"- **CWE:** {_str(finding.get('cwe_id'), 'n/a')}",
        f"- **Confidence:** {_str(finding.get('confidence'), 'n/a')}",
    ]
    taint = finding.get("taint_analysis")
    if isinstance(taint, dict):
        meta.append(f"- **Exploitability:** {_str(taint.get('exploitability'), 'n/a')}")
    if fid:
        meta.append(f"- **Finding ID:** `{fid}`")
    dupes = finding.get("duplicate_count")
    if isinstance(dupes, int) and dupes > 1:
        meta.append(f"- **Occurrences merged:** {dupes}")
    lines.extend(meta)
    lines.append("")

    description = _str(finding.get("description"))
    if description:
        lines.extend([description, ""])

    steps = finding.get("reproduction_steps")
    if isinstance(steps, list) and steps:
        lines.extend(["**Reproduction**", ""])
        lines.extend(f"{i}. {_str(step)}" for i, step in enumerate(steps, 1) if _str(step))
        lines.append("")

    evidences = finding.get("evidences")
    if isinstance(evidences, list) and evidences:
        lines.extend(["**Evidence**", ""])
        for ev in evidences:
            if not isinstance(ev, dict):
                continue
            code_file = _str(ev.get("code_file") or ev.get("path"))
            loc = code_file
            line_range = _str(ev.get("line_range"))
            if code_file and line_range:
                loc = f"{code_file}:{line_range}"
            if loc:
                lines.append(f"`{loc}`")
                lines.append("")
            snippet = _str(ev.get("snippet"))
            if snippet:
                lines.extend(_fence(snippet, _lang_from_path(code_file)))
                lines.append("")
            taint_flow = _str(ev.get("taint_flow"))
            if taint_flow:
                lines.extend([taint_flow, ""])

    if isinstance(taint, dict):
        impact = _str(taint.get("impact"))
        if impact:
            lines.extend([f"**Impact:** {impact}", ""])

    remediation = finding.get("remediation")
    if isinstance(remediation, dict):
        lines.extend(["**Remediation**", ""])
        summary = _str(remediation.get("summary"))
        if summary:
            lines.extend([summary, ""])
        fix = _str(remediation.get("fix"))
        if fix:
            lines.extend([fix, ""])
        example = _str(remediation.get("code_example"))
        if example:
            lines.extend(["Corrected example:", ""])
            lines.extend(_fence(example))
            lines.append("")
        refs = remediation.get("references")
        if isinstance(refs, list) and refs:
            lines.append("References:")
            lines.extend(f"- {_str(ref)}" for ref in refs if _str(ref))
            lines.append("")

    lines.extend(["---", ""])
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    """Render a parsed SAST report dict as a Markdown document."""
    meta = report.get("report_metadata") if isinstance(report.get("report_metadata"), dict) else {}
    findings = report.get("findings")
    findings = findings if isinstance(findings, list) else []
    findings = [f for f in findings if isinstance(f, dict)]
    findings.sort(key=_severity_rank)

    lines = ["# Static Analysis Security Report", ""]
    codebase = _str(meta.get("codebase_path"))
    timestamp = _str(meta.get("report_timestamp"))
    if codebase:
        lines.append(f"- **Codebase:** `{codebase}`")
    if timestamp:
        lines.append(f"- **Generated:** {timestamp}")
    lines.append(f"- **Total findings:** {len(findings)}")
    lines.append("")

    counts: dict[str, int] = {}
    for finding in findings:
        counts[_str(finding.get("severity"), "unknown").lower()] = (
            counts.get(_str(finding.get("severity"), "unknown").lower(), 0) + 1
        )

    lines.extend(["## Executive summary", ""])
    if findings:
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in _SEVERITY_LABELS:
            if counts.get(sev):
                lines.append(f"| {sev} | {counts[sev]} |")
        for sev, count in counts.items():
            if sev not in _SEVERITY_LABELS:
                lines.append(f"| {sev} | {count} |")
        lines.append("")
    else:
        lines.extend(["No findings were reported.", ""])

    lines.extend(["## Findings", ""])
    for index, finding in enumerate(findings, 1):
        lines.extend(_finding_section(index, finding))

    lines.extend([
        "> Automated analysis. Every finding must be validated by a human "
        "reviewer before it is acted on or filed.",
        "",
    ])
    return "\n".join(lines).rstrip() + "\n"
