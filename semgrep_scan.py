"""Deterministic Semgrep pre-scan (Phase 0) for the SAST pipeline.

Before any LLM phase runs, this module runs Semgrep over the target codebase
and turns the JSON output into a compact list of candidate findings. Those
candidates are injected into the analyst phase's prompt, which changes the
analyst's job from free-floating hunting to prove-or-refute against
deterministic leads — plus hunting for the classes a pattern matcher cannot
see (business logic, authz, multi-file flows).

The scanner runs here, in the Python orchestration layer, and never as an
agent tool: the specialist agents are deliberately denied Bash, and that trust
boundary (see ``config.py``) stays intact. Semgrep itself never executes the
scanned code — it is a pattern matcher, so running it over untrusted source is
safe. Note that ``--config auto`` (the default) downloads rules from the
Semgrep registry, so Phase 0 needs network access unless ``SEMGREP_CONFIG``
points at a local ruleset.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from loguru import logger

DEFAULT_CONFIG = "auto"
DEFAULT_IMAGE = "semgrep/semgrep:latest"
DEFAULT_TIMEOUT = 600

# A large repo under a broad ruleset can produce far more hits than an LLM
# context can hold. Candidates are leads, not findings, so truncating to the
# highest-severity few hundred loses triage breadth, not correctness — and the
# truncation is stated explicitly in the block the analyst sees.
MAX_CANDIDATES = 200

_CWE_TOKEN = re.compile(r"CWE-\d+", re.IGNORECASE)
_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}


class SemgrepUnavailableError(RuntimeError):
    """Phase 0 was requested but nothing on this host can run Semgrep."""


def _env_flag(name: str) -> bool:
    """Parse a boolean env var: 1/true/yes/on (case-insensitive) are true."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SemgrepConfig:
    """How Phase 0 invokes Semgrep. Populated from the environment + CLI."""

    disabled: bool
    config: str = DEFAULT_CONFIG
    timeout: int = DEFAULT_TIMEOUT
    image: str = DEFAULT_IMAGE

    @classmethod
    def from_env(cls, disabled: bool = False) -> SemgrepConfig:
        return cls(
            disabled=disabled or _env_flag("SAST_NO_SEMGREP"),
            config=os.getenv("SEMGREP_CONFIG", "").strip() or DEFAULT_CONFIG,
            timeout=int(os.getenv("SEMGREP_TIMEOUT", "") or DEFAULT_TIMEOUT),
            image=os.getenv("SEMGREP_IMAGE", "").strip() or DEFAULT_IMAGE,
        )


@dataclass(frozen=True)
class Candidate:
    """One Semgrep hit, reduced to what the analyst needs to prove-or-refute.

    ``severity`` is Semgrep's own label (error/warning/info), kept verbatim —
    it is the rule author's opinion, not the finding's severity. The analyst
    re-judges severity from reachability and impact per the severity rubric.
    """

    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    snippet: str
    cwe: str = ""

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
        }
        if self.cwe:
            result["cwe"] = self.cwe
        return result


@dataclass(frozen=True)
class ScanOutcome:
    """What Phase 0 produced.

    ``status`` is one of:

    - ``"ok"``       — Semgrep ran and reported at least one hit.
    - ``"empty"``    — Semgrep ran and reported zero hits.
    - ``"disabled"`` — the operator opted out (--no-semgrep / SAST_NO_SEMGREP).
    - ``"failed"``   — Semgrep ran but crashed, timed out, or returned garbage.

    A missing scanner binary is NOT a status: that raises
    ``SemgrepUnavailableError`` and aborts the run, because silently degrading
    to ungrounded analysis is exactly the failure mode Phase 0 exists to fix.
    A scan that starts and then fails degrades to ``"failed"`` with a loud
    warning instead, so a Semgrep crash on one odd file cannot destroy an
    otherwise-good (and expensive) three-phase LLM run — but the analyst is
    told explicitly that it has no deterministic leads.
    """

    status: str
    candidates: tuple[Candidate, ...] = ()
    version: str = ""
    config: str = DEFAULT_CONFIG
    detail: str = ""
    truncated: bool = False

    @property
    def rules_triggered(self) -> int:
        """Distinct rules that produced at least one candidate.

        Semgrep's JSON output does not report how many rules were evaluated,
        only the rules that fired — so this is a lower bound, labeled as such.
        """
        return len({c.rule_id for c in self.candidates})

    def metadata(self) -> dict[str, Any]:
        """The deterministic record of Phase 0, for ``report_metadata``.

        Written by this code, not by the model: the scanner provenance of a
        report must not depend on the reporter remembering to include it.
        """
        return {
            "status": self.status,
            "version": self.version or None,
            "config": self.config,
            "candidate_count": len(self.candidates),
            "rules_triggered": self.rules_triggered,
            "truncated": self.truncated,
            "detail": self.detail or None,
        }


def resolve_command(config: SemgrepConfig) -> list[str] | None:
    """Pick the Semgrep invocation prefix: local binary, else Docker, else None.

    Priority order is deliberate: a locally installed ``semgrep`` is faster and
    does not require a running Docker daemon; the Docker fallback exists so a
    host without a Python toolchain for Semgrep can still run Phase 0.
    """
    semgrep = shutil.which("semgrep")
    if semgrep:
        return [semgrep]
    docker = shutil.which("docker")
    if docker:
        return [docker, "run", "--rm"]
    return None


def _build_argv(
    prefix: list[str], config: SemgrepConfig, code_path: str
) -> tuple[list[str], str | None, str]:
    """Build the full argv plus the working directory and reported-path prefix.

    Local mode runs with ``cwd=code_path`` and target ``.`` so Semgrep reports
    relative paths. Docker mode mounts the codebase at ``/src`` **read-only**
    (the scanned code is untrusted; the container has no business modifying
    it) and reports paths under ``/src/``, which the caller strips.

    ``--metrics=off`` stops the CLI from phoning scan metadata home to
    semgrep.dev — the default ``auto`` config talks to the registry to fetch
    rules, which is enough network exposure for a security scan of code that
    may be private.
    """
    if prefix[0].endswith("semgrep"):
        argv = prefix + [
            "scan", "--json", "--metrics=off", "--config", config.config, ".",
        ]
        return argv, code_path, ""
    argv = prefix + [
        "-v", f"{code_path}:/src:ro",
        config.image,
        "scan", "--json", "--metrics=off", "--config", config.config, "/src",
    ]
    return argv, None, "/src/"


def _extract_cwe(metadata: Any) -> str:
    """Pull the first ``CWE-<digits>`` token out of Semgrep rule metadata, if any.

    ``metadata.cwe`` is a list of strings in current rulesets but a bare string
    in older ones; both shapes have been seen in the wild.
    """
    if not isinstance(metadata, dict):
        return ""
    raw = metadata.get("cwe")
    values = raw if isinstance(raw, list) else [raw]
    for value in values:
        match = _CWE_TOKEN.search(str(value or ""))
        if match:
            return match.group(0).upper()
    return ""


def parse_results(payload: dict[str, Any], path_prefix: str = "") -> list[Candidate]:
    """Turn Semgrep's ``--json`` output into sorted, de-prefixed candidates.

    Sorted by severity (error > warning > info), then path, then line, so the
    truncation cap keeps the most serious leads and output is stable across
    runs.
    """
    candidates: list[Candidate] = []
    for result in payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") or {}
        path = str(result.get("path") or "")
        if path_prefix and path.startswith(path_prefix):
            path = path[len(path_prefix):]
        path = path.removeprefix("./")
        start = result.get("start") or {}
        candidates.append(
            Candidate(
                rule_id=str(result.get("check_id") or ""),
                severity=str(extra.get("severity") or "").lower(),
                path=path,
                line=int(start.get("line") or 0),
                message=str(extra.get("message") or "").strip(),
                snippet=str(extra.get("lines") or "").strip(),
                cwe=_extract_cwe(extra.get("metadata")),
            )
        )
    candidates.sort(
        key=lambda c: (_SEVERITY_RANK.get(c.severity, 3), c.path, c.line, c.rule_id)
    )
    return candidates


def run_scan(code_path: str, config: SemgrepConfig) -> ScanOutcome:
    """Execute Phase 0 and return the outcome. Never returns ``None``."""
    if config.disabled:
        logger.warning(
            "Phase 0 DISABLED by operator (--no-semgrep / SAST_NO_SEMGREP): "
            "findings will have no deterministic scanner grounding."
        )
        return ScanOutcome(status="disabled", config=config.config,
                           detail="disabled by operator")

    prefix = resolve_command(config)
    if prefix is None:
        raise SemgrepUnavailableError(
            "Phase 0 requires Semgrep, but neither a `semgrep` binary nor "
            "`docker` was found on PATH.\n"
            "Install one of:\n"
            "  - brew install semgrep        (or: pipx install semgrep)\n"
            "  - Docker                      (Phase 0 falls back to "
            f"{config.image})\n"
            "Or opt out explicitly with --no-semgrep or SAST_NO_SEMGREP=1."
        )

    argv, cwd, path_prefix = _build_argv(prefix, config, code_path)
    logger.info(f"Phase 0: running Semgrep ({' '.join(argv)})")
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=config.timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"Semgrep timed out after {config.timeout}s; continuing without scanner leads")
        return ScanOutcome(status="failed", config=config.config,
                           detail=f"timed out after {config.timeout}s")
    except OSError as exc:
        logger.warning(f"Could not launch Semgrep: {exc}; continuing without scanner leads")
        return ScanOutcome(status="failed", config=config.config, detail=str(exc))

    if completed.returncode != 0:
        tail = (completed.stderr or "").strip()[-500:]
        logger.warning(f"Semgrep exited {completed.returncode}: {tail}; continuing without scanner leads")
        return ScanOutcome(status="failed", config=config.config,
                           detail=f"exit {completed.returncode}: {tail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        logger.warning("Semgrep output was not parseable JSON; continuing without scanner leads")
        return ScanOutcome(status="failed", config=config.config,
                           detail="unparseable JSON on stdout")

    candidates = parse_results(payload, path_prefix)
    truncated = len(candidates) > MAX_CANDIDATES
    if truncated:
        candidates = candidates[:MAX_CANDIDATES]
    version = str(payload.get("version") or "")
    status = "ok" if candidates else "empty"
    logger.info(
        f"Phase 0: Semgrep {version or '(version unknown)'} reported "
        f"{len(candidates)} candidate(s)"
        + (f" (truncated to {MAX_CANDIDATES})" if truncated else "")
    )
    return ScanOutcome(
        status=status,
        candidates=tuple(candidates),
        version=version,
        config=config.config,
        truncated=truncated,
    )


def render_candidates_block(outcome: ScanOutcome) -> str:
    """Render the Phase 0 outcome as the ``{{semgrep_candidates}}`` prompt block.

    Whatever happened in Phase 0, the analyst must be told *in words* — a blank
    or missing block reads as "no leads" whether Semgrep found nothing or never
    ran, and those mean very different things for how hard it must hunt.
    """
    if outcome.status == "disabled":
        return (
            "The deterministic pre-scan was DISABLED by the operator "
            "(--no-semgrep / SAST_NO_SEMGREP). You have no deterministic "
            "scanner leads: hunt from the recon context alone."
        )
    if outcome.status == "failed":
        return (
            f"The deterministic pre-scan was attempted but FAILED ({outcome.detail}). "
            "You have no deterministic scanner leads: hunt from the recon "
            "context alone, and do not assume the codebase was ever scanned."
        )
    if outcome.status == "empty":
        return (
            f"Semgrep {outcome.version or '(version unknown)'} (config "
            f"{outcome.config!r}) ran over the entire codebase and reported "
            "ZERO findings. Absence of scanner hits is not evidence of safety: "
            "pattern matchers do not see business-logic flaws, broken "
            "authorization, or multi-file data flows. Hunt as if you had no "
            "leads."
        )

    listing = json.dumps(
        [c.as_dict() for c in outcome.candidates], indent=1, ensure_ascii=False
    )
    truncation = (
        f"\n\nThis list was TRUNCATED to the first {MAX_CANDIDATES} "
        "candidates by severity; there are more hits on disk than shown here."
        if outcome.truncated
        else ""
    )
    return (
        f"Semgrep {outcome.version or '(version unknown)'} (config "
        f"{outcome.config!r}) reported {len(outcome.candidates)} candidate "
        f"finding(s), shown below as JSON. `severity` is Semgrep's own label "
        "(error/warning/info), NOT the finding's severity — judge that "
        "yourself from reachability and impact.\n\n"
        f"```json\n{listing}\n```"
        f"{truncation}"
    )
