"""Skill and reference loader for the SAST specialist agents.

Each phase of the pipeline (recon -> analyst -> reporter) loads its system
prompt from a ``SKILL.md`` file under ``skills/``, plus the subset of the
``references/`` knowledge base that phase actually cites.

Keeping prompts and specs as files makes them reviewable and editable without
touching Python. Keeping the reference list *per phase* is what keeps the
context small: the analyst needs the taint-flow and severity specs, the recon
phase does not, and neither pays for the other's tokens.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"
REFERENCES_DIR = Path(__file__).parent / "references"


@dataclass(frozen=True)
class Specialist:
    """A single phase of the SAST pipeline."""

    agent: str
    description: str
    skill_path: str
    references: tuple[str, ...] = ()


SPECIALISTS: tuple[Specialist, ...] = (
    Specialist(
        agent="recon",
        description="Map the attack surface: tech stack, entry points, and sensitive operations.",
        skill_path="recon/SKILL.md",
        references=("ast-grep-and-xray.md",),
    ),
    Specialist(
        agent="analyst",
        description="Deep vulnerability and taint analysis using the ast-grep and xray MCP servers.",
        skill_path="analyst/SKILL.md",
        references=("ast-grep-and-xray.md", "severity-and-cwe.md", "taint-analysis.md"),
    ),
    Specialist(
        agent="reporter",
        description="Emit the structured JSON findings report from the analyst's results.",
        skill_path="reporter/SKILL.md",
        references=("severity-and-cwe.md", "taint-analysis.md"),
    ),
)

_BY_AGENT = {item.agent: item for item in SPECIALISTS}


def specialist(agent: str) -> Specialist:
    """Look up a phase by name."""
    try:
        return _BY_AGENT[agent]
    except KeyError:
        raise KeyError(
            f"unknown specialist {agent!r}; known: {', '.join(sorted(_BY_AGENT))}"
        ) from None


def _read_within(base: Path, relative_path: str) -> str:
    """Read ``base/relative_path``, refusing anything that escapes ``base``."""
    root = base.resolve()
    path = (base / relative_path).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"path escaped {root.name}/: {relative_path!r}")
    return path.read_text(encoding="utf-8")


def load_skill(relative_path: str) -> str:
    """Read a skill body from ``skills/``."""
    return _read_within(SKILLS_DIR, relative_path)


def load_reference(relative_path: str) -> str:
    """Read a spec document from ``references/``."""
    return _read_within(REFERENCES_DIR, relative_path)


def reference_appendix(relative_paths: tuple[str, ...]) -> str:
    """Render the cited reference documents as one appendix block.

    Section headings reuse the same ``references/<name>`` path the skill bodies
    cite, so a citation in the prompt resolves to a heading the model can see.
    """
    if not relative_paths:
        return "(No reference documents apply to this phase.)"
    sections = [
        f"### references/{name}\n\n{load_reference(name).strip()}"
        for name in relative_paths
    ]
    return "\n\n".join(sections)
