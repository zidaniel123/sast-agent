"""Skill registry and loader for the SAST specialist agents.

Each phase of the pipeline (recon -> analyst -> reporter) loads its system
prompt from a ``SKILL.md`` file under ``skills/``. Keeping the prompts as files
makes them reviewable and editable without touching Python.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"


@dataclass(frozen=True)
class Specialist:
    """A single phase of the SAST pipeline."""

    agent: str
    description: str
    skill_path: str


SPECIALISTS: tuple[Specialist, ...] = (
    Specialist(
        agent="recon",
        description="Map the attack surface: tech stack, entry points, and sensitive operations.",
        skill_path="recon/SKILL.md",
    ),
    Specialist(
        agent="analyst",
        description="Deep vulnerability and taint analysis using the ast-grep and xray MCP servers.",
        skill_path="analyst/SKILL.md",
    ),
    Specialist(
        agent="reporter",
        description="Emit the structured JSON findings report from the analyst's results.",
        skill_path="reporter/SKILL.md",
    ),
)


def load_skill(relative_path: str) -> str:
    """Read a skill body from ``skills/`` with a path-escape guard."""
    path = (SKILLS_DIR / relative_path).resolve()
    if SKILLS_DIR.resolve() not in path.parents:
        raise ValueError("skill path escaped the skills directory")
    return path.read_text(encoding="utf-8")
