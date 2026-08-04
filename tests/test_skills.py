"""Skill/reference loading, the path-escape guard, and prompt rendering."""

from __future__ import annotations

import pytest

from skills import (
    SPECIALISTS,
    load_reference,
    load_skill,
    reference_appendix,
    specialist,
)


class TestRegistry:
    def test_every_specialist_skill_file_exists_and_is_non_empty(self):
        for item in SPECIALISTS:
            assert load_skill(item.skill_path).strip()

    def test_every_cited_reference_file_exists(self):
        for item in SPECIALISTS:
            for name in item.references:
                assert load_reference(name).strip()

    def test_lookup_by_agent_name(self):
        assert specialist("analyst").skill_path == "analyst/SKILL.md"

    def test_unknown_agent_names_are_reported_with_the_known_set(self):
        with pytest.raises(KeyError, match="analyst"):
            specialist("nope")

    def test_recon_does_not_pay_for_the_reporting_specs(self):
        # Per-phase reference lists are the whole point: recon has no use for the
        # severity rubric or the taint-flow format, so it should not load them.
        assert specialist("recon").references == ("ast-grep-and-xray.md",)


class TestPathEscapeGuard:
    @pytest.mark.parametrize(
        "bad",
        ["../config.py", "../../etc/passwd", "recon/../../config.py"],
    )
    def test_traversal_is_refused(self, bad):
        with pytest.raises(ValueError, match="escaped"):
            load_skill(bad)

    def test_traversal_is_refused_for_references_too(self):
        with pytest.raises(ValueError, match="escaped"):
            load_reference("../main.py")


class TestReferenceAppendix:
    def test_headings_match_the_paths_the_skills_cite(self):
        # A skill body says "see references/taint-analysis.md"; that string has to
        # resolve to something visible in the rendered prompt.
        appendix = reference_appendix(("taint-analysis.md",))
        assert "### references/taint-analysis.md" in appendix

    def test_empty_reference_list_is_explicit_not_blank(self):
        assert reference_appendix(()).startswith("(No reference")

    def test_all_cited_documents_are_included(self):
        item = specialist("analyst")
        appendix = reference_appendix(item.references)
        for name in item.references:
            assert f"### references/{name}" in appendix


class TestRenderedPrompts:
    """The bug this guards: skills cited references/ files the agent could never
    open, because the agent's working directory is the *scanned* project."""

    def test_no_unfilled_placeholders_remain(self):
        from main import _phase_prompt

        prompts = {
            "recon": _phase_prompt("recon", code_path="/tmp/x"),
            "analyst": _phase_prompt("analyst", code_path="/tmp/x", recon_context="ctx"),
            "reporter": _phase_prompt(
                "reporter",
                code_path="/tmp/x",
                analysis_results="res",
                report_timestamp="2026-01-01T00:00:00+00:00",
            ),
        }
        for name, text in prompts.items():
            assert "{{" not in text, f"{name} prompt has an unsubstituted placeholder"

    def test_every_cited_reference_is_actually_inlined(self):
        from main import _phase_prompt

        prompt = _phase_prompt("analyst", code_path="/tmp/x", recon_context="ctx")
        for name in specialist("analyst").references:
            body = load_reference(name).strip()
            # A distinctive line from each spec must survive into the prompt.
            first_heading = next(
                line for line in body.splitlines() if line.startswith("#")
            )
            assert first_heading in prompt

    def test_prompts_carry_the_untrusted_input_warning(self):
        from main import _phase_prompt

        prompt = _phase_prompt("recon", code_path="/tmp/x")
        assert "Untrusted input" in prompt
