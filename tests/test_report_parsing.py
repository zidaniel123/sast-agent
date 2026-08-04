"""JSON extraction from reporter output, and run-id validation.

The regression these guard: a naive first-``{`` / last-``}`` slice throws away an
entire three-phase run whenever the model writes prose containing a brace, or
prints an illustrative snippet before the real report.
"""

from __future__ import annotations

import json

import pytest

from main import _SAFE_RUN_ID, save_report_from_text

REPORT = {
    "report_metadata": {"codebase_path": "/tmp/x"},
    "findings": [{"vulnerability": "SQLi", "severity": "high"}],
}


def _write(tmp_path, text, run_id="run1"):
    return save_report_from_text(text, str(tmp_path), run_id)


class TestExtraction:
    def test_bare_json_object(self, tmp_path):
        path = _write(tmp_path, json.dumps(REPORT))
        assert path is not None
        assert json.loads(open(path).read())["findings"][0]["vulnerability"] == "SQLi"

    def test_fenced_json_block(self, tmp_path):
        text = f"Here is the report:\n\n```json\n{json.dumps(REPORT, indent=2)}\n```\n"
        path = _write(tmp_path, text)
        assert path is not None
        assert json.loads(open(path).read())["findings"]

    def test_prose_containing_a_stray_brace_before_the_report(self, tmp_path):
        # The old first-{/last-} slice started at this brace and produced garbage.
        text = "Note: the handler uses ${user_input} unsanitized.\n\n" + json.dumps(REPORT)
        path = _write(tmp_path, text)
        assert path is not None
        assert json.loads(open(path).read())["findings"]

    def test_illustrative_snippet_before_the_real_report(self, tmp_path):
        text = (
            "For example a finding looks like:\n"
            '```json\n{"vulnerability": "example"}\n```\n\n'
            "The actual report:\n"
            f"```json\n{json.dumps(REPORT)}\n```\n"
        )
        path = _write(tmp_path, text)
        assert path is not None
        # The object carrying "findings" wins over the illustrative fragment.
        assert json.loads(open(path).read())["findings"][0]["vulnerability"] == "SQLi"

    def test_trailing_prose_after_the_report(self, tmp_path):
        text = json.dumps(REPORT) + "\n\nLet me know if you need {more} detail."
        path = _write(tmp_path, text)
        assert path is not None
        assert json.loads(open(path).read())["findings"]

    def test_braces_inside_json_strings_do_not_break_the_scan(self, tmp_path):
        payload = dict(REPORT)
        payload["findings"] = [{"vulnerability": 'template ${x} and a quote \\" here'}]
        path = _write(tmp_path, "prose\n" + json.dumps(payload))
        assert path is not None
        assert json.loads(open(path).read())["findings"]

    def test_raw_control_characters_in_string_values_are_tolerated(self, tmp_path):
        # Models emit multi-line evidence snippets as literal newlines/tabs inside
        # string values, which is invalid strict JSON. Rejecting it discarded a
        # whole run; the scanner parses it with strict=False instead.
        text = '{"findings": [{"vulnerability": "x", "taint_flow": "line1\nline2\tcol"}]}'
        path = _write(tmp_path, text)
        assert path is not None
        assert json.loads(open(path).read())["findings"][0]["vulnerability"] == "x"

    def test_nested_code_fences_inside_strings_do_not_truncate(self, tmp_path):
        # A taint_flow value containing an embedded ```python block used to make
        # the fence regex stop at the first closing ``` — mid-string — producing
        # a truncated, unparseable fragment.
        text = (
            "Emitting the final report.\n\n```json\n"
            '{"findings": [{"vulnerability": "path bypass",'
            ' "taint_flow": "PoC:\n```python\nrequests.get(url)\n```\ndone"}]}\n'
            "```\n"
        )
        path = _write(tmp_path, text)
        assert path is not None
        assert json.loads(open(path).read())["findings"][0]["vulnerability"] == "path bypass"

    def test_last_full_report_wins_when_reporter_re_emits(self, tmp_path):
        # The reporter sometimes starts a report, abandons it mid-object, narrates
        # "emitting the final report", then prints the complete one. The last
        # object carrying a findings list must win over the abandoned first.
        partial = '```json\n{"report_metadata": {"v": 1}, "findings": [{"vulnerability": "PARTIAL"'
        prose = "\nAll findings verified against source. Emitting the final report.\n"
        final = "```json\n" + json.dumps(
            {"report_metadata": {"v": 1}, "findings": [{"vulnerability": "FINAL", "severity": "high"}]}
        ) + "\n```\n"
        path = _write(tmp_path, partial + prose + final)
        assert path is not None
        assert json.loads(open(path).read())["findings"][0]["vulnerability"] == "FINAL"


class TestFailureIsRecoverable:
    def test_unparseable_output_preserves_the_raw_text(self, tmp_path):
        path = _write(tmp_path, "The analysis failed and I have no JSON for you.")
        assert path is None
        raw = tmp_path / "run1.raw.txt"
        assert raw.exists(), "raw reporter output must survive a parse failure"
        assert "no JSON" in raw.read_text()

    def test_unparseable_output_does_not_raise(self, tmp_path):
        assert _write(tmp_path, "{ this is not json at all ") is None


class TestRunIdValidation:
    @pytest.mark.parametrize("good", ["run1", "2026-01-01_scan", "a.b-c_d", "x" * 64])
    def test_accepts_safe_ids(self, good):
        assert _SAFE_RUN_ID.match(good)

    @pytest.mark.parametrize(
        "bad",
        ["../../etc/passwd", "a/b", "", "x" * 65, "has space", "semi;colon"],
    )
    def test_rejects_ids_that_could_escape_the_output_directory(self, bad):
        assert not _SAFE_RUN_ID.match(bad)
