"""Finding identity and deduplication.

The property under test throughout: a fingerprint must survive edits that do not
change the vulnerability, and must change when the vulnerability does.
"""

from __future__ import annotations

import pytest

from fingerprint import (
    deduplicate,
    finding_fingerprint,
    normalize_code,
    sink_of,
    strip_line_numbers,
)


def finding(**overrides):
    base = {
        "vulnerability": "SQL injection in user lookup",
        "cwe_id": "CWE-89",
        "severity": "high",
        "taint_analysis": {
            "source_location": "app/api/users.py:31",
            "sink_location": "app/db/queries.py:58",
        },
        "evidences": [
            {"path": "app/db/queries.py", "snippet": 'q = "SELECT * FROM u WHERE n = " + name'}
        ],
    }
    base.update(overrides)
    return base


class TestNormalizeCode:
    def test_whitespace_is_collapsed(self):
        assert normalize_code("a   =\n\n  b") == "a = b"

    def test_line_comments_are_dropped(self):
        assert "TODO" not in normalize_code("x = 1  # TODO fix this")

    def test_block_comments_are_dropped(self):
        assert "note" not in normalize_code("/* note */ x = 1")

    def test_string_literals_are_collapsed(self):
        # A changed error message must not look like a changed vulnerability.
        assert normalize_code('log("old text")') == normalize_code('log("new text")')

    def test_the_expression_itself_still_matters(self):
        assert normalize_code("eval(x)") != normalize_code("eval(y)")


class TestLocationHandling:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("app/db.py:58", "app/db.py"),
            ("app/db.py:56-58", "app/db.py"),
            ("app/db.py", "app/db.py"),
            ("", ""),
        ],
    )
    def test_line_numbers_are_stripped(self, value, expected):
        assert strip_line_numbers(value) == expected

    def test_sink_prefers_the_sink_location(self):
        assert sink_of(finding()) == "app/db/queries.py"

    def test_sink_falls_back_to_evidence_when_taint_is_missing(self):
        item = finding(taint_analysis={})
        assert sink_of(item) == "app/db/queries.py"

    def test_missing_everything_yields_empty(self):
        assert sink_of({"vulnerability": "x"}) == ""


class TestFingerprintStability:
    def test_same_finding_hashes_the_same(self):
        assert finding_fingerprint(finding()) == finding_fingerprint(finding())

    def test_line_numbers_moving_does_not_change_identity(self):
        # Someone added imports at the top of the file. Same bug.
        moved = finding(
            taint_analysis={
                "source_location": "app/api/users.py:71",
                "sink_location": "app/db/queries.py:98",
            }
        )
        assert finding_fingerprint(moved) == finding_fingerprint(finding())

    def test_reformatting_does_not_change_identity(self):
        reformatted = finding(
            evidences=[
                {
                    "path": "app/db/queries.py",
                    "snippet": 'q  =  "SELECT * FROM u WHERE n = "   +   name',
                }
            ]
        )
        assert finding_fingerprint(reformatted) == finding_fingerprint(finding())

    def test_reworded_description_does_not_change_identity(self):
        reworded = finding(vulnerability="Unsanitized SQL built from user input")
        assert finding_fingerprint(reworded) == finding_fingerprint(finding())

    def test_severity_disagreement_does_not_change_identity(self):
        assert finding_fingerprint(finding(severity="medium")) == finding_fingerprint(finding())

    def test_a_different_file_is_a_different_finding(self):
        other = finding(
            taint_analysis={"sink_location": "app/db/other.py:58"},
        )
        assert finding_fingerprint(other) != finding_fingerprint(finding())

    def test_a_different_weakness_class_is_a_different_finding(self):
        assert finding_fingerprint(finding(cwe_id="CWE-79")) != finding_fingerprint(finding())

    def test_ids_are_short_and_hex(self):
        value = finding_fingerprint(finding())
        assert len(value) == 16
        int(value, 16)

    def test_an_empty_finding_still_gets_an_id(self):
        assert finding_fingerprint({"vulnerability": "mystery"})


class TestDeduplicate:
    def test_identical_findings_collapse_to_one(self):
        result = deduplicate([finding(), finding()])
        assert len(result) == 1
        assert result[0]["duplicate_count"] == 2

    def test_two_paths_to_the_same_sink_are_one_finding(self):
        # The fix is at the sink, so this is one piece of work, not two.
        via_api = finding(taint_analysis={"sink_location": "app/db/queries.py:58"})
        via_cli = finding(taint_analysis={"sink_location": "app/db/queries.py:58"})
        via_cli["taint_analysis"]["source_location"] = "app/cli.py:12"
        assert len(deduplicate([via_api, via_cli])) == 1

    def test_distinct_findings_are_preserved(self):
        other = finding(cwe_id="CWE-79", taint_analysis={"sink_location": "app/views.py:10"})
        assert len(deduplicate([finding(), other])) == 2

    def test_every_finding_gains_a_stable_id(self):
        result = deduplicate([finding()])
        assert result[0]["finding_id"] == finding_fingerprint(finding())

    def test_merge_keeps_the_strongest_severity(self):
        result = deduplicate([finding(severity="low"), finding(severity="critical")])
        assert result[0]["severity"] == "critical"

    def test_merge_unions_distinct_evidence(self):
        # The same sink reported twice: identical primary evidence, plus a second
        # snippet from the other tainted path.
        second = finding(
            evidences=[
                dict(finding()["evidences"][0]),
                {"path": "app/cli.py", "snippet": "run_query(user_arg)"},
            ]
        )
        result = deduplicate([finding(), second])
        assert len(result) == 1
        assert len(result[0]["evidences"]) == 2

    def test_extra_evidence_does_not_change_identity(self):
        second = finding(
            evidences=[
                dict(finding()["evidences"][0]),
                {"path": "app/cli.py", "snippet": "run_query(user_arg)"},
            ]
        )
        assert finding_fingerprint(second) == finding_fingerprint(finding())

    def test_merge_does_not_stack_identical_evidence(self):
        result = deduplicate([finding(), finding()])
        assert len(result[0]["evidences"]) == 1

    def test_order_of_first_appearance_is_preserved(self):
        first = finding(cwe_id="CWE-79", taint_analysis={"sink_location": "a.py:1"})
        second = finding(cwe_id="CWE-89", taint_analysis={"sink_location": "b.py:1"})
        result = deduplicate([first, second, first])
        assert [item["cwe_id"] for item in result] == ["CWE-79", "CWE-89"]

    def test_non_dict_entries_are_ignored(self):
        assert deduplicate([finding(), "garbage", None]) and len(deduplicate([finding(), "x"])) == 1

    def test_empty_input(self):
        assert deduplicate([]) == []
